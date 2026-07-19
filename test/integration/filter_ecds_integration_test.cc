#include "envoy/config/core/v3/extension.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/service/discovery/v3/discovery.pb.h"
#include "envoy/service/extension/v3/config_discovery.pb.h"

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "api/envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/integration/http_integration.h"

#include "absl/strings/match.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

using FilterProto = envoy_modsecurity::extensions::filters::http::modsecurity::v3::ModSecurity;
using testing::Eq;
using testing::Ge;

constexpr absl::string_view EcdsResourceName = "modsecurity-dynamic";
constexpr absl::string_view EcdsTypeUrl =
    "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig";

FilterProto filterConfig(absl::string_view token, uint32_t status, uint64_t rule_id) {
  FilterProto configuration;
  auto* inline_rules = configuration.add_rules()->mutable_inline_rules();
  inline_rules->set_name("ecds-generation.conf");
  inline_rules->set_rules(
      "SecRuleEngine On\nSecRequestBodyAccess On\nSecRule REQUEST_BODY \"@contains " +
      std::string(token) + "\" \"id:" + std::to_string(rule_id) +
      ",phase:2,deny,status:" + std::to_string(status) + ",nolog\"\n");
  configuration.mutable_request_body()->mutable_max_bytes()->set_value(1024);
  configuration.mutable_max_active_body_bytes()->set_value(64 * 1024);
  configuration.set_stat_prefix("ecds");
  return configuration;
}

class FilterEcdsIntegrationTest : public Grpc::EnvoyGrpcClientIntegrationParamTest,
                                  public HttpIntegrationTest {
 public:
  struct PendingRequest {
    IntegrationCodecClientPtr client;
    Http::RequestEncoder* encoder;
    IntegrationStreamDecoderPtr response;
  };

  struct CompleteRequest {
    IntegrationCodecClientPtr client;
    IntegrationStreamDecoderPtr response;
  };

  FilterEcdsIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP1, ipVersion()) {
    concurrency_ = 4;
    setUpstreamCount(1);
    addEcdsCluster();
    addDynamicFilter();
    balanceConnectionsAcrossWorkers();
    config_helper_.addConfigModifier(
        [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
               hcm) {
          auto* route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->mutable_routes(0);
          route->mutable_direct_response()->set_status(200);
        });
  }

  ~FilterEcdsIntegrationTest() override {
    if (ecds_connection_ != nullptr) {
      auto result = ecds_connection_->close();
      RELEASE_ASSERT(result, result.message());
      result = ecds_connection_->waitForDisconnect();
      RELEASE_ASSERT(result, result.message());
    }
  }

  void createUpstreams() override {
    HttpIntegrationTest::createUpstreams();
    addFakeUpstream(Http::CodecType::HTTP2);
  }

  void addEcdsCluster() {
    config_helper_.addConfigModifier(
        [](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          auto* cluster = bootstrap.mutable_static_resources()->add_clusters();
          cluster->MergeFrom(bootstrap.static_resources().clusters(0));
          cluster->set_name("ecds_cluster");
          ConfigHelper::setHttp2(*cluster);
        });
  }

  void addDynamicFilter() {
    config_helper_.addConfigModifier(
        [this](envoy::extensions::filters::network::http_connection_manager::v3::
                   HttpConnectionManager& hcm) {
          auto* filter = hcm.add_http_filters();
          filter->set_name(std::string(EcdsResourceName));
          auto* discovery = filter->mutable_config_discovery();
          discovery->add_type_urls(
              "type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity");
          std::ignore = discovery->mutable_default_config()->PackFrom(
              filterConfig("old-token", 418, 1300001));
          discovery->set_apply_default_config_without_warming(true);
          discovery->mutable_config_source()->set_resource_api_version(
              envoy::config::core::v3::ApiVersion::V3);
          auto* api_source = discovery->mutable_config_source()->mutable_api_config_source();
          api_source->set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
          api_source->set_transport_api_version(envoy::config::core::v3::ApiVersion::V3);
          auto* grpc_service = api_source->add_grpc_services();
          setGrpcService(*grpc_service, "ecds_cluster", ecdsUpstream().localAddress());
          hcm.mutable_http_filters()->SwapElements(hcm.http_filters_size() - 2,
                                                   hcm.http_filters_size() - 1);
        });
  }

  void balanceConnectionsAcrossWorkers() {
    config_helper_.addConfigModifier(
        [](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          bootstrap.mutable_static_resources()
              ->mutable_listeners(0)
              ->mutable_connection_balance_config()
              ->mutable_exact_balance();
        });
  }

  FakeUpstream& ecdsUpstream() const { return *fake_upstreams_[1]; }

  void initializeEcds() {
    initialize();
    registerTestServerPorts({"http"});
    ASSERT_TRUE(ecdsUpstream().waitForHttpConnection(*dispatcher_, ecds_connection_));
    ASSERT_TRUE(ecds_connection_->waitForNewStream(*dispatcher_, ecds_stream_));
    ecds_stream_->startGrpcStream();
    envoy::service::discovery::v3::DiscoveryRequest request;
    ASSERT_TRUE(ecds_stream_->waitForGrpcMessage(*dispatcher_, request));
    EXPECT_EQ(EcdsTypeUrl, request.type_url());
    EXPECT_TRUE(request.version_info().empty());
    EXPECT_TRUE(request.error_detail().message().empty());
    codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  }

  void sendConfig(const FilterProto& configuration, absl::string_view version) {
    envoy::config::core::v3::TypedExtensionConfig typed_config;
    typed_config.set_name(std::string(EcdsResourceName));
    std::ignore = typed_config.mutable_typed_config()->PackFrom(configuration);

    envoy::service::discovery::v3::Resource resource;
    resource.set_name(std::string(EcdsResourceName));
    std::ignore = resource.mutable_resource()->PackFrom(typed_config);

    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(std::string(version));
    response.set_type_url(std::string(EcdsTypeUrl));
    response.set_nonce("nonce-" + std::string(version));
    std::ignore = response.add_resources()->PackFrom(resource);
    ecds_stream_->sendGrpcMessage(response);
  }

  void expectAck(absl::string_view version) {
    envoy::service::discovery::v3::DiscoveryRequest request;
    ASSERT_TRUE(ecds_stream_->waitForGrpcMessage(*dispatcher_, request));
    EXPECT_EQ(version, request.version_info());
    EXPECT_TRUE(request.error_detail().message().empty());
  }

  void expectNack(absl::string_view last_good_version) {
    envoy::service::discovery::v3::DiscoveryRequest request;
    ASSERT_TRUE(ecds_stream_->waitForGrpcMessage(*dispatcher_, request));
    EXPECT_EQ(last_good_version, request.version_info());
    EXPECT_FALSE(request.error_detail().message().empty());
  }

  Http::TestRequestHeaderMapImpl requestHeaders() const {
    return {{":method", "POST"},
            {":path", "/ecds"},
            {":scheme", "http"},
            {":authority", "integration.test"},
            {"content-type", "application/x-www-form-urlencoded"}};
  }

  void expectBodyStatus(absl::string_view body, absl::string_view status) {
    auto response = codec_client_->makeRequestWithBody(requestHeaders(), std::string(body));
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(response->complete());
    EXPECT_EQ(status, response->headers().getStatusValue());
  }

  std::vector<PendingRequest> startPendingRequests(int count) {
    std::vector<PendingRequest> requests;
    requests.reserve(count);
    for (int request = 0; request < count; ++request) {
      auto client = makeHttpConnection(makeClientConnection(lookupPort("http")));
      auto stream = client->startRequest(requestHeaders());
      client->sendData(stream.first, "value=", false);
      requests.push_back({std::move(client), &stream.first, std::move(stream.second)});
    }
    return requests;
  }

  void completePendingRequests(std::vector<PendingRequest>& requests, absl::string_view token) {
    for (PendingRequest& request : requests) {
      request.client->sendData(*request.encoder, std::string(token), true);
    }
  }

  void expectPendingStatusesAndClose(std::vector<PendingRequest>& requests,
                                     absl::string_view expected_status) {
    for (PendingRequest& request : requests) {
      ASSERT_TRUE(request.response->waitForEndStream());
      ASSERT_TRUE(request.response->complete());
      EXPECT_EQ(expected_status, request.response->headers().getStatusValue());
      request.client->close();
    }
  }

  std::vector<CompleteRequest> startRacingRequests(int count, absl::string_view current_token,
                                                   absl::string_view next_token) {
    std::vector<CompleteRequest> requests;
    requests.reserve(count);
    const std::string body =
        "current=" + std::string(current_token) + "&next=" + std::string(next_token);
    for (int request = 0; request < count; ++request) {
      auto client = makeHttpConnection(makeClientConnection(lookupPort("http")));
      auto response = client->makeRequestWithBody(requestHeaders(), body);
      requests.push_back({std::move(client), std::move(response)});
    }
    return requests;
  }

  void expectRacingStatusesAndClose(std::vector<CompleteRequest>& requests,
                                    absl::string_view current_status,
                                    absl::string_view next_status) {
    for (CompleteRequest& request : requests) {
      ASSERT_TRUE(request.response->waitForEndStream());
      ASSERT_TRUE(request.response->complete());
      const absl::string_view actual_status = request.response->headers().getStatusValue();
      EXPECT_TRUE(actual_status == current_status || actual_status == next_status)
          << "unexpected status from a request racing an ECDS update: " << actual_status;
      request.client->close();
    }
  }

  std::string workerConnectionGauge(int worker) const {
    const absl::string_view listener =
        ipVersion() == Network::Address::IpVersion::v4 ? "127.0.0.1_0" : "[__1]_0";
    return "listener." + std::string(listener) + ".worker_" + std::to_string(worker) +
           ".downstream_cx_active";
  }

  std::string gaugeName(absl::string_view suffix) const {
    std::vector<std::string> matches;
    test_server_->statStore().forEachGauge(nullptr, [&](Stats::Gauge& gauge) {
      if (absl::EndsWith(gauge.name(), suffix)) {
        matches.push_back(gauge.name());
      }
    });
    EXPECT_EQ(1, matches.size()) << "gauge suffix: " << suffix;
    return matches.size() == 1 ? matches.front() : "";
  }

 private:
  FakeHttpConnectionPtr ecds_connection_{nullptr};
  FakeStreamPtr ecds_stream_{nullptr};
};

INSTANTIATE_TEST_SUITE_P(IpVersions, FilterEcdsIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         Grpc::EnvoyGrpcClientIntegrationParamTest::protocolTestParamsToString);

TEST_P(FilterEcdsIntegrationTest, AckNackGenerationPinningAndChurn) {
  initializeEcds();

  auto old_stream = codec_client_->startRequest(requestHeaders());
  codec_client_->sendData(old_stream.first, "value=", false);

  sendConfig(filterConfig("new-token", 419, 1300002), "1");
  test_server_->waitForCounter(
      "extension_config_discovery.http_filter.modsecurity-dynamic.config_reload", Ge(1));
  expectAck("1");

  codec_client_->sendData(old_stream.first, "old-token", true);
  ASSERT_TRUE(old_stream.second->waitForEndStream());
  ASSERT_TRUE(old_stream.second->complete());
  EXPECT_EQ("418", old_stream.second->headers().getStatusValue());
  expectBodyStatus("value=old-token", "200");
  expectBodyStatus("value=new-token", "419");

  FilterProto invalid = filterConfig("invalid-token", 420, 1300003);
  invalid.mutable_rules(0)->mutable_inline_rules()->set_rules("SecRule REQUEST_URI\n");
  sendConfig(invalid, "2");
  test_server_->waitForCounter(
      "extension_config_discovery.http_filter.modsecurity-dynamic.config_fail", Ge(1));
  expectNack("1");
  expectBodyStatus("value=new-token", "419");

  FilterProto missing_file = filterConfig("unused", 420, 1300004);
  missing_file.clear_rules();
  missing_file.add_rules()->set_filename(
      "/envoy-modsecurity-qualification/does-not-exist.conf");
  sendConfig(missing_file, "2-missing-file");
  test_server_->waitForCounter(
      "extension_config_discovery.http_filter.modsecurity-dynamic.config_fail", Ge(2));
  expectNack("1");
  expectBodyStatus("value=new-token", "419");

  constexpr int ChurnUpdates = 12;
  for (int update = 0; update < ChurnUpdates; ++update) {
    const std::string token = "churn-token-" + std::to_string(update);
    const std::string version = std::to_string(update + 3);
    sendConfig(filterConfig(token, 430 + update, 1300100 + update), version);
    test_server_->waitForCounter(
        "extension_config_discovery.http_filter.modsecurity-dynamic.config_reload",
        Ge(update + 2));
    expectAck(version);
  }
  expectBodyStatus("value=churn-token-11", "441");
  for (int connection = 0; connection < 16; ++connection) {
    auto client = makeHttpConnection(makeClientConnection(lookupPort("http")));
    auto response =
        client->makeRequestWithBody(requestHeaders(), "value=churn-token-11");
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(response->complete());
    EXPECT_EQ("441", response->headers().getStatusValue());
    client->close();
  }
  const std::string transactions = gaugeName(".active_transactions");
  const std::string body_bytes = gaugeName(".modsecurity_buffer_bytes");
  ASSERT_FALSE(transactions.empty());
  ASSERT_FALSE(body_bytes.empty());
  test_server_->waitForGauge(transactions, Eq(0));
  test_server_->waitForGauge(body_bytes, Eq(0));
  test_server_->waitForGauge("listener_manager.workers_started", Eq(1));
  test_server_->waitForGauge("server.concurrency", Eq(4));
}

TEST_P(FilterEcdsIntegrationTest, ConcurrentWorkerRequestsOverlapEcdsChurn) {
  initializeEcds();

  constexpr int WorkerCount = 4;
  constexpr int RequestsPerBatch = WorkerCount * 2;
  constexpr int ChurnUpdates = 8;
  const std::string transactions = gaugeName(".active_transactions");
  const std::string body_bytes = gaugeName(".modsecurity_buffer_bytes");
  ASSERT_FALSE(transactions.empty());
  ASSERT_FALSE(body_bytes.empty());

  std::string current_token = "old-token";
  std::string current_status = "418";
  for (int update = 0; update < ChurnUpdates; ++update) {
    std::vector<PendingRequest> pinned = startPendingRequests(RequestsPerBatch);
    test_server_->waitForGauge(transactions, Eq(RequestsPerBatch));
    test_server_->waitForGauge(body_bytes, Ge(RequestsPerBatch));

    const std::string next_token = "concurrent-token-" + std::to_string(update);
    const std::string next_status = std::to_string(430 + update);
    const std::string version = "concurrent-" + std::to_string(update);
    sendConfig(filterConfig(next_token, 430 + update, 1300200 + update), version);

    // Do not wait for the ECDS ACK or any response here. The old-generation body callbacks,
    // new stream creation, candidate compilation, and worker publication must overlap.
    completePendingRequests(pinned, current_token);
    std::vector<CompleteRequest> racing =
        startRacingRequests(RequestsPerBatch, current_token, next_token);

    if (update == 0) {
      for (int worker = 0; worker < WorkerCount; ++worker) {
        test_server_->waitForGauge(workerConnectionGauge(worker),
                                   Ge(RequestsPerBatch / WorkerCount));
      }
    }

    test_server_->waitForCounter(
        "extension_config_discovery.http_filter.modsecurity-dynamic.config_reload",
        Ge(update + 1));
    expectAck(version);
    expectPendingStatusesAndClose(pinned, current_status);
    expectRacingStatusesAndClose(racing, current_status, next_status);
    expectBodyStatus("value=" + next_token, next_status);

    test_server_->waitForGauge(transactions, Eq(0));
    test_server_->waitForGauge(body_bytes, Eq(0));
    current_token = next_token;
    current_status = next_status;
  }

  test_server_->waitForGauge("listener_manager.workers_started", Eq(1));
  test_server_->waitForGauge("server.concurrency", Eq(WorkerCount));
}

}  // namespace
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
