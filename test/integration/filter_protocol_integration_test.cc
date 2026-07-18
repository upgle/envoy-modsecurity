#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"

#include <string>
#include <tuple>
#include <vector>

#include "api/envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.h"

#include "test/integration/http_protocol_integration.h"

#include "absl/strings/match.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

using Proto = envoy_modsecurity::extensions::filters::http::modsecurity::v3::ModSecurity;
using PerRouteProto =
    envoy_modsecurity::extensions::filters::http::modsecurity::v3::ModSecurityPerRoute;
using testing::Eq;
using testing::Ge;

class FilterProtocolIntegrationTest : public HttpProtocolIntegrationTest {
 public:
  FilterProtocolIntegrationTest() {
    config_helper_.addConfigModifier(
        [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
               hcm) {
          Proto configuration;
          auto* inline_rules = configuration.add_rules()->mutable_inline_rules();
          inline_rules->set_name("protocol-integration.conf");
          inline_rules->set_rules(R"(
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule REQUEST_BODY "@contains attack-token" "id:1200001,phase:2,deny,status:406,nolog"
SecRule RESPONSE_BODY "@contains response-token" "id:1200002,phase:4,deny,status:451,nolog"
)");
          configuration.mutable_request_body()->mutable_max_bytes()->set_value(64);
          configuration.mutable_response()->mutable_body()->mutable_max_bytes()->set_value(64);
          configuration.mutable_max_active_body_bytes()->set_value(128);
          configuration.set_stat_prefix("protocol");

          auto* filter = hcm.add_http_filters();
          filter->set_name("envoy.filters.http.modsecurity");
          std::ignore = filter->mutable_typed_config()->PackFrom(configuration);
          hcm.mutable_http_filters()->SwapElements(hcm.http_filters_size() - 2,
                                                   hcm.http_filters_size() - 1);

          auto* virtual_host = hcm.mutable_route_config()->mutable_virtual_hosts(0);
          auto* default_route = virtual_host->mutable_routes(0);
          default_route->clear_route();
          default_route->mutable_direct_response()->set_status(200);

          auto* streaming_route = virtual_host->add_routes();
          streaming_route->mutable_match()->set_prefix("/stream");
          streaming_route->mutable_route()->set_cluster("cluster_0");
          PerRouteProto per_route;
          per_route.set_disabled(true);
          std::ignore = (*streaming_route->mutable_typed_per_filter_config())
                            ["envoy.filters.http.modsecurity"]
                                .PackFrom(per_route);
          virtual_host->mutable_routes()->SwapElements(0, virtual_host->routes_size() - 1);

          auto* upstream_route = virtual_host->add_routes();
          upstream_route->mutable_match()->set_prefix("/upstream");
          upstream_route->mutable_route()->set_cluster("cluster_0");
          virtual_host->mutable_routes()->SwapElements(1, virtual_host->routes_size() - 1);
        });
  }

  void initializeFilter() {
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
  }

  Http::TestRequestHeaderMapImpl requestHeaders(absl::string_view path = "/finite") const {
    return {{":method", "POST"},
            {":path", std::string(path)},
            {":scheme", "http"},
            {":authority", "integration.test"},
            {"content-type", "application/x-www-form-urlencoded"}};
  }

  void expectBodyStatus(absl::string_view body, absl::string_view expected_status) {
    auto response = codec_client_->makeRequestWithBody(requestHeaders(), std::string(body));
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(response->complete());
    EXPECT_EQ(expected_status, response->headers().getStatusValue());
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

  std::string counterName(absl::string_view suffix) const {
    std::vector<std::string> matches;
    test_server_->statStore().forEachCounter(nullptr, [&](Stats::Counter& counter) {
      if (absl::EndsWith(counter.name(), suffix)) {
        matches.push_back(counter.name());
      }
    });
    EXPECT_EQ(1, matches.size()) << "counter suffix: " << suffix;
    return matches.size() == 1 ? matches.front() : "";
  }

  void expectAccountingReleased() {
    const std::string transactions = gaugeName(".active_transactions");
    const std::string body_bytes = gaugeName(".modsecurity_buffer_bytes");
    if (!transactions.empty() && !body_bytes.empty()) {
      test_server_->waitForGauge(transactions, Eq(0));
      test_server_->waitForGauge(body_bytes, Eq(0));
    }
  }

  IntegrationStreamDecoderPtr startUpstreamRequest() {
    Http::TestRequestHeaderMapImpl headers{{":method", "GET"},
                                           {":path", "/upstream"},
                                           {":scheme", "http"},
                                           {":authority", "integration.test"}};
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    waitForNextUpstreamRequest();
    return response;
  }
};

INSTANTIATE_TEST_SUITE_P(
    Http1AndHttp2, FilterProtocolIntegrationTest,
    testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams(
        {Http::CodecType::HTTP1, Http::CodecType::HTTP2}, {Http::CodecType::HTTP1})),
    HttpProtocolIntegrationTest::protocolTestParamsToString);

TEST_P(FilterProtocolIntegrationTest, EnforcesFiniteBodyBoundariesAndPhaseTwo) {
  initializeFilter();

  expectBodyStatus(std::string(63, 'a'), "200");
  expectBodyStatus(std::string(64, 'a'), "200");

  auto declared_oversized_headers = requestHeaders();
  declared_oversized_headers.setContentLength(65);
  auto declared_oversized = codec_client_->startRequest(declared_oversized_headers);
  ASSERT_TRUE(declared_oversized.second->waitForEndStream());
  ASSERT_TRUE(declared_oversized.second->complete());
  EXPECT_EQ("413", declared_oversized.second->headers().getStatusValue());

  if (downstreamProtocol() == Http::CodecType::HTTP1) {
    auto blocked = codec_client_->makeRequestWithBody(requestHeaders(), "value=attack-token");
    ASSERT_TRUE(blocked->waitForReset());
    codec_client_ = makeHttpConnection(lookupPort("http"));
  } else {
    expectBodyStatus("value=attack-token", "406");
  }

  auto actual_oversized = codec_client_->startRequest(requestHeaders());
  codec_client_->sendData(actual_oversized.first, std::string(64, 'a'), false);
  codec_client_->sendData(actual_oversized.first, "a", true);
  ASSERT_TRUE(actual_oversized.second->waitForEndStream());
  ASSERT_TRUE(actual_oversized.second->complete());
  EXPECT_EQ("413", actual_oversized.second->headers().getStatusValue());
  expectAccountingReleased();
}

TEST_P(FilterProtocolIntegrationTest, TrailersCompleteFiniteBodyInspection) {
  initializeFilter();

  auto encoder_decoder = codec_client_->startRequest(requestHeaders());
  codec_client_->sendData(encoder_decoder.first, "value=safe", false);
  codec_client_->sendTrailers(encoder_decoder.first,
                              Http::TestRequestTrailerMapImpl{{"x-checksum", "complete"}});
  ASSERT_TRUE(encoder_decoder.second->waitForEndStream());
  ASSERT_TRUE(encoder_decoder.second->complete());
  EXPECT_EQ("200", encoder_decoder.second->headers().getStatusValue());
  expectAccountingReleased();
}

TEST_P(FilterProtocolIntegrationTest, DownstreamResetReleasesBufferedRequest) {
  initializeFilter();

  auto encoder_decoder = codec_client_->startRequest(requestHeaders());
  codec_client_->sendData(encoder_decoder.first, std::string(32, 'a'), false);
  const std::string transactions = gaugeName(".active_transactions");
  const std::string body_bytes = gaugeName(".modsecurity_buffer_bytes");
  ASSERT_FALSE(transactions.empty());
  ASSERT_FALSE(body_bytes.empty());
  test_server_->waitForGauge(transactions, Ge(1));
  test_server_->waitForGauge(body_bytes, Ge(1));
  if (downstreamProtocol() == Http::CodecType::HTTP1) {
    codec_client_->close();
    ASSERT_TRUE(codec_client_->waitForDisconnect());
  } else {
    codec_client_->sendReset(encoder_decoder.first);
  }
  expectAccountingReleased();
}

TEST_P(FilterProtocolIntegrationTest, EnforcesResponseBoundariesAndPhaseFour) {
  initializeFilter();

  for (size_t size : {size_t{63}, size_t{64}}) {
    auto response = startUpstreamRequest();
    Http::TestResponseHeaderMapImpl headers{{":status", "200"},
                                            {"content-type", "text/plain"},
                                            {"content-length", std::to_string(size)}};
    upstream_request_->encodeHeaders(headers, false);
    upstream_request_->encodeData(size, true);
    ASSERT_TRUE(response->waitForEndStream());
    ASSERT_TRUE(response->complete());
    EXPECT_EQ("200", response->headers().getStatusValue());
  }

  auto blocked = startUpstreamRequest();
  Http::TestResponseHeaderMapImpl blocked_headers{{":status", "200"},
                                                  {"content-type", "text/plain"},
                                                  {"content-length", "14"}};
  upstream_request_->encodeHeaders(blocked_headers, false);
  upstream_request_->encodeData("response-token", true);
  ASSERT_TRUE(blocked->waitForEndStream());
  ASSERT_TRUE(blocked->complete());
  EXPECT_EQ("451", blocked->headers().getStatusValue());

  auto oversized = startUpstreamRequest();
  Http::TestResponseHeaderMapImpl oversized_headers{{":status", "200"},
                                                    {"content-type", "text/plain"},
                                                    {"content-length", "65"}};
  upstream_request_->encodeHeaders(oversized_headers, false);
  ASSERT_TRUE(oversized->waitForEndStream());
  ASSERT_TRUE(oversized->complete());
  EXPECT_EQ("500", oversized->headers().getStatusValue());
  expectAccountingReleased();
}

TEST_P(FilterProtocolIntegrationTest, UpstreamResetFailsClosedAndReleasesBufferedResponse) {
  initializeFilter();

  auto response = startUpstreamRequest();
  Http::TestResponseHeaderMapImpl headers{{":status", "200"},
                                          {"content-type", "text/plain"}};
  upstream_request_->encodeHeaders(headers, false);
  upstream_request_->encodeData(32, false);
  const std::string body_bytes = gaugeName(".modsecurity_buffer_bytes");
  ASSERT_FALSE(body_bytes.empty());
  test_server_->waitForGauge(body_bytes, Ge(1));
  upstream_request_->encodeResetStream();
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("502", response->headers().getStatusValue());
  expectAccountingReleased();
}

TEST_P(FilterProtocolIntegrationTest, ExplicitlyDisabledStreamingRouteDoesNotBuffer) {
  initializeFilter();

  auto encoder_decoder = codec_client_->startRequest(requestHeaders("/stream/unbounded"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  const std::string bypassed = counterName(".request_body_bypassed");
  ASSERT_FALSE(bypassed.empty());
  EXPECT_EQ(0, test_server_->counter(bypassed)->value());
  if (downstreamProtocol() == Http::CodecType::HTTP1) {
    codec_client_->close();
    ASSERT_TRUE(codec_client_->waitForDisconnect());
  } else {
    codec_client_->sendReset(encoder_decoder.first);
  }
  expectAccountingReleased();
}

TEST_P(FilterProtocolIntegrationTest, Http2MultiplexedResetDoesNotAffectPeerStream) {
  if (downstreamProtocol() != Http::CodecType::HTTP2) {
    return;
  }
  initializeFilter();

  auto first = codec_client_->startRequest(requestHeaders("/finite/first"));
  auto second = codec_client_->startRequest(requestHeaders("/finite/second"));
  codec_client_->sendData(first.first, "first=partial", false);
  codec_client_->sendData(second.first, "value=", false);
  const std::string transactions = gaugeName(".active_transactions");
  ASSERT_FALSE(transactions.empty());
  test_server_->waitForGauge(transactions, Ge(2));

  codec_client_->sendReset(first.first);
  codec_client_->sendData(second.first, "attack-token", true);
  ASSERT_TRUE(second.second->waitForEndStream());
  ASSERT_TRUE(second.second->complete());
  EXPECT_EQ("406", second.second->headers().getStatusValue());
  expectAccountingReleased();
}

}  // namespace
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
