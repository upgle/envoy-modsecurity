#include "source/extensions/filters/http/modsecurity/filter.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/stats/isolated_store_impl.h"
#include "test/mocks/http/mocks.h"
#include "test/test_common/simulated_time_system.h"

using testing::_;
using testing::NiceMock;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

struct TransactionState {
  std::string request_body;
  std::string request_http_version;
  std::string request_method;
  std::string request_uri;
  std::string response_body;
  std::string response_http_version;
  absl::Status request_headers_status{absl::OkStatus()};
  absl::Status request_body_status{absl::OkStatus()};
  absl::Status response_body_status{absl::OkStatus()};
  absl::Status logging_status{absl::OkStatus()};
  Engine::LoggingResult logging_result;
  int request_headers_calls{0};
  int request_body_calls{0};
  int response_headers_calls{0};
  int response_body_calls{0};
  int logging_calls{0};
  int intervention_calls{0};
  int intervene_on_call{0};
  int destroyed_transactions{0};
  std::optional<Engine::Intervention> intervention;
};

class FakeTransaction final : public Engine::Transaction {
 public:
  explicit FakeTransaction(std::shared_ptr<TransactionState> state) : state_(std::move(state)) {}
  ~FakeTransaction() override { state_->destroyed_transactions++; }

  absl::Status processConnection(absl::string_view, uint32_t, absl::string_view,
                                 uint32_t) override {
    return absl::OkStatus();
  }
  absl::Status processUri(absl::string_view uri, absl::string_view method,
                          absl::string_view http_version) override {
    state_->request_uri = uri;
    state_->request_method = method;
    state_->request_http_version = http_version;
    return absl::OkStatus();
  }
  absl::Status addRequestHeader(absl::string_view, absl::string_view) override {
    return absl::OkStatus();
  }
  absl::Status processRequestHeaders() override {
    state_->request_headers_calls++;
    return state_->request_headers_status;
  }
  absl::Status appendRequestBody(absl::string_view data) override {
    state_->request_body.append(data.data(), data.size());
    return absl::OkStatus();
  }
  absl::Status processRequestBody() override {
    state_->request_body_calls++;
    return state_->request_body_status;
  }
  absl::Status addResponseHeader(absl::string_view, absl::string_view) override {
    return absl::OkStatus();
  }
  absl::Status processResponseHeaders(uint32_t, absl::string_view http_version) override {
    state_->response_http_version = http_version;
    state_->response_headers_calls++;
    return absl::OkStatus();
  }
  absl::Status appendResponseBody(absl::string_view data) override {
    state_->response_body.append(data.data(), data.size());
    return absl::OkStatus();
  }
  absl::Status processResponseBody() override {
    state_->response_body_calls++;
    return state_->response_body_status;
  }
  absl::StatusOr<Engine::LoggingResult> processLogging() override {
    state_->logging_calls++;
    if (!state_->logging_status.ok()) {
      return state_->logging_status;
    }
    return state_->logging_result;
  }
  absl::StatusOr<std::optional<Engine::Intervention>> intervention() override {
    state_->intervention_calls++;
    if (state_->intervene_on_call != 0 && state_->intervention_calls == state_->intervene_on_call) {
      return state_->intervention;
    }
    return std::nullopt;
  }

 private:
  const std::shared_ptr<TransactionState> state_;
};

class FakeGeneration final : public Engine::RuleGeneration {
 public:
  explicit FakeGeneration(std::shared_ptr<TransactionState> state) : state_(std::move(state)) {}

  absl::StatusOr<std::unique_ptr<Engine::Transaction>> createTransaction() const override {
    return std::unique_ptr<Engine::Transaction>(new FakeTransaction(state_));
  }
  uint64_t generationId() const override { return 7; }
  uint64_t loadedRuleCount() const override { return 1; }
  uint64_t sourceCount() const override { return 1; }

 private:
  const std::shared_ptr<TransactionState> state_;
};

class FilterTest : public testing::Test {
 public:
  void initialize(uint64_t request_limit = 32,
                  std::optional<uint64_t> response_limit = std::nullopt,
                  bool failure_mode_allow = false, uint64_t active_body_limit = 64,
                  std::string request_intervention_body = "request blocked by ModSecurity",
                  std::string response_intervention_body = "response blocked by ModSecurity") {
    state_ = std::make_shared<TransactionState>();
    generation_ = std::make_shared<FakeGeneration>(state_);
    stats_ = std::make_shared<FilterStats>(
        FilterStats::generate("test.modsecurity", *store_.rootScope()));
    body_memory_budget_ = std::make_shared<BodyMemoryBudget>(active_body_limit);
    config_ = std::make_shared<FilterConfig>(
        EffectiveSettings{request_limit, response_limit, failure_mode_allow,
                          Http::Code::InternalServerError,
                          std::make_shared<const std::string>(
                              std::move(request_intervention_body)),
                          std::make_shared<const std::string>(
                              std::move(response_intervention_body))},
        generation_, stats_, body_memory_budget_, time_system_);
    filter_ = std::make_unique<Filter>(config_);
    filter_->setDecoderFilterCallbacks(decoder_callbacks_);
    filter_->setEncoderFilterCallbacks(encoder_callbacks_);
  }

  Http::TestRequestHeaderMapImpl requestHeaders() {
    return {{":method", "POST"}, {":path", "/submit"}, {":authority", "example.test"}};
  }

  Event::SimulatedTimeSystem time_system_;
  Stats::IsolatedStoreImpl store_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  NiceMock<Http::MockStreamEncoderFilterCallbacks> encoder_callbacks_;
  std::shared_ptr<TransactionState> state_;
  std::shared_ptr<FakeGeneration> generation_;
  FilterStatsSharedPtr stats_;
  BodyMemoryBudgetSharedPtr body_memory_budget_;
  FilterConfigSharedPtr config_;
  std::unique_ptr<Filter> filter_;
};

TEST_F(FilterTest, BuffersRequestAndRunsEachPhaseExactlyOnce) {
  initialize();
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .Times(0);
  auto headers = requestHeaders();

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  Buffer::OwnedImpl first("hello");
  EXPECT_EQ(filter_->decodeData(first, false), Http::FilterDataStatus::StopIterationAndBuffer);
  Buffer::OwnedImpl second(" world");
  EXPECT_EQ(filter_->decodeData(second, true), Http::FilterDataStatus::Continue);

  EXPECT_EQ(state_->request_body, "hello world");
  EXPECT_EQ(state_->request_http_version, "1.1");
  EXPECT_EQ(state_->request_headers_calls, 1);
  EXPECT_EQ(state_->request_body_calls, 1);
  EXPECT_EQ(state_->logging_calls, 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  EXPECT_EQ(stats_->modsecurity_buffer_bytes_.value(), 0);
  EXPECT_EQ(body_memory_budget_->used(), 0);

  filter_->onStreamComplete();
  filter_->onStreamComplete();
  filter_->onDestroy();
  EXPECT_EQ(state_->logging_calls, 1);
}

TEST_F(FilterTest, UsesAuthorityFormTargetForStandardConnect) {
  initialize();
  Http::TestRequestHeaderMapImpl headers{{":method", "CONNECT"},
                                         {":authority", "proxy.example:443"}};

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);

  EXPECT_EQ(state_->request_method, "CONNECT");
  EXPECT_EQ(state_->request_uri, "proxy.example:443");
  EXPECT_EQ(state_->request_headers_calls, 1);
  EXPECT_EQ(stats_->request_body_bypassed_.value(), 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, PreservesPathTargetForExtendedConnect) {
  initialize();
  Http::TestRequestHeaderMapImpl headers{{":method", "CONNECT"},
                                         {":protocol", "websocket"},
                                         {":scheme", "https"},
                                         {":path", "/chat"},
                                         {":authority", "example.test"}};

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);

  EXPECT_EQ(state_->request_method, "CONNECT");
  EXPECT_EQ(state_->request_uri, "/chat");
  EXPECT_EQ(state_->request_headers_calls, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, PublishesBoundedDetectionMetadataWithoutMatchedValues) {
  initialize();
  for (size_t i = 0; i < Engine::LoggingResult::MaxRuleEvents; ++i) {
    state_->logging_result.rules.push_back({static_cast<int64_t>(942000 + i), 2, false});
  }
  state_->logging_result.rules_truncated = true;
  state_->logging_result.blocking_inbound_anomaly_score = 7;
  state_->logging_result.detection_inbound_anomaly_score = 12;
  state_->logging_result.inbound_anomaly_score_threshold = 5;

  Protobuf::Struct metadata;
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .WillOnce(SaveArg<1>(&metadata));
  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::Continue);

  const auto& fields = metadata.fields();
  EXPECT_EQ(fields.at("schema_version").number_value(), 1);
  EXPECT_EQ(fields.at("outcome").string_value(), "allowed");
  EXPECT_EQ(fields.at("reason").string_value(), "rule_match");
  EXPECT_EQ(fields.at("phase").string_value(), "complete");
  EXPECT_EQ(fields.at("rule_generation").string_value(), "7");
  EXPECT_EQ(fields.at("blocking_inbound_anomaly_score").number_value(), 7);
  EXPECT_EQ(fields.at("detection_inbound_anomaly_score").number_value(), 12);
  EXPECT_EQ(fields.at("inbound_anomaly_score_threshold").number_value(), 5);
  ASSERT_EQ(fields.at("rules").list_value().values_size(), Engine::LoggingResult::MaxRuleEvents);
  const Protobuf::Struct& first_rule = fields.at("rules").list_value().values(0).struct_value();
  EXPECT_EQ(first_rule.fields().at("id").string_value(), "942000");
  EXPECT_EQ(first_rule.fields().at("phase").number_value(), 2);
  EXPECT_FALSE(first_rule.fields().at("disruptive").bool_value());
  EXPECT_TRUE(fields.at("rules_truncated").bool_value());
  EXPECT_EQ(stats_->security_events_.value(), 1);
  EXPECT_EQ(stats_->security_event_rule_truncations_.value(), 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, LoggingFailurePublishesLossSignalWithoutChangingTrafficOutcome) {
  initialize();
  state_->logging_status = absl::InternalError("logging unavailable");
  Protobuf::Struct metadata;
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .WillOnce(SaveArg<1>(&metadata));

  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::Continue);

  EXPECT_EQ(metadata.fields().at("outcome").string_value(), "allowed");
  EXPECT_EQ(metadata.fields().at("reason").string_value(), "logging_error");
  EXPECT_TRUE(metadata.fields().at("logging_error").bool_value());
  EXPECT_EQ(stats_->logging_errors_.value(), 1);
  EXPECT_EQ(stats_->security_events_.value(), 1);
  filter_->onDestroy();
  EXPECT_EQ(state_->logging_calls, 1);
}

TEST_F(FilterTest, DestroyedActiveStreamPublishesIncompleteEventOnce) {
  initialize(32, 32);
  Protobuf::Struct metadata;
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .WillOnce(SaveArg<1>(&metadata));

  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(state_->destroyed_transactions, 0);
  filter_->onDestroy();

  EXPECT_EQ(metadata.fields().at("outcome").string_value(), "incomplete");
  EXPECT_EQ(metadata.fields().at("reason").string_value(), "stream_destroyed");
  EXPECT_EQ(state_->logging_calls, 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->security_events_.value(), 1);
}

TEST_F(FilterTest, RejectsRequestOverflowBeforePartialAppend) {
  initialize(5);
  Protobuf::Struct metadata;
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .WillOnce(SaveArg<1>(&metadata));
  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);

  EXPECT_CALL(decoder_callbacks_, sendLocalReply(Http::Code::PayloadTooLarge, _, _, _,
                                                 "modsecurity_request_body_overflow"));
  Buffer::OwnedImpl body("123456");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  EXPECT_TRUE(state_->request_body.empty());
  EXPECT_EQ(stats_->request_body_overflow_.value(), 1);
  EXPECT_EQ(metadata.fields().at("outcome").string_value(), "blocked");
  EXPECT_EQ(metadata.fields().at("reason").string_value(), "body_overflow");
  EXPECT_EQ(metadata.fields().at("http_status").number_value(), 413);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, RejectsDeclaredOversizedRequestBeforeBodyArrives) {
  initialize(5);
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/upload"},
                                         {":authority", "example.test"},
                                         {"content-length", "6"}};

  EXPECT_CALL(decoder_callbacks_, sendLocalReply(Http::Code::PayloadTooLarge, _, _, _,
                                                 "modsecurity_request_body_overflow"));
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  EXPECT_TRUE(state_->request_body.empty());
  EXPECT_EQ(stats_->request_body_overflow_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, RequestTrailersFinishBufferedBody) {
  initialize();
  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body("chunk before trailers");
  EXPECT_EQ(filter_->decodeData(body, false), Http::FilterDataStatus::StopIterationAndBuffer);
  Http::TestRequestTrailerMapImpl trailers{{"x-checksum", "complete"}};
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::Continue);

  EXPECT_EQ(state_->request_body, "chunk before trailers");
  EXPECT_EQ(state_->request_body_calls, 1);
  EXPECT_EQ(stats_->request_trailers_uninspected_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(body_memory_budget_->used(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, GrpcRequestUsesHeaderOnlyInspectionWithoutBufferingStream) {
  initialize();
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/example.Service/Stream"},
                                         {":authority", "example.test"},
                                         {"content-type", "application/grpc"},
                                         {"te", "trailers"}};

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  Buffer::OwnedImpl message("binary grpc message");
  EXPECT_EQ(filter_->decodeData(message, false), Http::FilterDataStatus::Continue);

  EXPECT_TRUE(state_->request_body.empty());
  EXPECT_EQ(state_->request_body_calls, 0);
  EXPECT_EQ(stats_->request_body_bypassed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, GrpcResponseUsesHeaderOnlyInspectionAndReleasesTransaction) {
  initialize(32, 32);
  Http::TestRequestHeaderMapImpl request_headers{{":method", "POST"},
                                                 {":path", "/example.Service/Stream"},
                                                 {":authority", "example.test"},
                                                 {"content-type", "application/grpc"}};
  EXPECT_EQ(filter_->decodeHeaders(request_headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(state_->destroyed_transactions, 0);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"content-type", "application/grpc"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false), Http::FilterHeadersStatus::Continue);
  Buffer::OwnedImpl message("binary grpc response");
  EXPECT_EQ(filter_->encodeData(message, false), Http::FilterDataStatus::Continue);

  EXPECT_EQ(state_->response_headers_calls, 1);
  EXPECT_EQ(state_->response_body_calls, 0);
  EXPECT_EQ(stats_->response_body_bypassed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, ConnectStreamingRequestUsesHeaderOnlyInspection) {
  initialize();
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/example.Service/Stream"},
                                         {":authority", "example.test"},
                                         {"content-type", "application/connect+proto"},
                                         {"connect-protocol-version", "1"}};

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  Buffer::OwnedImpl envelope("connect streaming envelope");
  EXPECT_EQ(filter_->decodeData(envelope, false), Http::FilterDataStatus::Continue);

  EXPECT_TRUE(state_->request_body.empty());
  EXPECT_EQ(state_->request_body_calls, 0);
  EXPECT_EQ(stats_->request_body_bypassed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, WebSocketInspectsHandshakeWithoutBufferingTunnelData) {
  initialize(32, 32);
  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/socket"},
                                                 {":authority", "example.test"},
                                                 {"connection", "keep-alive, Upgrade"},
                                                 {"upgrade", "websocket"}};
  EXPECT_EQ(filter_->decodeHeaders(request_headers, false), Http::FilterHeadersStatus::Continue);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "101"}, {"connection", "Upgrade"}, {"upgrade", "websocket"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false), Http::FilterHeadersStatus::Continue);
  Buffer::OwnedImpl frame("websocket frame");
  EXPECT_EQ(filter_->decodeData(frame, false), Http::FilterDataStatus::Continue);
  EXPECT_EQ(filter_->encodeData(frame, false), Http::FilterDataStatus::Continue);

  EXPECT_EQ(state_->request_body_calls, 0);
  EXPECT_EQ(state_->response_body_calls, 0);
  EXPECT_EQ(stats_->request_body_bypassed_.value(), 1);
  EXPECT_EQ(stats_->response_body_bypassed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, RejectedWebSocketUpgradeStillInspectsFiniteResponseBody) {
  initialize(32, 32);
  Http::TestRequestHeaderMapImpl request_headers{{":method", "GET"},
                                                 {":path", "/socket"},
                                                 {":authority", "example.test"},
                                                 {"connection", "Upgrade"},
                                                 {"upgrade", "websocket"}};
  EXPECT_EQ(filter_->decodeHeaders(request_headers, false), Http::FilterHeadersStatus::Continue);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "403"},
                                                   {"content-type", "text/plain"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);
  Buffer::OwnedImpl body("upgrade rejected");
  EXPECT_EQ(filter_->encodeData(body, true), Http::FilterDataStatus::Continue);

  EXPECT_EQ(state_->response_body, "upgrade rejected");
  EXPECT_EQ(state_->response_body_calls, 1);
  EXPECT_EQ(stats_->response_body_bypassed_.value(), 0);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, ServerSentEventsResponseDoesNotWaitForEndStream) {
  initialize(32, 32);
  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"}, {":path", "/events"}, {":authority", "example.test"}};
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);

  Http::TestResponseHeaderMapImpl response_headers{
      {":status", "200"}, {"content-type", "text/event-stream; charset=utf-8"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false), Http::FilterHeadersStatus::Continue);
  Buffer::OwnedImpl event("data: ready\n\n");
  EXPECT_EQ(filter_->encodeData(event, false), Http::FilterDataStatus::Continue);

  EXPECT_EQ(state_->response_body_calls, 0);
  EXPECT_EQ(stats_->response_body_bypassed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, HoldsAndInspectsResponseWhenEnabled) {
  initialize(32, 32);
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"},
                                                   {"content-type", "text/plain"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);
  Buffer::OwnedImpl response_body("safe response");
  EXPECT_EQ(filter_->encodeData(response_body, true), Http::FilterDataStatus::Continue);
  EXPECT_EQ(state_->response_body, "safe response");
  EXPECT_EQ(state_->response_http_version, "HTTP/1.1");
  EXPECT_EQ(state_->response_headers_calls, 1);
  EXPECT_EQ(state_->response_body_calls, 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  EXPECT_EQ(stats_->modsecurity_buffer_bytes_.value(), 0);
  EXPECT_EQ(body_memory_budget_->used(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, RuntimeFailureCanFailOpen) {
  initialize(32, std::nullopt, true);
  state_->request_headers_status = absl::InternalError("engine unavailable");
  Protobuf::Struct metadata;
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .WillOnce(SaveArg<1>(&metadata));
  auto headers = requestHeaders();

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 1);
  EXPECT_EQ(metadata.fields().at("outcome").string_value(), "bypassed");
  EXPECT_EQ(metadata.fields().at("reason").string_value(), "runtime_error");
  EXPECT_EQ(metadata.fields().at("phase").string_value(), "request");
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  Buffer::OwnedImpl body("not inspected after failure");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::Continue);
  filter_->onDestroy();
}

TEST_F(FilterTest, BodyRuntimeFailureCanFailOpenAndReleaseIteration) {
  initialize(32, std::nullopt, true);
  state_->request_body_status = absl::InternalError("engine unavailable");
  auto headers = requestHeaders();

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  Buffer::OwnedImpl body("buffered body");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::Continue);
  EXPECT_EQ(state_->request_body_calls, 1);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  EXPECT_EQ(stats_->modsecurity_buffer_bytes_.value(), 0);
  EXPECT_EQ(body_memory_budget_->used(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, RuntimeFailureFailsClosedByDefault) {
  initialize();
  state_->request_headers_status = absl::InternalError("engine unavailable");
  auto headers = requestHeaders();

  EXPECT_CALL(decoder_callbacks_, sendLocalReply(Http::Code::InternalServerError, _, _, _,
                                                 "modsecurity_runtime_error"));
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 0);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, DisruptiveInterventionSendsLocalReply) {
  initialize();
  state_->intervene_on_call = 3;
  state_->intervention = Engine::Intervention{403, {}};
  state_->logging_result.rules = {{942100, 2, false}, {949110, 2, true}};
  state_->logging_result.blocking_inbound_anomaly_score = 5;
  state_->logging_result.inbound_anomaly_score_threshold = 5;
  Protobuf::Struct metadata;
  EXPECT_CALL(decoder_callbacks_.stream_info_,
              setDynamicMetadata("envoy.filters.http.modsecurity", _))
      .WillOnce(SaveArg<1>(&metadata));
  auto headers = requestHeaders();

  EXPECT_CALL(decoder_callbacks_,
              sendLocalReply(Http::Code::Forbidden, "request blocked by ModSecurity", _, _,
                             "modsecurity_request_intervention"));
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->request_interventions_.value(), 1);
  EXPECT_EQ(metadata.fields().at("outcome").string_value(), "blocked");
  EXPECT_EQ(metadata.fields().at("reason").string_value(), "rule_intervention");
  EXPECT_EQ(metadata.fields().at("phase").string_value(), "request");
  EXPECT_EQ(metadata.fields().at("http_status").number_value(), 403);
  EXPECT_EQ(metadata.fields().at("blocking_inbound_anomaly_score").number_value(), 5);
  ASSERT_EQ(metadata.fields().at("rules").list_value().values_size(), 2);
  EXPECT_TRUE(metadata.fields()
                  .at("rules")
                  .list_value()
                  .values(1)
                  .struct_value()
                  .fields()
                  .at("disruptive")
                  .bool_value());
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, RequestInterventionUsesConfiguredBodyAndPreservesRedirect) {
  initialize(32, std::nullopt, false, 64, "custom request intervention");
  state_->intervene_on_call = 3;
  state_->intervention = Engine::Intervention{200, "https://example.test/blocked"};
  auto headers = requestHeaders();
  std::function<void(Http::ResponseHeaderMap&)> modify_headers;

  EXPECT_CALL(decoder_callbacks_,
              sendLocalReply(Http::Code::Found, "custom request intervention", _, _,
                             "modsecurity_request_intervention"))
      .WillOnce(SaveArg<2>(&modify_headers));
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::StopIteration);

  ASSERT_NE(modify_headers, nullptr);
  Http::TestResponseHeaderMapImpl response_headers;
  modify_headers(response_headers);
  EXPECT_EQ(response_headers.getLocationValue(), "https://example.test/blocked");
  EXPECT_EQ(stats_->request_interventions_.value(), 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, RequestInterventionAllowsExplicitEmptyBody) {
  initialize(32, std::nullopt, false, 64, "");
  state_->intervene_on_call = 3;
  state_->intervention = Engine::Intervention{403, {}};
  auto headers = requestHeaders();

  EXPECT_CALL(decoder_callbacks_,
              sendLocalReply(Http::Code::Forbidden, "", _, _,
                             "modsecurity_request_intervention"));
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::StopIteration);
  filter_->onDestroy();
}

TEST_F(FilterTest, ResponseInterventionUsesConfiguredBody) {
  initialize(32, 32, false, 64, "request body", "custom response intervention");
  state_->intervene_on_call = 5;
  state_->intervention = Engine::Intervention{451, {}};
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};

  EXPECT_CALL(encoder_callbacks_,
              sendLocalReply(static_cast<Http::Code>(451), "custom response intervention", _, _,
                             "modsecurity_response_intervention"));
  EXPECT_EQ(filter_->encodeHeaders(response_headers, true),
            Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->response_interventions_.value(), 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, ResponseOverflowIsFailClosedEvenWhenFailureModeAllows) {
  initialize(32, 5, true);
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);

  EXPECT_CALL(encoder_callbacks_, sendLocalReply(Http::Code::InternalServerError, _, _, _,
                                                 "modsecurity_response_body_overflow"));
  Buffer::OwnedImpl response_body("123456");
  EXPECT_EQ(filter_->encodeData(response_body, true),
            Http::FilterDataStatus::StopIterationNoBuffer);
  EXPECT_EQ(stats_->response_body_overflow_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, RejectsDeclaredOversizedResponseBeforeBodyArrives) {
  initialize(32, 5);
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}, {"content-length", "6"}};

  EXPECT_CALL(encoder_callbacks_, sendLocalReply(Http::Code::InternalServerError, _, _, _,
                                                 "modsecurity_response_body_overflow"));
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->response_body_overflow_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, ResponseTrailersFinishBufferedBody) {
  initialize(32, 32);
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body("chunk before trailers");
  EXPECT_EQ(filter_->encodeData(body, false), Http::FilterDataStatus::StopIterationAndBuffer);
  Http::TestResponseTrailerMapImpl trailers{{"x-checksum", "complete"}};
  EXPECT_EQ(filter_->encodeTrailers(trailers), Http::FilterTrailersStatus::Continue);

  EXPECT_EQ(state_->response_body, "chunk before trailers");
  EXPECT_EQ(state_->response_body_calls, 1);
  EXPECT_EQ(stats_->response_trailers_uninspected_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(body_memory_budget_->used(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, ResponseBodyRuntimeFailureCanFailOpenAndReleaseIteration) {
  initialize(32, 32, true);
  state_->response_body_status = absl::InternalError("engine unavailable");
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);
  Buffer::OwnedImpl response_body("buffered response");
  EXPECT_EQ(filter_->encodeData(response_body, true), Http::FilterDataStatus::Continue);
  EXPECT_EQ(state_->response_body_calls, 1);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  EXPECT_EQ(stats_->modsecurity_buffer_bytes_.value(), 0);
  EXPECT_EQ(body_memory_budget_->used(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, BodyMemoryBudgetFailsClosedAndReleasesTransaction) {
  initialize(32, std::nullopt, true, 32);
  ASSERT_TRUE(body_memory_budget_->tryReserve(30));
  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);

  EXPECT_CALL(decoder_callbacks_, sendLocalReply(Http::Code::InternalServerError, _, _, _,
                                                 "modsecurity_body_memory_budget_exceeded"));
  Buffer::OwnedImpl body("123");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  EXPECT_EQ(stats_->body_memory_budget_exceeded_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 0);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  EXPECT_EQ(body_memory_budget_->used(), 30);
  body_memory_budget_->release(30);
  filter_->onDestroy();
}

TEST_F(FilterTest, NativeMemoryExhaustionIgnoresFailureModeAllow) {
  initialize(32, std::nullopt, true);
  state_->request_headers_status = absl::ResourceExhaustedError("allocation failed");
  auto headers = requestHeaders();

  EXPECT_CALL(decoder_callbacks_, sendLocalReply(Http::Code::InternalServerError, _, _, _,
                                                 "modsecurity_runtime_error"));
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 0);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
  filter_->onDestroy();
}

TEST(RouteConfigTest, AppliesIndependentRequestAndResponseOverrides) {
  const EffectiveSettings base{
      32,
      16,
      false,
      Http::Code::InternalServerError,
      std::make_shared<const std::string>("request blocked by ModSecurity"),
      std::make_shared<const std::string>("response blocked by ModSecurity")};

  const RouteConfig replace(false, 64, RouteConfig::ResponseOverride::Replace, 128);
  const EffectiveSettings replaced = replace.apply(base);
  EXPECT_EQ(replaced.request_body_max_bytes, 64);
  ASSERT_TRUE(replaced.response_body_max_bytes.has_value());
  EXPECT_EQ(*replaced.response_body_max_bytes, 128);
  EXPECT_EQ(replaced.request_intervention_body, base.request_intervention_body);
  EXPECT_EQ(replaced.response_intervention_body, base.response_intervention_body);
  EXPECT_FALSE(replace.disabled());

  const RouteConfig disable(false, std::nullopt, RouteConfig::ResponseOverride::Disable,
                            std::nullopt);
  const EffectiveSettings disabled = disable.apply(base);
  EXPECT_EQ(disabled.request_body_max_bytes, 32);
  EXPECT_FALSE(disabled.response_body_max_bytes.has_value());

  const RouteConfig inherit(false, std::nullopt, RouteConfig::ResponseOverride::Inherit,
                            std::nullopt);
  const EffectiveSettings inherited = inherit.apply(base);
  EXPECT_EQ(inherited.request_body_max_bytes, 32);
  ASSERT_TRUE(inherited.response_body_max_bytes.has_value());
  EXPECT_EQ(*inherited.response_body_max_bytes, 16);

  const RouteConfig route_disabled(true, std::nullopt, RouteConfig::ResponseOverride::Inherit,
                                   std::nullopt);
  EXPECT_TRUE(route_disabled.disabled());
}

}  // namespace
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
