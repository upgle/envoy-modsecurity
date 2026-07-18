#include "source/extensions/filters/http/modsecurity/filter.h"

#include <memory>
#include <optional>
#include <string>

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

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

struct TransactionState {
  std::string request_body;
  std::string request_http_protocol;
  std::string response_body;
  std::string response_http_protocol;
  absl::Status request_headers_status{absl::OkStatus()};
  absl::Status request_body_status{absl::OkStatus()};
  absl::Status response_body_status{absl::OkStatus()};
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
  absl::Status processUri(absl::string_view, absl::string_view,
                          absl::string_view http_protocol) override {
    state_->request_http_protocol = http_protocol;
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
  absl::Status processResponseHeaders(uint32_t, absl::string_view http_protocol) override {
    state_->response_http_protocol = http_protocol;
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
  absl::Status processLogging() override {
    state_->logging_calls++;
    return absl::OkStatus();
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
  uint64_t loadedRuleCount() const override { return 1; }
  uint64_t sourceCount() const override { return 1; }

 private:
  const std::shared_ptr<TransactionState> state_;
};

class FilterTest : public testing::Test {
 public:
  void initialize(uint64_t request_limit = 32,
                  std::optional<uint64_t> response_limit = std::nullopt,
                  bool failure_mode_allow = false, uint64_t active_body_limit = 64) {
    state_ = std::make_shared<TransactionState>();
    generation_ = std::make_shared<FakeGeneration>(state_);
    stats_ = std::make_shared<FilterStats>(
        FilterStats::generate("test.modsecurity", *store_.rootScope()));
    body_memory_budget_ = std::make_shared<BodyMemoryBudget>(active_body_limit);
    config_ = std::make_shared<FilterConfig>(
        EffectiveSettings{request_limit, response_limit, failure_mode_allow,
                          Http::Code::InternalServerError},
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
  auto headers = requestHeaders();

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  Buffer::OwnedImpl first("hello");
  EXPECT_EQ(filter_->decodeData(first, false), Http::FilterDataStatus::StopIterationAndBuffer);
  Buffer::OwnedImpl second(" world");
  EXPECT_EQ(filter_->decodeData(second, true), Http::FilterDataStatus::Continue);

  EXPECT_EQ(state_->request_body, "hello world");
  EXPECT_EQ(state_->request_http_protocol, "HTTP/1.1");
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

TEST_F(FilterTest, ActiveRuleGenerationTracksInFlightTransactionAfterConfigRelease) {
  initialize();
  EXPECT_EQ(stats_->active_rule_generations_.value(), 1);

  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);
  config_.reset();
  EXPECT_EQ(stats_->active_rule_generations_.value(), 1);

  Buffer::OwnedImpl body("complete");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::Continue);
  EXPECT_EQ(stats_->active_rule_generations_.value(), 0);
  filter_->onDestroy();
}

TEST_F(FilterTest, PassesCanonicalHttp2ProtocolToEngineInterface) {
  initialize(32, 32);
  decoder_callbacks_.stream_info_.protocol_ = Http::Protocol::Http2;

  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(state_->request_http_protocol, "HTTP/2");

  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, true), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(state_->response_http_protocol, "HTTP/2");
  filter_->onDestroy();
}

TEST_F(FilterTest, RejectsRequestOverflowBeforePartialAppend) {
  initialize(5);
  auto headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::StopIteration);

  EXPECT_CALL(decoder_callbacks_, sendLocalReply(Http::Code::PayloadTooLarge, _, _, _,
                                                 "modsecurity_request_body_overflow"));
  Buffer::OwnedImpl body("123456");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  EXPECT_TRUE(state_->request_body.empty());
  EXPECT_EQ(stats_->request_body_overflow_.value(), 1);
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
  EXPECT_EQ(state_->response_http_protocol, "HTTP/1.1");
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
  auto headers = requestHeaders();

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 1);
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
  auto headers = requestHeaders();

  EXPECT_CALL(decoder_callbacks_,
              sendLocalReply(Http::Code::Forbidden, _, _, _, "modsecurity_request_intervention"));
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->request_interventions_.value(), 1);
  EXPECT_EQ(state_->destroyed_transactions, 1);
  EXPECT_EQ(stats_->active_transactions_.value(), 0);
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
  const EffectiveSettings base{32, 16, false, Http::Code::InternalServerError};

  const RouteConfig replace(false, 64, RouteConfig::ResponseOverride::Replace, 128);
  const EffectiveSettings replaced = replace.apply(base);
  EXPECT_EQ(replaced.request_body_max_bytes, 64);
  ASSERT_TRUE(replaced.response_body_max_bytes.has_value());
  EXPECT_EQ(*replaced.response_body_max_bytes, 128);
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
