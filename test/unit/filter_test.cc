#include "source/extensions/filters/http/modsecurity/filter.h"

#include <memory>
#include <optional>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/stats/isolated_store_impl.h"

#include "test/mocks/http/mocks.h"
#include "test/test_common/simulated_time_system.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

struct TransactionState {
  std::string request_body;
  std::string response_body;
  absl::Status request_headers_status{absl::OkStatus()};
  int request_headers_calls{0};
  int request_body_calls{0};
  int response_headers_calls{0};
  int response_body_calls{0};
  int logging_calls{0};
  int intervention_calls{0};
  int intervene_on_call{0};
  std::optional<Engine::Intervention> intervention;
};

class FakeTransaction final : public Engine::Transaction {
public:
  explicit FakeTransaction(std::shared_ptr<TransactionState> state) : state_(std::move(state)) {}

  absl::Status processConnection(absl::string_view, uint32_t, absl::string_view,
                                 uint32_t) override {
    return absl::OkStatus();
  }
  absl::Status processUri(absl::string_view, absl::string_view,
                          absl::string_view) override {
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
    return absl::OkStatus();
  }
  absl::Status addResponseHeader(absl::string_view, absl::string_view) override {
    return absl::OkStatus();
  }
  absl::Status processResponseHeaders(uint32_t, absl::string_view) override {
    state_->response_headers_calls++;
    return absl::OkStatus();
  }
  absl::Status appendResponseBody(absl::string_view data) override {
    state_->response_body.append(data.data(), data.size());
    return absl::OkStatus();
  }
  absl::Status processResponseBody() override {
    state_->response_body_calls++;
    return absl::OkStatus();
  }
  absl::Status processLogging() override {
    state_->logging_calls++;
    return absl::OkStatus();
  }
  absl::StatusOr<std::optional<Engine::Intervention>> intervention() override {
    state_->intervention_calls++;
    if (state_->intervene_on_call != 0 &&
        state_->intervention_calls == state_->intervene_on_call) {
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
                  bool failure_mode_allow = false) {
    state_ = std::make_shared<TransactionState>();
    generation_ = std::make_shared<FakeGeneration>(state_);
    stats_ = std::make_shared<FilterStats>(
        FilterStats::generate("test.modsecurity", *store_.rootScope()));
    config_ = std::make_shared<FilterConfig>(
        EffectiveSettings{request_limit, response_limit, failure_mode_allow,
                          Http::Code::InternalServerError},
        generation_, stats_, time_system_);
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
  EXPECT_EQ(state_->request_headers_calls, 1);
  EXPECT_EQ(state_->request_body_calls, 1);

  filter_->onStreamComplete();
  filter_->onStreamComplete();
  filter_->onDestroy();
  EXPECT_EQ(state_->logging_calls, 1);
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
  EXPECT_EQ(state_->response_headers_calls, 1);
  EXPECT_EQ(state_->response_body_calls, 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, RuntimeFailureCanFailOpen) {
  initialize(32, std::nullopt, true);
  state_->request_headers_status = absl::InternalError("engine unavailable");
  auto headers = requestHeaders();

  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(stats_->runtime_errors_.value(), 1);
  EXPECT_EQ(stats_->failure_mode_allowed_.value(), 1);
  Buffer::OwnedImpl body("not inspected after failure");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::Continue);
  filter_->onDestroy();
}

TEST_F(FilterTest, DisruptiveInterventionSendsLocalReply) {
  initialize();
  state_->intervene_on_call = 3;
  state_->intervention = Engine::Intervention{403, {}, "blocked"};
  auto headers = requestHeaders();

  EXPECT_CALL(decoder_callbacks_,
              sendLocalReply(Http::Code::Forbidden, _, _, _,
                             "modsecurity_request_intervention"));
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(stats_->request_interventions_.value(), 1);
  filter_->onDestroy();
}

TEST_F(FilterTest, ResponseOverflowIsFailClosedEvenWhenFailureModeAllows) {
  initialize(32, 5, true);
  auto request_headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(request_headers, true), Http::FilterHeadersStatus::Continue);
  Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  EXPECT_EQ(filter_->encodeHeaders(response_headers, false),
            Http::FilterHeadersStatus::StopIteration);

  EXPECT_CALL(encoder_callbacks_,
              sendLocalReply(Http::Code::InternalServerError, _, _, _,
                             "modsecurity_response_body_overflow"));
  Buffer::OwnedImpl response_body("123456");
  EXPECT_EQ(filter_->encodeData(response_body, true),
            Http::FilterDataStatus::StopIterationNoBuffer);
  EXPECT_EQ(stats_->response_body_overflow_.value(), 1);
  filter_->onDestroy();
}

} // namespace
} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
