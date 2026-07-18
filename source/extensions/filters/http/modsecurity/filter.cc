#include "source/extensions/filters/http/modsecurity/filter.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_join.h"
#include "envoy/network/address.h"
#include "source/common/grpc/common.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

struct IpEndpoint {
  std::string address{"0.0.0.0"};
  uint32_t port{0};
};

IpEndpoint endpoint(const Network::Address::InstanceConstSharedPtr& address) {
  if (address == nullptr || address->ip() == nullptr) {
    return {};
  }
  return {address->ip()->addressAsString(), address->ip()->port()};
}

bool isPseudoHeader(absl::string_view name) { return !name.empty() && name.front() == ':'; }

class ScopedHistogramTimer {
 public:
  ScopedHistogramTimer(Stats::Histogram& histogram, TimeSource& time_source)
      : histogram_(histogram), time_source_(time_source), start_(time_source.monotonicTime()) {}

  ScopedHistogramTimer(const ScopedHistogramTimer&) = delete;
  ScopedHistogramTimer& operator=(const ScopedHistogramTimer&) = delete;

  ~ScopedHistogramTimer() { complete(); }

  void complete() {
    if (completed_) {
      return;
    }
    completed_ = true;
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        time_source_.monotonicTime() - start_);
    histogram_.recordValue(static_cast<uint64_t>(elapsed.count()));
  }

 private:
  Stats::Histogram& histogram_;
  TimeSource& time_source_;
  const MonotonicTime start_;
  bool completed_{false};
};

}  // namespace

Filter::Filter(FilterConfigSharedPtr config)
    : config_(std::move(config)),
      settings_(config_->settings()),
      stats_(config_->statsShared()),
      time_source_(config_->timeSource()),
      body_memory_budget_(config_->bodyMemoryBudget()) {}

void Filter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void Filter::setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

void Filter::initializeSettings() {
  if (settings_initialized_) {
    return;
  }
  settings_initialized_ = true;

  const auto* route_config =
      Http::Utility::resolveMostSpecificPerFilterConfig<RouteConfig>(decoder_callbacks_);
  if (route_config != nullptr) {
    disabled_ = route_config->disabled();
    settings_ = route_config->apply(settings_);
  }
  if (disabled_) {
    config_.reset();
  }
}

Filter::InspectionOutcome Filter::createTransaction() {
  generation_ = config_->generation();
  auto transaction = generation_->createTransaction();
  config_.reset();
  if (!transaction.ok()) {
    generation_.reset();
    return handleEngineResult(transaction.status(), MessageSide::Request, false);
  }
  transaction_ = std::move(*transaction);
  stats_->active_transactions_.inc();
  memory_account_ = decoder_callbacks_->account();
  return InspectionOutcome::Continue;
}

std::string Filter::httpProtocol() const {
  const auto protocol = decoder_callbacks_->streamInfo().protocol();
  return protocol.has_value() ? Http::Utility::getProtocolString(*protocol) : "HTTP/1.1";
}

Filter::InspectionOutcome Filter::handleEngineResult(const absl::Status& status, MessageSide side,
                                                     bool check_intervention) {
  if (!status.ok()) {
    const bool pcre_match_limit_exceeded = Engine::isPcreMatchLimitExceeded(status);
    if (pcre_match_limit_exceeded) {
      stats_->pcre_match_limit_exceeded_.inc();
    }
    stats_->runtime_errors_.inc();
    if (settings_.failure_mode_allow && status.code() != absl::StatusCode::kResourceExhausted) {
      stats_->failure_mode_allowed_.inc();
      disposition_ = StreamDisposition::Bypassed;
      releaseResources();
      return InspectionOutcome::Bypass;
    }
    sendRuntimeError(side, pcre_match_limit_exceeded ? "modsecurity_pcre_match_limit_exceeded"
                                                     : "modsecurity_runtime_error");
    return InspectionOutcome::LocalReply;
  }
  return check_intervention ? checkIntervention(side) : InspectionOutcome::Continue;
}

Filter::InspectionOutcome Filter::checkIntervention(MessageSide side) {
  auto intervention = transaction_->intervention();
  if (!intervention.ok()) {
    return handleEngineResult(intervention.status(), side, false);
  }
  if (!intervention->has_value()) {
    return InspectionOutcome::Continue;
  }
  sendIntervention(**intervention, side);
  return InspectionOutcome::LocalReply;
}

void Filter::sendIntervention(const Engine::Intervention& intervention, MessageSide side) {
  int status = intervention.status;
  if (!intervention.redirect_url.empty() && (status < 300 || status >= 400)) {
    status = 302;
  } else if (status < 300 || status > 599) {
    status = 403;
  }

  disposition_ = StreamDisposition::LocalReply;
  if (intervention.rule_ids_truncated) {
    stats_->intervention_rule_ids_truncated_.inc();
  }
  const std::string rule_ids =
      intervention.rule_ids.empty() ? "none" : absl::StrJoin(intervention.rule_ids, ",");
  ENVOY_LOG(info, "ModSecurity intervention side={} status={} rule_ids={} truncated={}",
            side == MessageSide::Request ? "request" : "response", status, rule_ids,
            intervention.rule_ids_truncated);
  const auto code = static_cast<Http::Code>(status);
  const std::string redirect_url = intervention.redirect_url;
  auto modify_headers = [redirect_url](Http::ResponseHeaderMap& headers) {
    if (!redirect_url.empty()) {
      headers.setLocation(redirect_url);
    }
  };

  if (side == MessageSide::Request) {
    stats_->request_interventions_.inc();
    decoder_callbacks_->sendLocalReply(code, "request blocked by ModSecurity", modify_headers,
                                       std::nullopt, "modsecurity_request_intervention");
  } else {
    stats_->response_interventions_.inc();
    encoder_callbacks_->sendLocalReply(code, "response blocked by ModSecurity", modify_headers,
                                       std::nullopt, "modsecurity_response_intervention");
  }
  finishLogging();
  releaseResources();
}

void Filter::sendRuntimeError(MessageSide side, absl::string_view details) {
  disposition_ = StreamDisposition::LocalReply;
  if (side == MessageSide::Response && encoder_callbacks_ != nullptr) {
    encoder_callbacks_->sendLocalReply(settings_.status_on_error, "ModSecurity inspection error",
                                       nullptr, std::nullopt, details);
  } else {
    decoder_callbacks_->sendLocalReply(settings_.status_on_error, "ModSecurity inspection error",
                                       nullptr, std::nullopt, details);
  }
  releaseResources();
}

Filter::InspectionOutcome Filter::addHeaders(const Http::HeaderMap& headers, MessageSide side,
                                             absl::string_view request_host) {
  bool host_added = false;
  InspectionOutcome outcome = InspectionOutcome::Continue;
  headers.iterate([&](const Http::HeaderEntry& header) {
    const absl::string_view name = header.key().getStringView();
    if (isPseudoHeader(name)) {
      return Http::HeaderMap::Iterate::Continue;
    }
    host_added =
        host_added || (side == MessageSide::Request && absl::EqualsIgnoreCase(name, "host"));
    const absl::Status status =
        side == MessageSide::Request
            ? transaction_->addRequestHeader(name, header.value().getStringView())
            : transaction_->addResponseHeader(name, header.value().getStringView());
    if (!status.ok()) {
      outcome = handleEngineResult(status, side, false);
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  });

  if (outcome != InspectionOutcome::Continue || side == MessageSide::Response || host_added ||
      request_host.empty()) {
    return outcome;
  }
  return handleEngineResult(transaction_->addRequestHeader("host", request_host),
                            MessageSide::Request, false);
}

bool Filter::bodyInspectionPending(MessageSide side) const {
  if (disabled_ || disposition_ != StreamDisposition::Inspecting || transaction_ == nullptr) {
    return false;
  }
  if (side == MessageSide::Request) {
    return !request_body_.finished;
  }
  return settings_.response_body_max_bytes.has_value() && response_headers_finished_ &&
         !response_body_.finished;
}

Http::FilterHeadersStatus Filter::headerStatusForOutcome(InspectionOutcome outcome) {
  return outcome == InspectionOutcome::LocalReply ? Http::FilterHeadersStatus::StopIteration
                                                  : Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
  initializeSettings();
  if (disabled_) {
    return Http::FilterHeadersStatus::Continue;
  }

  InspectionOutcome outcome = createTransaction();
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }

  ScopedHistogramTimer timer(stats_->request_headers_duration_us_, time_source_);
  const auto& addresses = decoder_callbacks_->streamInfo().downstreamAddressProvider();
  const IpEndpoint client = endpoint(addresses.remoteAddress());
  const IpEndpoint server = endpoint(addresses.localAddress());
  outcome = handleEngineResult(
      transaction_->processConnection(client.address, client.port, server.address, server.port),
      MessageSide::Request);
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }
  outcome = handleEngineResult(
      transaction_->processUri(headers.getPathValue(), headers.getMethodValue(), httpProtocol()),
      MessageSide::Request);
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }
  outcome = addHeaders(headers, MessageSide::Request, headers.getHostValue());
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }
  outcome = handleEngineResult(transaction_->processRequestHeaders(), MessageSide::Request);
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }
  timer.complete();

  classifyRequest(headers);
  if (stream_kind_ != StreamKind::Regular) {
    skipBodyInspectionForStreaming(MessageSide::Request);
    return Http::FilterHeadersStatus::Continue;
  }
  if (end_stream) {
    return headerStatusForOutcome(completeBodyInspection(MessageSide::Request));
  }
  if (declaredBodyExceedsLimit(headers, MessageSide::Request)) {
    sendBodyOverflow(MessageSide::Request);
    return Http::FilterHeadersStatus::StopIteration;
  }

  ensureBufferLimit(MessageSide::Request);
  // StopIteration keeps request headers from the next filter while still allowing this filter to
  // receive data callbacks. Intermediate data is held with StopIterationAndBuffer below.
  return Http::FilterHeadersStatus::StopIteration;
}

bool Filter::reserveBodyBytes(uint64_t bytes) {
  if (bytes == 0) {
    return true;
  }
  if (!body_memory_budget_->tryReserve(bytes)) {
    return false;
  }
  if (memory_account_ != nullptr) {
    memory_account_->charge(bytes);
  }
  charged_body_bytes_ += bytes;
  stats_->modsecurity_buffer_bytes_.add(bytes);
  return true;
}

Filter::BodyState& Filter::bodyState(MessageSide side) {
  return side == MessageSide::Request ? request_body_ : response_body_;
}

uint64_t Filter::bodyLimit(MessageSide side) const {
  return side == MessageSide::Request ? settings_.request_body_max_bytes
                                      : *settings_.response_body_max_bytes;
}

Stats::Histogram& Filter::bodyDurationHistogram(MessageSide side) const {
  return side == MessageSide::Request ? stats_->request_body_duration_us_
                                      : stats_->response_body_duration_us_;
}

void Filter::classifyRequest(const Http::RequestHeaderMap& headers) {
  if (Grpc::Common::isGrpcRequestHeaders(headers)) {
    stream_kind_ = StreamKind::Grpc;
  } else if (Grpc::Common::isConnectStreamingRequestHeaders(headers)) {
    stream_kind_ = StreamKind::ConnectStreaming;
  } else if (Http::HeaderUtility::isConnect(headers) || Http::Utility::isUpgrade(headers)) {
    stream_kind_ = StreamKind::Tunnel;
    connect_tunnel_ = Http::HeaderUtility::isConnect(headers);
  }
}

bool Filter::shouldBypassResponseBody(const Http::ResponseHeaderMap& headers) const {
  if (stream_kind_ == StreamKind::Grpc || stream_kind_ == StreamKind::ConnectStreaming) {
    return true;
  }
  const uint64_t status = Http::Utility::getResponseStatus(headers);
  if (stream_kind_ == StreamKind::Tunnel &&
      ((connect_tunnel_ && status >= 200 && status < 300) || (!connect_tunnel_ && status == 101))) {
    return true;
  }
  return absl::StartsWithIgnoreCase(headers.getContentTypeValue(), "text/event-stream");
}

bool Filter::declaredBodyExceedsLimit(const Http::RequestOrResponseHeaderMap& headers,
                                      MessageSide side) const {
  const absl::string_view value = headers.getContentLengthValue();
  uint64_t content_length = 0;
  return !value.empty() && absl::SimpleAtoi(value, &content_length) &&
         content_length > bodyLimit(side);
}

void Filter::ensureBufferLimit(MessageSide side) {
  const uint64_t limit = bodyLimit(side);
  if (side == MessageSide::Request) {
    if (limit > decoder_callbacks_->bufferLimit()) {
      decoder_callbacks_->setBufferLimit(limit);
    }
  } else if (limit > encoder_callbacks_->bufferLimit()) {
    encoder_callbacks_->setBufferLimit(limit);
  }
}

void Filter::sendBodyOverflow(MessageSide side) {
  disposition_ = StreamDisposition::LocalReply;
  if (side == MessageSide::Request) {
    stats_->request_body_overflow_.inc();
    decoder_callbacks_->sendLocalReply(Http::Code::PayloadTooLarge,
                                       "request body exceeds ModSecurity inspection limit", nullptr,
                                       std::nullopt, "modsecurity_request_body_overflow");
    releaseResources();
    return;
  }

  stats_->response_body_overflow_.inc();
  sendRuntimeError(MessageSide::Response, "modsecurity_response_body_overflow");
}

void Filter::sendBodyMemoryBudgetExceeded(MessageSide side) {
  stats_->body_memory_budget_exceeded_.inc();
  sendRuntimeError(side, "modsecurity_body_memory_budget_exceeded");
}

Filter::InspectionOutcome Filter::appendBody(Buffer::Instance& data, MessageSide side) {
  const uint64_t length = data.length();
  BodyState& state = bodyState(side);
  const uint64_t limit = bodyLimit(side);

  if (state.bytes > limit || length > limit - state.bytes) {
    sendBodyOverflow(side);
    return InspectionOutcome::LocalReply;
  }
  if (!reserveBodyBytes(length)) {
    sendBodyMemoryBudgetExceeded(side);
    return InspectionOutcome::LocalReply;
  }
  state.bytes += length;

  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
    if (slice.len_ == 0) {
      continue;
    }
    const absl::string_view bytes(static_cast<const char*>(slice.mem_), slice.len_);
    const absl::Status status = side == MessageSide::Request
                                    ? transaction_->appendRequestBody(bytes)
                                    : transaction_->appendResponseBody(bytes);
    if (!status.ok()) {
      return handleEngineResult(status, side, false);
    }
    const InspectionOutcome outcome = checkIntervention(side);
    if (outcome != InspectionOutcome::Continue) {
      return outcome;
    }
  }
  return InspectionOutcome::Continue;
}

Filter::InspectionOutcome Filter::completeBodyInspection(MessageSide side) {
  BodyState& state = bodyState(side);
  if (state.finished) {
    return InspectionOutcome::Continue;
  }
  state.finished = true;
  ScopedHistogramTimer timer(bodyDurationHistogram(side), time_source_);
  const absl::Status status = side == MessageSide::Request ? transaction_->processRequestBody()
                                                           : transaction_->processResponseBody();
  const InspectionOutcome outcome = handleEngineResult(status, side);
  if (outcome == InspectionOutcome::Continue &&
      (side == MessageSide::Response || !settings_.response_body_max_bytes.has_value())) {
    finishLogging();
    releaseResources();
  }
  return outcome;
}

void Filter::skipBodyInspectionForStreaming(MessageSide side) {
  BodyState& state = bodyState(side);
  if (state.finished) {
    return;
  }
  state.finished = true;
  if (side == MessageSide::Request) {
    stats_->request_body_bypassed_.inc();
    if (settings_.response_body_max_bytes.has_value()) {
      return;
    }
  } else {
    stats_->response_body_bypassed_.inc();
  }
  finishLogging();
  releaseResources();
}

void Filter::skipResponseBodyInspectionByRules() {
  if (response_body_.finished) {
    return;
  }
  response_body_.finished = true;
  stats_->response_body_skipped_by_rules_.inc();
  finishLogging();
  releaseResources();
}

Http::FilterDataStatus Filter::processData(Buffer::Instance& data, bool end_stream,
                                           MessageSide side) {
  if (!bodyInspectionPending(side)) {
    return Http::FilterDataStatus::Continue;
  }
  InspectionOutcome outcome = appendBody(data, side);
  if (outcome != InspectionOutcome::Continue) {
    return outcome == InspectionOutcome::LocalReply ? Http::FilterDataStatus::StopIterationNoBuffer
                                                    : Http::FilterDataStatus::Continue;
  }
  if (end_stream) {
    outcome = completeBodyInspection(side);
    return outcome == InspectionOutcome::LocalReply ? Http::FilterDataStatus::StopIterationNoBuffer
                                                    : Http::FilterDataStatus::Continue;
  }
  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus Filter::processTrailers(MessageSide side) {
  if (!bodyInspectionPending(side)) {
    return Http::FilterTrailersStatus::Continue;
  }
  return completeBodyInspection(side) == InspectionOutcome::LocalReply
             ? Http::FilterTrailersStatus::StopIteration
             : Http::FilterTrailersStatus::Continue;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& data, bool end_stream) {
  return processData(data, end_stream, MessageSide::Request);
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {
  stats_->request_trailers_uninspected_.inc();
  return processTrailers(MessageSide::Request);
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool end_stream) {
  if (disabled_ || disposition_ != StreamDisposition::Inspecting || transaction_ == nullptr ||
      !settings_.response_body_max_bytes.has_value()) {
    return Http::FilterHeadersStatus::Continue;
  }

  ScopedHistogramTimer timer(stats_->response_headers_duration_us_, time_source_);
  InspectionOutcome outcome = addHeaders(headers, MessageSide::Response);
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }
  const uint64_t response_status = Http::Utility::getResponseStatus(headers);
  outcome = handleEngineResult(
      transaction_->processResponseHeaders(response_status, httpProtocol()), MessageSide::Response);
  if (outcome != InspectionOutcome::Continue) {
    return headerStatusForOutcome(outcome);
  }
  response_headers_finished_ = true;
  timer.complete();

  if (end_stream) {
    return headerStatusForOutcome(completeBodyInspection(MessageSide::Response));
  }
  if (shouldBypassResponseBody(headers)) {
    skipBodyInspectionForStreaming(MessageSide::Response);
    return Http::FilterHeadersStatus::Continue;
  }
  auto should_inspect_body = transaction_->shouldInspectResponseBody();
  if (!should_inspect_body.ok()) {
    return headerStatusForOutcome(
        handleEngineResult(should_inspect_body.status(), MessageSide::Response, false));
  }
  if (!*should_inspect_body) {
    skipResponseBodyInspectionByRules();
    return Http::FilterHeadersStatus::Continue;
  }
  if (declaredBodyExceedsLimit(headers, MessageSide::Response)) {
    sendBodyOverflow(MessageSide::Response);
    return Http::FilterHeadersStatus::StopIteration;
  }

  ensureBufferLimit(MessageSide::Response);
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus Filter::encodeData(Buffer::Instance& data, bool end_stream) {
  return processData(data, end_stream, MessageSide::Response);
}

Http::FilterTrailersStatus Filter::encodeTrailers(Http::ResponseTrailerMap&) {
  stats_->response_trailers_uninspected_.inc();
  return processTrailers(MessageSide::Response);
}

void Filter::finishLogging() {
  if (logging_finished_ || transaction_ == nullptr) {
    return;
  }
  logging_finished_ = true;
  ScopedHistogramTimer timer(stats_->logging_duration_us_, time_source_);
  const absl::Status status = transaction_->processLogging();
  if (!status.ok()) {
    if (Engine::isPcreMatchLimitExceeded(status)) {
      stats_->pcre_match_limit_exceeded_.inc();
    }
    stats_->logging_errors_.inc();
  }
}

void Filter::onStreamComplete() { finishLogging(); }

void Filter::releaseResources() {
  if (resources_released_) {
    return;
  }
  resources_released_ = true;
  if (transaction_ != nullptr) {
    transaction_.reset();
    stats_->active_transactions_.dec();
  }
  generation_.reset();
  if (charged_body_bytes_ != 0) {
    if (memory_account_ != nullptr) {
      memory_account_->credit(charged_body_bytes_);
    }
    body_memory_budget_->release(charged_body_bytes_);
    stats_->modsecurity_buffer_bytes_.sub(charged_body_bytes_);
    charged_body_bytes_ = 0;
  }
  memory_account_.reset();
}

void Filter::onDestroy() {
  finishLogging();
  releaseResources();
}

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
