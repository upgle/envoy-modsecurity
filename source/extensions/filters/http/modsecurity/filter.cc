#include "source/extensions/filters/http/modsecurity/filter.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/strip.h"
#include "envoy/network/address.h"
#include "source/common/grpc/common.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/protobuf.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

constexpr absl::string_view SecurityMetadataNamespace = "envoy.filters.http.modsecurity";

const std::string& securityMetadataNamespace() {
  static const std::string value(SecurityMetadataNamespace);
  return value;
}

struct IpEndpoint {
  absl::string_view address{"0.0.0.0"};
  uint32_t port{0};
};

IpEndpoint endpoint(const Network::Address::InstanceConstSharedPtr& address) {
  if (address == nullptr || address->ip() == nullptr) {
    return {};
  }
  return {address->ip()->addressAsString(), address->ip()->port()};
}

bool isPseudoHeader(absl::string_view name) { return !name.empty() && name.front() == ':'; }

bool diagnosticStageTimingEnabled() {
  static const bool enabled = [] {
    const char* value = std::getenv("ENVOY_MODSECURITY_STAGE_TIMING");
    return value != nullptr && absl::string_view(value) != "0";
  }();
  return enabled;
}

class ScopedCounterTimer {
 public:
  ScopedCounterTimer(bool enabled, Stats::Counter& counter, TimeSource& time_source)
      : counter_(enabled ? &counter : nullptr), time_source_(time_source) {
    if (counter_ != nullptr) {
      start_ = time_source_.monotonicTime();
    }
  }

  ScopedCounterTimer(const ScopedCounterTimer&) = delete;
  ScopedCounterTimer& operator=(const ScopedCounterTimer&) = delete;

  ~ScopedCounterTimer() {
    if (counter_ == nullptr) {
      return;
    }
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::nanoseconds>(time_source_.monotonicTime() - start_);
    counter_->add(static_cast<uint64_t>(elapsed.count()));
  }

 private:
  Stats::Counter* counter_;
  TimeSource& time_source_;
  MonotonicTime start_;
};

template <class Callback>
auto timedCall(bool enabled, Stats::Counter& counter, TimeSource& time_source,
               Callback&& callback) {
  ScopedCounterTimer timer(enabled, counter, time_source);
  return callback();
}

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

bool nonZero(const std::optional<int64_t>& value) { return value.has_value() && *value != 0; }

bool thresholdExceeded(const std::optional<int64_t>& score,
                       const std::optional<int64_t>& threshold) {
  return score.has_value() && threshold.has_value() && *score >= *threshold;
}

void setOptionalNumber(Protobuf::Struct& metadata, absl::string_view name,
                       const std::optional<int64_t>& value) {
  if (value.has_value()) {
    (*metadata.mutable_fields())[std::string(name)].set_number_value(static_cast<double>(*value));
  }
}

}  // namespace

Filter::Filter(FilterConfigSharedPtr config)
    : config_(std::move(config)),
      settings_(config_->settings()),
      stats_(config_->statsShared()),
      time_source_(config_->timeSource()),
      body_memory_budget_(config_->bodyMemoryBudget()),
      rule_engine_mode_(config_->generation()->ruleEngineMode()),
      stage_timing_enabled_(diagnosticStageTimingEnabled()) {}

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

bool Filter::createTransaction() {
  ScopedCounterTimer timer(stage_timing_enabled_, stats_->stage_profile_transaction_create_ns_,
                           time_source_);
  rule_generation_id_ = config_->generation()->generationId();
  auto transaction = config_->generation()->createTransaction();
  config_.reset();
  if (!transaction.ok()) {
    return evaluate(transaction.status(), Path::Request, false);
  }
  transaction_ = std::move(*transaction);
  stats_->active_transactions_.inc();
  memory_account_ = decoder_callbacks_->account();
  return true;
}

absl::string_view Filter::httpVersion() const {
  const auto protocol = decoder_callbacks_->streamInfo().protocol();
  if (protocol.has_value()) {
    return Http::Utility::getProtocolString(*protocol);
  }
  return "HTTP/1.1";
}

absl::string_view Filter::modSecurityRequestVersion() const {
  const absl::string_view version = httpVersion();
  constexpr absl::string_view prefix = "HTTP/";
  // libmodsecurity's processURI API prepends "HTTP/" when it initializes REQUEST_PROTOCOL.
  return absl::StartsWith(version, prefix) ? version.substr(prefix.size()) : version;
}

bool Filter::evaluate(const absl::Status& status, Path path, bool check_intervention) {
  if (!status.ok()) {
    stats_->runtime_errors_.inc();
    if (settings_.failure_mode_allow && status.code() != absl::StatusCode::kResourceExhausted) {
      stats_->failure_mode_allowed_.inc();
      engine_bypassed_ = true;
      setSecurityOutcome(SecurityOutcome::Bypassed, SecurityReason::RuntimeError, path);
      publishSecurityEvent(nullptr);
      releaseResources();
      return false;
    }
    setSecurityOutcome(SecurityOutcome::Error, SecurityReason::RuntimeError, path,
                       static_cast<uint32_t>(settings_.status_on_error));
    sendRuntimeError(path, "modsecurity_runtime_error");
    return false;
  }
  return !check_intervention || checkIntervention(path);
}

bool Filter::checkIntervention(Path path) {
  if (stage_timing_enabled_) {
    stats_->stage_profile_intervention_lookups_.inc();
  }
  auto intervention =
      timedCall(stage_timing_enabled_, stats_->stage_profile_intervention_lookup_ns_, time_source_,
                [&] { return transaction_->intervention(); });
  if (!intervention.ok()) {
    return evaluate(intervention.status(), path, false);
  }
  if (!intervention->has_value()) {
    return true;
  }
  sendIntervention(std::move(**intervention), path);
  return false;
}

void Filter::sendIntervention(Engine::Intervention intervention, Path path) {
  ScopedCounterTimer response_timer(stage_timing_enabled_,
                                    stats_->stage_profile_intervention_response_ns_, time_source_);
  int status = intervention.status;
  if (!intervention.redirect_url.empty() && (status < 300 || status >= 400)) {
    status = 302;
  } else if (status < 300 || status > 599) {
    status = 403;
  }

  local_reply_ = true;
  const auto code = static_cast<Http::Code>(status);
  setSecurityOutcome(SecurityOutcome::Blocked, SecurityReason::RuleIntervention, path,
                     static_cast<uint32_t>(status));
  std::function<void(Http::ResponseHeaderMap&)> modify_headers;
  if (!intervention.redirect_url.empty()) {
    modify_headers = [redirect_url = std::move(intervention.redirect_url)](
                         Http::ResponseHeaderMap& headers) {
      headers.setLocation(redirect_url);
    };
  }

  // A local reply can complete the stream and run access loggers synchronously, so publish the
  // phase-5 result before handing the reply to Envoy.
  finishLogging();

  if (path == Path::Request) {
    stats_->request_interventions_.inc();
    timedCall(stage_timing_enabled_, stats_->stage_profile_local_reply_ns_, time_source_, [&] {
      decoder_callbacks_->sendLocalReply(code, *settings_.request_intervention_body, modify_headers,
                                         std::nullopt, "modsecurity_request_intervention");
      return true;
    });
  } else {
    stats_->response_interventions_.inc();
    timedCall(stage_timing_enabled_, stats_->stage_profile_local_reply_ns_, time_source_, [&] {
      encoder_callbacks_->sendLocalReply(code, *settings_.response_intervention_body,
                                         modify_headers, std::nullopt,
                                         "modsecurity_response_intervention");
      return true;
    });
  }
  releaseResources();
}

void Filter::sendRuntimeError(Path path, absl::string_view details) {
  local_reply_ = true;
  publishSecurityEvent(nullptr);
  if (path == Path::Response && encoder_callbacks_ != nullptr) {
    encoder_callbacks_->sendLocalReply(settings_.status_on_error, "ModSecurity inspection error",
                                       nullptr, std::nullopt, details);
  } else {
    decoder_callbacks_->sendLocalReply(settings_.status_on_error, "ModSecurity inspection error",
                                       nullptr, std::nullopt, details);
  }
  releaseResources();
}

bool Filter::addRequestHeaders(const Http::RequestHeaderMap& headers,
                               absl::string_view request_host) {
  ScopedCounterTimer timer(stage_timing_enabled_, stats_->stage_profile_add_request_headers_ns_,
                           time_source_);
  bool host_added = false;
  bool succeeded = true;
  headers.iterate([&](const Http::HeaderEntry& header) {
    const absl::string_view name = header.key().getStringView();
    if (isPseudoHeader(name)) {
      return Http::HeaderMap::Iterate::Continue;
    }
    host_added = host_added || absl::EqualsIgnoreCase(name, "host");
    const absl::Status status =
        transaction_->addRequestHeader(name, header.value().getStringView());
    if (!status.ok()) {
      evaluate(status, Path::Request, false);
      succeeded = false;
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  });

  if (!succeeded || host_added || request_host.empty()) {
    return succeeded;
  }
  return evaluate(transaction_->addRequestHeader("host", request_host), Path::Request, false);
}

bool Filter::addResponseHeaders(const Http::ResponseHeaderMap& headers) {
  bool succeeded = true;
  headers.iterate([&](const Http::HeaderEntry& header) {
    const absl::string_view name = header.key().getStringView();
    if (isPseudoHeader(name)) {
      return Http::HeaderMap::Iterate::Continue;
    }
    const absl::Status status =
        transaction_->addResponseHeader(name, header.value().getStringView());
    if (!status.ok()) {
      evaluate(status, Path::Response, false);
      succeeded = false;
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  });
  return succeeded;
}

bool Filter::inspectionEnabled(Path path) const {
  if (disabled_ || engine_bypassed_ || local_reply_ || transaction_ == nullptr) {
    return false;
  }
  if (path == Path::Request) {
    return !request_body_.finished;
  }
  return settings_.response_body_max_bytes.has_value() && response_headers_finished_ &&
         !response_body_.finished;
}

Http::FilterHeadersStatus Filter::stoppedOrContinue() const {
  return local_reply_ ? Http::FilterHeadersStatus::StopIteration
                      : Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
  ScopedCounterTimer stage_timer(stage_timing_enabled_, stats_->stage_profile_decode_headers_ns_,
                                 time_source_);
  if (stage_timing_enabled_) {
    stats_->stage_profile_samples_.inc();
  }
  initializeSettings();
  if (disabled_) {
    return Http::FilterHeadersStatus::Continue;
  }

  if (!createTransaction()) {
    return stoppedOrContinue();
  }

  ScopedHistogramTimer timer(stats_->request_headers_duration_us_, time_source_);
  const auto& addresses = decoder_callbacks_->streamInfo().downstreamAddressProvider();
  const IpEndpoint client = endpoint(addresses.remoteAddress());
  const IpEndpoint server = endpoint(addresses.localAddress());
  if (!evaluate(timedCall(stage_timing_enabled_, stats_->stage_profile_process_connection_ns_,
                          time_source_,
                          [&] {
                            return transaction_->processConnection(client.address, client.port,
                                                                   server.address, server.port);
                          }),
                Path::Request)) {
    return stoppedOrContinue();
  }
  const absl::string_view request_target = Http::HeaderUtility::isStandardConnectRequest(headers)
                                               ? headers.getHostValue()
                                               : headers.getPathValue();
  // processURI only initializes transaction variables. The preceding connection-phase
  // intervention has already been consumed, so there cannot be a new intervention here.
  if (!evaluate(
          timedCall(stage_timing_enabled_, stats_->stage_profile_process_uri_ns_, time_source_,
                    [&] {
                      return transaction_->processUri(request_target, headers.getMethodValue(),
                                                      modSecurityRequestVersion());
                    }),
          Path::Request, false) ||
      !addRequestHeaders(headers, headers.getHostValue())) {
    return stoppedOrContinue();
  }
  if (!evaluate(timedCall(stage_timing_enabled_, stats_->stage_profile_process_request_headers_ns_,
                          time_source_, [&] { return transaction_->processRequestHeaders(); }),
                Path::Request)) {
    return stoppedOrContinue();
  }
  timer.complete();

  classifyRequest(headers);
  if (stream_kind_ != StreamKind::Regular) {
    bypassBodyForStreaming(Path::Request);
    return Http::FilterHeadersStatus::Continue;
  }
  if (end_stream) {
    return finishBody(Path::Request) ? Http::FilterHeadersStatus::Continue : stoppedOrContinue();
  }
  if (declaredBodyExceedsLimit(headers, Path::Request)) {
    sendBodyOverflow(Path::Request);
    return Http::FilterHeadersStatus::StopIteration;
  }

  ensureBufferLimit(Path::Request);
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

Filter::BodyState& Filter::bodyState(Path path) {
  return path == Path::Request ? request_body_ : response_body_;
}

uint64_t Filter::bodyLimit(Path path) const {
  return path == Path::Request ? settings_.request_body_max_bytes
                               : *settings_.response_body_max_bytes;
}

Stats::Histogram& Filter::bodyDurationHistogram(Path path) const {
  return path == Path::Request ? stats_->request_body_duration_us_
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
  absl::string_view content_type = headers.getContentTypeValue();
  const size_t parameter = content_type.find(';');
  content_type = absl::StripAsciiWhitespace(content_type.substr(0, parameter));
  return absl::EqualsIgnoreCase(content_type, "text/event-stream");
}

bool Filter::declaredBodyExceedsLimit(const Http::RequestOrResponseHeaderMap& headers,
                                      Path path) const {
  const absl::string_view value = headers.getContentLengthValue();
  uint64_t content_length = 0;
  return !value.empty() && absl::SimpleAtoi(value, &content_length) &&
         content_length > bodyLimit(path);
}

void Filter::ensureBufferLimit(Path path) {
  const uint64_t limit = bodyLimit(path);
  if (path == Path::Request) {
    if (limit > decoder_callbacks_->bufferLimit()) {
      decoder_callbacks_->setBufferLimit(limit);
    }
  } else if (limit > encoder_callbacks_->bufferLimit()) {
    encoder_callbacks_->setBufferLimit(limit);
  }
}

void Filter::sendBodyOverflow(Path path) {
  local_reply_ = true;
  if (path == Path::Request) {
    stats_->request_body_overflow_.inc();
    setSecurityOutcome(SecurityOutcome::Blocked, SecurityReason::BodyOverflow, path,
                       static_cast<uint32_t>(Http::Code::PayloadTooLarge));
    publishSecurityEvent(nullptr);
    decoder_callbacks_->sendLocalReply(Http::Code::PayloadTooLarge,
                                       "request body exceeds ModSecurity inspection limit", nullptr,
                                       std::nullopt, "modsecurity_request_body_overflow");
    releaseResources();
    return;
  }

  stats_->response_body_overflow_.inc();
  setSecurityOutcome(SecurityOutcome::Error, SecurityReason::BodyOverflow, path,
                     static_cast<uint32_t>(settings_.status_on_error));
  sendRuntimeError(Path::Response, "modsecurity_response_body_overflow");
}

void Filter::sendBodyMemoryBudgetExceeded(Path path) {
  stats_->body_memory_budget_exceeded_.inc();
  setSecurityOutcome(SecurityOutcome::Error, SecurityReason::BodyMemoryBudgetExceeded, path,
                     static_cast<uint32_t>(settings_.status_on_error));
  sendRuntimeError(path, "modsecurity_body_memory_budget_exceeded");
}

bool Filter::appendBody(Buffer::Instance& data, Path path) {
  const uint64_t length = data.length();
  BodyState& state = bodyState(path);
  const uint64_t limit = bodyLimit(path);

  if (state.bytes > limit || length > limit - state.bytes) {
    sendBodyOverflow(path);
    return false;
  }
  if (!reserveBodyBytes(length)) {
    sendBodyMemoryBudgetExceeded(path);
    return false;
  }
  state.bytes += length;

  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
    if (slice.len_ == 0) {
      continue;
    }
    const absl::string_view bytes(static_cast<const char*>(slice.mem_), slice.len_);
    const absl::Status status = path == Path::Request ? transaction_->appendRequestBody(bytes)
                                                      : transaction_->appendResponseBody(bytes);
    if (!status.ok()) {
      return evaluate(status, path, false);
    }
    if (!checkIntervention(path)) {
      return false;
    }
  }
  return true;
}

bool Filter::finishBody(Path path) {
  BodyState& state = bodyState(path);
  if (state.finished) {
    return true;
  }
  state.finished = true;
  ScopedHistogramTimer timer(bodyDurationHistogram(path), time_source_);
  const absl::Status status = path == Path::Request ? transaction_->processRequestBody()
                                                    : transaction_->processResponseBody();
  const bool succeeded = evaluate(status, path);
  if (succeeded && (path == Path::Response || !settings_.response_body_max_bytes.has_value())) {
    finishLogging();
    releaseResources();
  }
  return succeeded;
}

void Filter::bypassBodyForStreaming(Path path) {
  BodyState& state = bodyState(path);
  if (state.finished) {
    return;
  }
  state.finished = true;
  if (path == Path::Request) {
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

Http::FilterDataStatus Filter::processData(Buffer::Instance& data, bool end_stream, Path path) {
  if (!inspectionEnabled(path)) {
    return Http::FilterDataStatus::Continue;
  }
  if (!appendBody(data, path)) {
    return local_reply_ ? Http::FilterDataStatus::StopIterationNoBuffer
                        : Http::FilterDataStatus::Continue;
  }
  if (end_stream) {
    if (!finishBody(path) && local_reply_) {
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
    return Http::FilterDataStatus::Continue;
  }
  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus Filter::processTrailers(Path path) {
  if (!inspectionEnabled(path)) {
    return Http::FilterTrailersStatus::Continue;
  }
  if (!finishBody(path) && local_reply_) {
    return Http::FilterTrailersStatus::StopIteration;
  }
  return Http::FilterTrailersStatus::Continue;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& data, bool end_stream) {
  return processData(data, end_stream, Path::Request);
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {
  stats_->request_trailers_uninspected_.inc();
  return processTrailers(Path::Request);
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool end_stream) {
  if (disabled_ || engine_bypassed_ || local_reply_ || transaction_ == nullptr ||
      !settings_.response_body_max_bytes.has_value()) {
    return Http::FilterHeadersStatus::Continue;
  }

  ScopedHistogramTimer timer(stats_->response_headers_duration_us_, time_source_);
  if (!addResponseHeaders(headers)) {
    return stoppedOrContinue();
  }
  const uint64_t response_status = Http::Utility::getResponseStatus(headers);
  if (!evaluate(transaction_->processResponseHeaders(response_status, httpVersion()),
                Path::Response)) {
    return stoppedOrContinue();
  }
  response_headers_finished_ = true;
  timer.complete();

  if (end_stream) {
    return finishBody(Path::Response) ? Http::FilterHeadersStatus::Continue : stoppedOrContinue();
  }
  if (shouldBypassResponseBody(headers)) {
    bypassBodyForStreaming(Path::Response);
    return Http::FilterHeadersStatus::Continue;
  }
  if (declaredBodyExceedsLimit(headers, Path::Response)) {
    sendBodyOverflow(Path::Response);
    return Http::FilterHeadersStatus::StopIteration;
  }

  ensureBufferLimit(Path::Response);
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus Filter::encodeData(Buffer::Instance& data, bool end_stream) {
  return processData(data, end_stream, Path::Response);
}

Http::FilterTrailersStatus Filter::encodeTrailers(Http::ResponseTrailerMap&) {
  stats_->response_trailers_uninspected_.inc();
  return processTrailers(Path::Response);
}

void Filter::finishLogging() {
  if (logging_finished_ || transaction_ == nullptr) {
    return;
  }
  logging_finished_ = true;
  ScopedCounterTimer stage_timer(stage_timing_enabled_, stats_->stage_profile_logging_ns_,
                                 time_source_);
  ScopedHistogramTimer timer(stats_->logging_duration_us_, time_source_);
  auto result = timedCall(stage_timing_enabled_, stats_->stage_profile_process_logging_ns_,
                          time_source_, [&] { return transaction_->processLogging(); });
  if (!result.ok()) {
    stats_->logging_errors_.inc();
    publishSecurityEvent(nullptr, true);
    return;
  }
  recordCrsThresholdStats(*result);
  publishSecurityEvent(&*result);
}

void Filter::recordCrsThresholdStats(const Engine::LoggingResult& result) {
  const bool detection_only = rule_engine_mode_ == Engine::RuleEngineMode::DetectionOnly;
  if (thresholdExceeded(result.blocking_inbound_anomaly_score,
                        result.inbound_anomaly_score_threshold)) {
    stats_->crs_inbound_anomaly_score_threshold_exceeded_.inc();
    if (detection_only) {
      stats_->detection_only_crs_inbound_anomaly_score_threshold_exceeded_.inc();
    }
  }
  if (thresholdExceeded(result.blocking_outbound_anomaly_score,
                        result.outbound_anomaly_score_threshold)) {
    stats_->crs_outbound_anomaly_score_threshold_exceeded_.inc();
    if (detection_only) {
      stats_->detection_only_crs_outbound_anomaly_score_threshold_exceeded_.inc();
    }
  }
}

void Filter::setSecurityOutcome(SecurityOutcome outcome, SecurityReason reason, Path path,
                                std::optional<uint32_t> status) {
  security_outcome_ = outcome;
  security_reason_ = reason;
  security_phase_ = path;
  security_status_ = status;
}

const char* Filter::securityOutcomeName(SecurityOutcome outcome) {
  switch (outcome) {
    case SecurityOutcome::Allowed:
      return "allowed";
    case SecurityOutcome::Bypassed:
      return "bypassed";
    case SecurityOutcome::Error:
      return "error";
    case SecurityOutcome::Blocked:
      return "blocked";
    case SecurityOutcome::Incomplete:
      return "incomplete";
  }
  return "error";
}

const char* Filter::securityReasonName(SecurityReason reason) {
  switch (reason) {
    case SecurityReason::None:
      return "";
    case SecurityReason::RuntimeError:
      return "runtime_error";
    case SecurityReason::RuleIntervention:
      return "rule_intervention";
    case SecurityReason::BodyOverflow:
      return "body_overflow";
    case SecurityReason::BodyMemoryBudgetExceeded:
      return "body_memory_budget_exceeded";
    case SecurityReason::StreamDestroyed:
      return "stream_destroyed";
  }
  return "runtime_error";
}

void Filter::publishSecurityEvent(const Engine::LoggingResult* result, bool logging_error) {
  ScopedCounterTimer stage_timer(stage_timing_enabled_, stats_->stage_profile_security_event_ns_,
                                 time_source_);
  if (security_event_published_ || decoder_callbacks_ == nullptr) {
    return;
  }

  const bool has_rule_events = result != nullptr && !result->rules.empty();
  const bool has_anomaly_signal =
      result != nullptr && (nonZero(result->blocking_inbound_anomaly_score) ||
                            nonZero(result->detection_inbound_anomaly_score) ||
                            nonZero(result->blocking_outbound_anomaly_score) ||
                            nonZero(result->detection_outbound_anomaly_score));
  if (security_outcome_ == SecurityOutcome::Allowed && !has_rule_events && !has_anomaly_signal &&
      !logging_error) {
    return;
  }

  security_event_published_ = true;
  Protobuf::Struct& metadata =
      (*decoder_callbacks_->streamInfo().dynamicMetadata().mutable_filter_metadata())
          [securityMetadataNamespace()];
  auto& fields = *metadata.mutable_fields();
  fields["schema_version"].set_number_value(1);
  fields["outcome"].set_string_value(securityOutcomeName(security_outcome_));
  fields["reason"].set_string_value(
      security_reason_ == SecurityReason::None
          ? (logging_error ? "logging_error" : "rule_match")
          : securityReasonName(security_reason_));
  fields["phase"].set_string_value(
      !security_phase_.has_value()
          ? "complete"
          : (*security_phase_ == Path::Request ? "request" : "response"));
  fields["rule_generation"].set_string_value(std::to_string(rule_generation_id_));
  fields["rule_engine_mode"].set_string_value(
      std::string(Engine::ruleEngineModeName(rule_engine_mode_)));
  if (security_status_.has_value()) {
    fields["http_status"].set_number_value(static_cast<double>(*security_status_));
  }
  if (logging_error) {
    fields["logging_error"].set_bool_value(true);
  }

  if (result != nullptr) {
    Protobuf::Value rules;
    for (const Engine::RuleEvent& event : result->rules) {
      Protobuf::Struct* rule = rules.mutable_list_value()->add_values()->mutable_struct_value();
      auto& rule_fields = *rule->mutable_fields();
      rule_fields["id"].set_string_value(std::to_string(event.id));
      rule_fields["phase"].set_number_value(event.phase);
      rule_fields["disruptive"].set_bool_value(event.disruptive);
    }
    if (!result->rules.empty()) {
      fields["rules"] = std::move(rules);
    }
    fields["rules_truncated"].set_bool_value(result->rules_truncated);
    setOptionalNumber(metadata, "blocking_inbound_anomaly_score",
                      result->blocking_inbound_anomaly_score);
    setOptionalNumber(metadata, "detection_inbound_anomaly_score",
                      result->detection_inbound_anomaly_score);
    setOptionalNumber(metadata, "inbound_anomaly_score_threshold",
                      result->inbound_anomaly_score_threshold);
    setOptionalNumber(metadata, "blocking_outbound_anomaly_score",
                      result->blocking_outbound_anomaly_score);
    setOptionalNumber(metadata, "detection_outbound_anomaly_score",
                      result->detection_outbound_anomaly_score);
    setOptionalNumber(metadata, "outbound_anomaly_score_threshold",
                      result->outbound_anomaly_score_threshold);
    if (result->rules_truncated) {
      stats_->security_event_rule_truncations_.inc();
    }
  }

  stats_->security_events_.inc();
}

void Filter::onStreamComplete() { finishLogging(); }

void Filter::releaseResources() {
  if (resources_released_) {
    return;
  }
  resources_released_ = true;
  ScopedCounterTimer stage_timer(stage_timing_enabled_, stats_->stage_profile_release_resources_ns_,
                                 time_source_);
  if (transaction_ != nullptr) {
    transaction_.reset();
    stats_->active_transactions_.dec();
  }
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
  if (transaction_ != nullptr && !logging_finished_ &&
      security_outcome_ == SecurityOutcome::Allowed) {
    setSecurityOutcome(SecurityOutcome::Incomplete, SecurityReason::StreamDestroyed,
                       response_headers_finished_ ? Path::Response : Path::Request);
  }
  finishLogging();
  releaseResources();
}

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
