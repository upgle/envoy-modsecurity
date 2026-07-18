#include "source/extensions/filters/http/modsecurity/filter.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
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

bool Filter::createTransaction() {
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

std::string Filter::httpVersion() const {
  const auto protocol = decoder_callbacks_->streamInfo().protocol();
  return protocol.has_value() ? Http::Utility::getProtocolString(*protocol) : "HTTP/1.1";
}

bool Filter::evaluate(const absl::Status& status, Path path, bool check_intervention) {
  if (!status.ok()) {
    stats_->runtime_errors_.inc();
    if (settings_.failure_mode_allow && status.code() != absl::StatusCode::kResourceExhausted) {
      stats_->failure_mode_allowed_.inc();
      engine_bypassed_ = true;
      releaseResources();
      return false;
    }
    sendRuntimeError(path, "modsecurity_runtime_error");
    return false;
  }
  return !check_intervention || checkIntervention(path);
}

bool Filter::checkIntervention(Path path) {
  auto intervention = transaction_->intervention();
  if (!intervention.ok()) {
    return evaluate(intervention.status(), path, false);
  }
  if (!intervention->has_value()) {
    return true;
  }
  sendIntervention(**intervention, path);
  return false;
}

void Filter::sendIntervention(const Engine::Intervention& intervention, Path path) {
  int status = intervention.status;
  if (!intervention.redirect_url.empty() && (status < 300 || status >= 400)) {
    status = 302;
  } else if (status < 300 || status > 599) {
    status = 403;
  }

  local_reply_ = true;
  const auto code = static_cast<Http::Code>(status);
  const std::string redirect_url = intervention.redirect_url;
  auto modify_headers = [redirect_url](Http::ResponseHeaderMap& headers) {
    if (!redirect_url.empty()) {
      headers.setLocation(redirect_url);
    }
  };

  if (path == Path::Request) {
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

void Filter::sendRuntimeError(Path path, absl::string_view details) {
  local_reply_ = true;
  if (path == Path::Response && encoder_callbacks_ != nullptr) {
    encoder_callbacks_->sendLocalReply(settings_.status_on_error, "ModSecurity inspection error",
                                       nullptr, std::nullopt, details);
  } else {
    decoder_callbacks_->sendLocalReply(settings_.status_on_error, "ModSecurity inspection error",
                                       nullptr, std::nullopt, details);
  }
  releaseResources();
}

bool Filter::addHeaders(const Http::HeaderMap& headers, Path path, absl::string_view request_host) {
  bool host_added = false;
  bool succeeded = true;
  headers.iterate([&](const Http::HeaderEntry& header) {
    const absl::string_view name = header.key().getStringView();
    if (isPseudoHeader(name)) {
      return Http::HeaderMap::Iterate::Continue;
    }
    host_added = host_added || (path == Path::Request && absl::EqualsIgnoreCase(name, "host"));
    const absl::Status status =
        path == Path::Request
            ? transaction_->addRequestHeader(name, header.value().getStringView())
            : transaction_->addResponseHeader(name, header.value().getStringView());
    if (!status.ok()) {
      evaluate(status, path, false);
      succeeded = false;
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  });

  if (!succeeded || path == Path::Response || host_added || request_host.empty()) {
    return succeeded;
  }
  return evaluate(transaction_->addRequestHeader("host", request_host), Path::Request, false);
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
  if (!evaluate(
          transaction_->processConnection(client.address, client.port, server.address, server.port),
          Path::Request)) {
    return stoppedOrContinue();
  }
  if (!evaluate(
          transaction_->processUri(headers.getPathValue(), headers.getMethodValue(), httpVersion()),
          Path::Request) ||
      !addHeaders(headers, Path::Request, headers.getHostValue())) {
    return stoppedOrContinue();
  }
  if (!evaluate(transaction_->processRequestHeaders(), Path::Request)) {
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
      ((connect_tunnel_ && status >= 200 && status < 300) ||
       (!connect_tunnel_ && status == 101))) {
    return true;
  }
  return absl::StartsWithIgnoreCase(headers.getContentTypeValue(), "text/event-stream");
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
    decoder_callbacks_->sendLocalReply(Http::Code::PayloadTooLarge,
                                       "request body exceeds ModSecurity inspection limit", nullptr,
                                       std::nullopt, "modsecurity_request_body_overflow");
    releaseResources();
    return;
  }

  stats_->response_body_overflow_.inc();
  sendRuntimeError(Path::Response, "modsecurity_response_body_overflow");
}

void Filter::sendBodyMemoryBudgetExceeded(Path path) {
  stats_->body_memory_budget_exceeded_.inc();
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
  if (disabled_ || engine_bypassed_ || local_reply_ ||
      transaction_ == nullptr || !settings_.response_body_max_bytes.has_value()) {
    return Http::FilterHeadersStatus::Continue;
  }

  ScopedHistogramTimer timer(stats_->response_headers_duration_us_, time_source_);
  if (!addHeaders(headers, Path::Response)) {
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
  ScopedHistogramTimer timer(stats_->logging_duration_us_, time_source_);
  if (!transaction_->processLogging().ok()) {
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
