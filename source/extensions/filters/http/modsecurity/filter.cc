#include "source/extensions/filters/http/modsecurity/filter.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "envoy/network/address.h"

#include "source/common/http/utility.h"

#include "absl/status/status.h"
#include "absl/strings/match.h"

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

uint64_t elapsedMicros(MonotonicTime start, TimeSource& time_source) {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                   time_source.monotonicTime() - start)
                                   .count());
}

} // namespace

Filter::Filter(FilterConfigSharedPtr config)
    : config_(std::move(config)), settings_(config_->settings()) {}

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
  settings_ = config_->settings();

  const auto* route_config =
      Http::Utility::resolveMostSpecificPerFilterConfig<RouteConfig>(decoder_callbacks_);
  if (route_config != nullptr) {
    disabled_ = route_config->disabled();
    settings_ = route_config->apply(settings_);
  }
}

bool Filter::createTransaction() {
  auto transaction = config_->generation()->createTransaction();
  if (!transaction.ok()) {
    return handleEngineResult(transaction.status(), Path::Request, false);
  }
  transaction_ = std::move(*transaction);
  transaction_counted_ = true;
  config_->stats().active_transactions_.inc();
  memory_account_ = decoder_callbacks_->account();
  return true;
}

std::string Filter::httpVersion() const {
  const auto protocol = decoder_callbacks_->streamInfo().protocol();
  return protocol.has_value() ? Http::Utility::getProtocolString(*protocol) : "HTTP/1.1";
}

bool Filter::handleEngineResult(const absl::Status& status, Path path,
                                bool check_intervention) {
  if (!status.ok()) {
    config_->stats().runtime_errors_.inc();
    if (settings_.failure_mode_allow) {
      config_->stats().failure_mode_allowed_.inc();
      engine_bypassed_ = true;
      return true;
    }
    sendRuntimeError(path, "modsecurity_runtime_error");
    return false;
  }
  return !check_intervention || checkIntervention(path);
}

bool Filter::checkIntervention(Path path) {
  auto intervention = transaction_->intervention();
  if (!intervention.ok()) {
    return handleEngineResult(intervention.status(), path, false);
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
    config_->stats().request_interventions_.inc();
    decoder_callbacks_->sendLocalReply(code, "request blocked by ModSecurity", modify_headers,
                                       std::nullopt, "modsecurity_request_intervention");
  } else {
    config_->stats().response_interventions_.inc();
    encoder_callbacks_->sendLocalReply(code, "response blocked by ModSecurity", modify_headers,
                                       std::nullopt, "modsecurity_response_intervention");
  }
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
}

bool Filter::addRequestHeaders(const Http::RequestHeaderMap& headers) {
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
      succeeded = handleEngineResult(status, Path::Request, false);
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  });

  if (!succeeded || engine_bypassed_ || host_added || headers.getHostValue().empty()) {
    return succeeded;
  }
  return handleEngineResult(transaction_->addRequestHeader("host", headers.getHostValue()),
                            Path::Request, false);
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
      succeeded = handleEngineResult(status, Path::Response, false);
      return Http::HeaderMap::Iterate::Break;
    }
    return Http::HeaderMap::Iterate::Continue;
  });
  return succeeded;
}

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
  initializeSettings();
  if (disabled_) {
    return Http::FilterHeadersStatus::Continue;
  }

  if (!createTransaction() || local_reply_) {
    return Http::FilterHeadersStatus::StopIteration;
  }
  if (engine_bypassed_) {
    return Http::FilterHeadersStatus::Continue;
  }

  const MonotonicTime start = config_->timeSource().monotonicTime();
  const auto& addresses = decoder_callbacks_->streamInfo().downstreamAddressProvider();
  const IpEndpoint client = endpoint(addresses.remoteAddress());
  const IpEndpoint server = endpoint(addresses.localAddress());
  if (!handleEngineResult(transaction_->processConnection(client.address, client.port,
                                                           server.address, server.port),
                          Path::Request, true) ||
      engine_bypassed_) {
    config_->stats().request_headers_duration_us_.recordValue(
        elapsedMicros(start, config_->timeSource()));
    return local_reply_ ? Http::FilterHeadersStatus::StopIteration
                        : Http::FilterHeadersStatus::Continue;
  }
  if (!handleEngineResult(
          transaction_->processUri(headers.getPathValue(), headers.getMethodValue(), httpVersion()),
          Path::Request, true) ||
      engine_bypassed_ || !addRequestHeaders(headers) || engine_bypassed_) {
    config_->stats().request_headers_duration_us_.recordValue(
        elapsedMicros(start, config_->timeSource()));
    return local_reply_ ? Http::FilterHeadersStatus::StopIteration
                        : Http::FilterHeadersStatus::Continue;
  }
  if (!handleEngineResult(transaction_->processRequestHeaders(), Path::Request, true)) {
    config_->stats().request_headers_duration_us_.recordValue(
        elapsedMicros(start, config_->timeSource()));
    return Http::FilterHeadersStatus::StopIteration;
  }
  config_->stats().request_headers_duration_us_.recordValue(
      elapsedMicros(start, config_->timeSource()));

  if (engine_bypassed_) {
    return Http::FilterHeadersStatus::Continue;
  }
  if (end_stream) {
    return finishRequestBody() ? Http::FilterHeadersStatus::Continue
                               : Http::FilterHeadersStatus::StopIteration;
  }

  if (settings_.request_body_max_bytes > decoder_callbacks_->bufferLimit()) {
    decoder_callbacks_->setBufferLimit(settings_.request_body_max_bytes);
  }
  // StopIteration keeps request headers from the next filter while still allowing this filter to
  // receive data callbacks. Intermediate data is held with StopIterationAndBuffer below.
  return Http::FilterHeadersStatus::StopIteration;
}

void Filter::chargeBodyBytes(uint64_t bytes) {
  if (bytes == 0) {
    return;
  }
  if (memory_account_ != nullptr) {
    memory_account_->charge(bytes);
  }
  charged_body_bytes_ += bytes;
  config_->stats().modsecurity_buffer_bytes_.add(bytes);
}

bool Filter::appendBody(Buffer::Instance& data, Path path) {
  const uint64_t length = data.length();
  uint64_t& current_bytes =
      path == Path::Request ? request_body_bytes_ : response_body_bytes_;
  const uint64_t max_bytes = path == Path::Request
                                 ? settings_.request_body_max_bytes
                                 : settings_.response_body_max_bytes.value();

  if (current_bytes > max_bytes || length > max_bytes - current_bytes) {
    local_reply_ = true;
    if (path == Path::Request) {
      config_->stats().request_body_overflow_.inc();
      decoder_callbacks_->sendLocalReply(Http::Code::PayloadTooLarge,
                                         "request body exceeds ModSecurity inspection limit",
                                         nullptr, std::nullopt,
                                         "modsecurity_request_body_overflow");
    } else {
      config_->stats().response_body_overflow_.inc();
      sendRuntimeError(Path::Response, "modsecurity_response_body_overflow");
    }
    return false;
  }
  current_bytes += length;

  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
    if (slice.len_ == 0) {
      continue;
    }
    const absl::string_view bytes(static_cast<const char*>(slice.mem_), slice.len_);
    const absl::Status status = path == Path::Request
                                    ? transaction_->appendRequestBody(bytes)
                                    : transaction_->appendResponseBody(bytes);
    if (!status.ok()) {
      return handleEngineResult(status, path, false);
    }
    chargeBodyBytes(slice.len_);
    if (!checkIntervention(path)) {
      return false;
    }
  }
  return true;
}

bool Filter::finishRequestBody() {
  if (request_body_finished_ || engine_bypassed_) {
    return true;
  }
  request_body_finished_ = true;
  const MonotonicTime start = config_->timeSource().monotonicTime();
  const bool result =
      handleEngineResult(transaction_->processRequestBody(), Path::Request, true);
  config_->stats().request_body_duration_us_.recordValue(
      elapsedMicros(start, config_->timeSource()));
  return result;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& data, bool end_stream) {
  if (disabled_ || engine_bypassed_) {
    return Http::FilterDataStatus::Continue;
  }
  if (!appendBody(data, Path::Request)) {
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }
  if (engine_bypassed_) {
    return Http::FilterDataStatus::Continue;
  }
  if (end_stream) {
    return finishRequestBody() ? Http::FilterDataStatus::Continue
                               : Http::FilterDataStatus::StopIterationNoBuffer;
  }
  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {
  if (disabled_ || engine_bypassed_) {
    return Http::FilterTrailersStatus::Continue;
  }
  return finishRequestBody() ? Http::FilterTrailersStatus::Continue
                             : Http::FilterTrailersStatus::StopIteration;
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                bool end_stream) {
  if (disabled_ || engine_bypassed_ || local_reply_ ||
      !settings_.response_body_max_bytes.has_value()) {
    return Http::FilterHeadersStatus::Continue;
  }

  const MonotonicTime start = config_->timeSource().monotonicTime();
  if (!addResponseHeaders(headers) || engine_bypassed_) {
    config_->stats().response_headers_duration_us_.recordValue(
        elapsedMicros(start, config_->timeSource()));
    return local_reply_ ? Http::FilterHeadersStatus::StopIteration
                        : Http::FilterHeadersStatus::Continue;
  }
  const uint64_t response_status = Http::Utility::getResponseStatus(headers);
  if (!handleEngineResult(
          transaction_->processResponseHeaders(response_status, httpVersion()), Path::Response,
          true)) {
    config_->stats().response_headers_duration_us_.recordValue(
        elapsedMicros(start, config_->timeSource()));
    return Http::FilterHeadersStatus::StopIteration;
  }
  response_headers_finished_ = true;
  config_->stats().response_headers_duration_us_.recordValue(
      elapsedMicros(start, config_->timeSource()));

  if (engine_bypassed_) {
    return Http::FilterHeadersStatus::Continue;
  }
  if (end_stream) {
    return finishResponseBody() ? Http::FilterHeadersStatus::Continue
                                : Http::FilterHeadersStatus::StopIteration;
  }

  if (*settings_.response_body_max_bytes > encoder_callbacks_->bufferLimit()) {
    encoder_callbacks_->setBufferLimit(*settings_.response_body_max_bytes);
  }
  return Http::FilterHeadersStatus::StopIteration;
}

bool Filter::finishResponseBody() {
  if (response_body_finished_ || engine_bypassed_ || !response_headers_finished_) {
    return true;
  }
  response_body_finished_ = true;
  const MonotonicTime start = config_->timeSource().monotonicTime();
  const bool result =
      handleEngineResult(transaction_->processResponseBody(), Path::Response, true);
  config_->stats().response_body_duration_us_.recordValue(
      elapsedMicros(start, config_->timeSource()));
  return result;
}

Http::FilterDataStatus Filter::encodeData(Buffer::Instance& data, bool end_stream) {
  if (disabled_ || engine_bypassed_ || local_reply_ ||
      !settings_.response_body_max_bytes.has_value()) {
    return Http::FilterDataStatus::Continue;
  }
  if (!appendBody(data, Path::Response)) {
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }
  if (engine_bypassed_) {
    return Http::FilterDataStatus::Continue;
  }
  if (end_stream) {
    return finishResponseBody() ? Http::FilterDataStatus::Continue
                                : Http::FilterDataStatus::StopIterationNoBuffer;
  }
  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus Filter::encodeTrailers(Http::ResponseTrailerMap&) {
  if (disabled_ || engine_bypassed_ || local_reply_ ||
      !settings_.response_body_max_bytes.has_value()) {
    return Http::FilterTrailersStatus::Continue;
  }
  return finishResponseBody() ? Http::FilterTrailersStatus::Continue
                              : Http::FilterTrailersStatus::StopIteration;
}

void Filter::finishLogging() {
  if (logging_finished_ || transaction_ == nullptr) {
    return;
  }
  logging_finished_ = true;
  const MonotonicTime start = config_->timeSource().monotonicTime();
  if (!transaction_->processLogging().ok()) {
    config_->stats().logging_errors_.inc();
  }
  config_->stats().logging_duration_us_.recordValue(
      elapsedMicros(start, config_->timeSource()));
}

void Filter::onStreamComplete() { finishLogging(); }

void Filter::releaseResources() {
  if (resources_released_) {
    return;
  }
  resources_released_ = true;
  transaction_.reset();
  if (transaction_counted_) {
    config_->stats().active_transactions_.dec();
    transaction_counted_ = false;
  }
  if (charged_body_bytes_ != 0) {
    if (memory_account_ != nullptr) {
      memory_account_->credit(charged_body_bytes_);
    }
    config_->stats().modsecurity_buffer_bytes_.sub(charged_body_bytes_);
    charged_body_bytes_ = 0;
  }
  memory_account_.reset();
}

void Filter::onDestroy() {
  finishLogging();
  releaseResources();
}

} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
