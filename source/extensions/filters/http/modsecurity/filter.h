#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "absl/strings/string_view.h"
#include "envoy/buffer/buffer.h"
#include "envoy/http/filter.h"
#include "source/extensions/filters/http/modsecurity/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

class Filter final : public Http::StreamFilter {
 public:
  explicit Filter(FilterConfigSharedPtr config);

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override;

  Http::Filter1xxHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap&) override {
    return Http::Filter1xxHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override;
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }

  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override;
  void onStreamComplete() override;
  void onDestroy() override;

 private:
  enum class Path { Request, Response };
  enum class StreamKind { Regular, Grpc, ConnectStreaming, Tunnel };
  struct BodyState {
    uint64_t bytes{0};
    bool finished{false};
  };

  void initializeSettings();
  bool createTransaction();
  bool evaluate(const absl::Status& status, Path path, bool check_intervention = true);
  bool checkIntervention(Path path);
  void sendIntervention(const Engine::Intervention& intervention, Path path);
  void sendRuntimeError(Path path, absl::string_view details);
  bool addHeaders(const Http::HeaderMap& headers, Path path, absl::string_view request_host = {});
  bool inspectionEnabled(Path path) const;
  Http::FilterHeadersStatus stoppedOrContinue() const;
  Http::FilterDataStatus processData(Buffer::Instance& data, bool end_stream, Path path);
  Http::FilterTrailersStatus processTrailers(Path path);
  bool appendBody(Buffer::Instance& data, Path path);
  bool finishBody(Path path);
  void bypassBodyForStreaming(Path path);
  void classifyRequest(const Http::RequestHeaderMap& headers);
  bool shouldBypassResponseBody(const Http::ResponseHeaderMap& headers) const;
  bool declaredBodyExceedsLimit(const Http::RequestOrResponseHeaderMap& headers, Path path) const;
  void sendBodyOverflow(Path path);
  void sendBodyMemoryBudgetExceeded(Path path);
  void ensureBufferLimit(Path path);
  BodyState& bodyState(Path path);
  uint64_t bodyLimit(Path path) const;
  Stats::Histogram& bodyDurationHistogram(Path path) const;
  void finishLogging();
  void setSecurityOutcome(absl::string_view outcome, absl::string_view reason, Path path,
                          std::optional<uint32_t> status = std::nullopt);
  void publishSecurityEvent(const Engine::LoggingResult* logging_result,
                            bool logging_error = false);
  bool reserveBodyBytes(uint64_t bytes);
  void releaseResources();
  std::string httpVersion() const;
  std::string modSecurityRequestVersion() const;

  FilterConfigSharedPtr config_;
  EffectiveSettings settings_;
  FilterStatsSharedPtr stats_;
  TimeSource& time_source_;
  BodyMemoryBudgetSharedPtr body_memory_budget_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};
  std::unique_ptr<Engine::Transaction> transaction_;
  Buffer::BufferMemoryAccountSharedPtr memory_account_;
  BodyState request_body_;
  BodyState response_body_;
  StreamKind stream_kind_{StreamKind::Regular};
  uint64_t charged_body_bytes_{0};
  uint64_t rule_generation_id_{0};
  std::string security_outcome_{"allowed"};
  std::string security_reason_;
  std::string security_phase_{"complete"};
  std::optional<uint32_t> security_status_;
  bool connect_tunnel_{false};
  bool settings_initialized_{false};
  bool disabled_{false};
  bool engine_bypassed_{false};
  bool local_reply_{false};
  bool response_headers_finished_{false};
  bool logging_finished_{false};
  bool security_event_published_{false};
  bool resources_released_{false};
};

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
