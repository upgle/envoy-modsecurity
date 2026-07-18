#pragma once

#include <cstdint>
#include <memory>

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
  enum class MessageSide { Request, Response };
  enum class InspectionOutcome { Continue, Bypass, LocalReply };
  enum class StreamDisposition { Inspecting, Bypassed, LocalReply };
  enum class StreamKind { Regular, Grpc, ConnectStreaming, Tunnel };
  struct BodyState {
    uint64_t bytes{0};
    bool finished{false};
  };

  void initializeSettings();
  InspectionOutcome createTransaction();
  InspectionOutcome handleEngineResult(const absl::Status& status, MessageSide side,
                                       bool check_intervention = true);
  InspectionOutcome checkIntervention(MessageSide side);
  void sendIntervention(const Engine::Intervention& intervention, MessageSide side);
  void sendRuntimeError(MessageSide side, absl::string_view details);
  InspectionOutcome addHeaders(const Http::HeaderMap& headers, MessageSide side,
                               absl::string_view request_host = {});
  bool bodyInspectionPending(MessageSide side) const;
  static Http::FilterHeadersStatus headerStatusForOutcome(InspectionOutcome outcome);
  Http::FilterDataStatus processData(Buffer::Instance& data, bool end_stream, MessageSide side);
  Http::FilterTrailersStatus processTrailers(MessageSide side);
  InspectionOutcome appendBody(Buffer::Instance& data, MessageSide side);
  InspectionOutcome completeBodyInspection(MessageSide side);
  void skipBodyInspectionForStreaming(MessageSide side);
  void classifyRequest(const Http::RequestHeaderMap& headers);
  bool shouldBypassResponseBody(const Http::ResponseHeaderMap& headers) const;
  bool declaredBodyExceedsLimit(const Http::RequestOrResponseHeaderMap& headers,
                                MessageSide side) const;
  void sendBodyOverflow(MessageSide side);
  void sendBodyMemoryBudgetExceeded(MessageSide side);
  void ensureBufferLimit(MessageSide side);
  BodyState& bodyState(MessageSide side);
  uint64_t bodyLimit(MessageSide side) const;
  Stats::Histogram& bodyDurationHistogram(MessageSide side) const;
  void finishLogging();
  bool reserveBodyBytes(uint64_t bytes);
  void releaseResources();
  std::string httpProtocol() const;

  FilterConfigSharedPtr config_;
  EffectiveSettings settings_;
  FilterStatsSharedPtr stats_;
  TimeSource& time_source_;
  BodyMemoryBudgetSharedPtr body_memory_budget_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};
  RuleGenerationHandleSharedPtr generation_;
  std::unique_ptr<Engine::Transaction> transaction_;
  Buffer::BufferMemoryAccountSharedPtr memory_account_;
  BodyState request_body_;
  BodyState response_body_;
  StreamKind stream_kind_{StreamKind::Regular};
  uint64_t charged_body_bytes_{0};
  bool connect_tunnel_{false};
  bool settings_initialized_{false};
  bool disabled_{false};
  StreamDisposition disposition_{StreamDisposition::Inspecting};
  bool response_headers_finished_{false};
  bool logging_finished_{false};
  bool resources_released_{false};
};

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
