#pragma once

#include <cstdint>
#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/http/filter.h"

#include "source/extensions/filters/http/modsecurity/config.h"

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

  void initializeSettings();
  bool createTransaction();
  bool handleEngineResult(const absl::Status& status, Path path, bool check_intervention);
  bool checkIntervention(Path path);
  void sendIntervention(const Engine::Intervention& intervention, Path path);
  void sendRuntimeError(Path path, absl::string_view details);
  bool addRequestHeaders(const Http::RequestHeaderMap& headers);
  bool addResponseHeaders(const Http::ResponseHeaderMap& headers);
  bool appendBody(Buffer::Instance& data, Path path);
  bool finishRequestBody();
  bool finishResponseBody();
  void finishLogging();
  void chargeBodyBytes(uint64_t bytes);
  void releaseResources();
  std::string httpVersion() const;

  FilterConfigSharedPtr config_;
  EffectiveSettings settings_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};
  std::unique_ptr<Engine::Transaction> transaction_;
  Buffer::BufferMemoryAccountSharedPtr memory_account_;
  uint64_t request_body_bytes_{0};
  uint64_t response_body_bytes_{0};
  uint64_t charged_body_bytes_{0};
  bool settings_initialized_{false};
  bool disabled_{false};
  bool engine_bypassed_{false};
  bool local_reply_{false};
  bool request_body_finished_{false};
  bool response_headers_finished_{false};
  bool response_body_finished_{false};
  bool logging_finished_{false};
  bool resources_released_{false};
  bool transaction_counted_{false};
};

} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
