#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include "envoy/common/time.h"
#include "envoy/http/codes.h"
#include "envoy/router/router.h"
#include "source/engine/engine.h"
#include "source/extensions/filters/http/modsecurity/stats.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

struct EffectiveSettings {
  uint64_t request_body_max_bytes;
  std::optional<uint64_t> response_body_max_bytes;
  bool failure_mode_allow;
  Http::Code status_on_error;
};

class RouteConfig final : public Router::RouteSpecificFilterConfig {
 public:
  enum class ResponseOverride { Inherit, Disable, Replace };

  RouteConfig(bool disabled, std::optional<uint64_t> request_body_max_bytes,
              ResponseOverride response_override, std::optional<uint64_t> response_body_max_bytes);

  EffectiveSettings apply(const EffectiveSettings& base) const;
  bool disabled() const { return disabled_; }

 private:
  const bool disabled_;
  const std::optional<uint64_t> request_body_max_bytes_;
  const ResponseOverride response_override_;
  const std::optional<uint64_t> response_body_max_bytes_;
};

class FilterConfig {
 public:
  FilterConfig(EffectiveSettings settings, std::shared_ptr<const Engine::RuleGeneration> generation,
               FilterStatsSharedPtr stats, TimeSource& time_source);
  ~FilterConfig();

  const EffectiveSettings& settings() const { return settings_; }
  const std::shared_ptr<const Engine::RuleGeneration>& generation() const { return generation_; }
  FilterStats& stats() const { return *stats_; }
  TimeSource& timeSource() const { return time_source_; }

 private:
  const EffectiveSettings settings_;
  const std::shared_ptr<const Engine::RuleGeneration> generation_;
  const FilterStatsSharedPtr stats_;
  TimeSource& time_source_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
