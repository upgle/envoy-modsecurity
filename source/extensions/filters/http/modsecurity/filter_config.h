#pragma once

#include <atomic>
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

// Shared by all streams created from one filter configuration. The counter limits admitted body
// bytes before libmodsecurity allocates its internal copies; Envoy's stream memory account tracks
// the same bytes for overload-manager victim selection.
class BodyMemoryBudget {
 public:
  explicit BodyMemoryBudget(uint64_t limit) : limit_(limit) {}

  bool tryReserve(uint64_t bytes);
  void release(uint64_t bytes);
  uint64_t limit() const { return limit_; }
  uint64_t used() const { return used_.load(std::memory_order_relaxed); }

 private:
  const uint64_t limit_;
  std::atomic<uint64_t> used_{0};
};

using BodyMemoryBudgetSharedPtr = std::shared_ptr<BodyMemoryBudget>;

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
               FilterStatsSharedPtr stats, BodyMemoryBudgetSharedPtr body_memory_budget,
               TimeSource& time_source);
  ~FilterConfig();

  const EffectiveSettings& settings() const { return settings_; }
  const std::shared_ptr<const Engine::RuleGeneration>& generation() const { return generation_; }
  FilterStats& stats() const { return *stats_; }
  const FilterStatsSharedPtr& statsShared() const { return stats_; }
  const BodyMemoryBudgetSharedPtr& bodyMemoryBudget() const { return body_memory_budget_; }
  TimeSource& timeSource() const { return time_source_; }

 private:
  const EffectiveSettings settings_;
  const std::shared_ptr<const Engine::RuleGeneration> generation_;
  const FilterStatsSharedPtr stats_;
  const BodyMemoryBudgetSharedPtr body_memory_budget_;
  TimeSource& time_source_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
