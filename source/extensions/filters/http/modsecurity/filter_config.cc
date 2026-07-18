#include "source/extensions/filters/http/modsecurity/filter_config.h"

#include <cstdint>
#include <utility>

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

bool BodyMemoryBudget::tryReserve(uint64_t bytes) {
  uint64_t current = used_.load(std::memory_order_relaxed);
  do {
    if (current > limit_ || bytes > limit_ - current) {
      return false;
    }
  } while (!used_.compare_exchange_weak(current, current + bytes, std::memory_order_relaxed));
  return true;
}

void BodyMemoryBudget::release(uint64_t bytes) {
  uint64_t current = used_.load(std::memory_order_relaxed);
  do {
    RELEASE_ASSERT(current >= bytes, "body memory budget underflow");
  } while (!used_.compare_exchange_weak(current, current - bytes, std::memory_order_relaxed));
}

RouteConfig::RouteConfig(bool disabled, std::optional<uint64_t> request_body_max_bytes,
                         ResponseOverride response_override,
                         std::optional<uint64_t> response_body_max_bytes)
    : disabled_(disabled),
      request_body_max_bytes_(request_body_max_bytes),
      response_override_(response_override),
      response_body_max_bytes_(response_body_max_bytes) {}

EffectiveSettings RouteConfig::apply(const EffectiveSettings& base) const {
  EffectiveSettings result = base;
  if (request_body_max_bytes_.has_value()) {
    result.request_body_max_bytes = *request_body_max_bytes_;
  }
  switch (response_override_) {
    case ResponseOverride::Inherit:
      break;
    case ResponseOverride::Disable:
      result.response_body_max_bytes.reset();
      break;
    case ResponseOverride::Replace:
      result.response_body_max_bytes = response_body_max_bytes_;
      break;
  }
  return result;
}

FilterConfig::FilterConfig(EffectiveSettings settings,
                           std::shared_ptr<const Engine::RuleGeneration> generation,
                           FilterStatsSharedPtr stats,
                           BodyMemoryBudgetSharedPtr body_memory_budget, TimeSource& time_source)
    : settings_(settings),
      generation_(std::move(generation)),
      stats_(std::move(stats)),
      body_memory_budget_(std::move(body_memory_budget)),
      time_source_(time_source) {
  stats_->active_rule_generations_.inc();
}

FilterConfig::~FilterConfig() { stats_->active_rule_generations_.dec(); }

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
