#pragma once

#include <memory>
#include <string>

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

#define ALL_MODSECURITY_FILTER_STATS(COUNTER, GAUGE, HISTOGRAM) \
  COUNTER(body_memory_budget_exceeded)                          \
  COUNTER(failure_mode_allowed)                                 \
  COUNTER(logging_errors)                                       \
  COUNTER(request_body_bypassed)                                \
  COUNTER(request_body_overflow)                                \
  COUNTER(request_interventions)                                \
  COUNTER(request_trailers_uninspected)                         \
  COUNTER(response_body_bypassed)                               \
  COUNTER(response_body_overflow)                               \
  COUNTER(response_interventions)                               \
  COUNTER(response_trailers_uninspected)                        \
  COUNTER(runtime_errors)                                       \
  COUNTER(security_event_rule_truncations)                      \
  COUNTER(security_events)                                      \
  GAUGE(active_rule_generations, Accumulate)                    \
  GAUGE(active_transactions, Accumulate)                        \
  GAUGE(modsecurity_buffer_bytes, Accumulate)                   \
  HISTOGRAM(logging_duration_us, Microseconds)                  \
  HISTOGRAM(request_body_duration_us, Microseconds)             \
  HISTOGRAM(request_headers_duration_us, Microseconds)          \
  HISTOGRAM(response_body_duration_us, Microseconds)            \
  HISTOGRAM(response_headers_duration_us, Microseconds)

struct FilterStats {
  ALL_MODSECURITY_FILTER_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                               GENERATE_HISTOGRAM_STRUCT)

  static FilterStats generate(const std::string& prefix, Stats::Scope& scope) {
    return {ALL_MODSECURITY_FILTER_STATS(POOL_COUNTER_PREFIX(scope, prefix),
                                         POOL_GAUGE_PREFIX(scope, prefix),
                                         POOL_HISTOGRAM_PREFIX(scope, prefix))};
  }
};

using FilterStatsSharedPtr = std::shared_ptr<FilterStats>;

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
