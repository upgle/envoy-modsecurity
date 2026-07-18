#pragma once

#include <cstdint>
#include <vector>

#include "source/engine/engine.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {

inline constexpr uint64_t MaxTotalInlineRuleBytes = 8 * 1024 * 1024;

// Adds one inline source size to the aggregate after enforcing the process-wide safety bound.
absl::Status accumulateInlineRuleBytes(uint64_t source_bytes, uint64_t& total_bytes);

// Applies the initial trusted-rule profile before libmodsecurity parses a candidate generation.
absl::Status validateRuleSources(const std::vector<RuleSource>& sources);

}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
