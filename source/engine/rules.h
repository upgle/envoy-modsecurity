#pragma once

#include <vector>

#include "source/engine/engine.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {

// Applies the initial trusted-rule profile before libmodsecurity parses a candidate generation.
absl::Status validateRuleSources(const std::vector<RuleSource>& sources);

} // namespace Engine
} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
