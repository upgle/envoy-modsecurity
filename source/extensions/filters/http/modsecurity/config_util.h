#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/status/statusor.h"
#include "api/envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.h"
#include "source/engine/engine.h"
#include "source/extensions/filters/http/modsecurity/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

namespace ConfigProto = envoy_modsecurity::extensions::filters::http::modsecurity::v3;

struct ParsedFilterSettings {
  EffectiveSettings settings;
  uint64_t max_active_body_bytes;
};

absl::StatusOr<std::vector<Engine::RuleSource>> convertRuleSources(
    const ConfigProto::ModSecurity& proto);
absl::StatusOr<ParsedFilterSettings> parseFilterSettings(const ConfigProto::ModSecurity& proto);
absl::StatusOr<std::shared_ptr<const RouteConfig>> convertRouteConfig(
    const ConfigProto::ModSecurityPerRoute& proto);

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
