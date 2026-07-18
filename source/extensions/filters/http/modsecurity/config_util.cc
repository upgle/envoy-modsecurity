#include "source/extensions/filters/http/modsecurity/config_util.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "source/engine/exception.h"
#include "source/engine/rules.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

constexpr uint64_t DefaultMaxActiveBodyBytes = 64 * 1024 * 1024;

}  // namespace

absl::StatusOr<std::vector<Engine::RuleSource>> convertRuleSources(
    const ConfigProto::ModSecurity& proto) {
  uint64_t total_inline_rule_bytes = 0;
  for (const ConfigProto::RuleSource& source : proto.rules()) {
    if (source.source_case() != ConfigProto::RuleSource::kInlineRules) {
      continue;
    }
    const absl::Status status = Engine::accumulateInlineRuleBytes(
        source.inline_rules().rules().size(), total_inline_rule_bytes);
    if (!status.ok()) {
      return status;
    }
  }

  return Engine::catchLibraryExceptions(
      "rule source conversion", [&]() -> absl::StatusOr<std::vector<Engine::RuleSource>> {
        std::vector<Engine::RuleSource> result;
        result.reserve(proto.rules_size());
        for (const ConfigProto::RuleSource& source : proto.rules()) {
          switch (source.source_case()) {
            case ConfigProto::RuleSource::kFilename:
              result.push_back(Engine::RuleSource::file(source.filename()));
              break;
            case ConfigProto::RuleSource::kInlineRules:
              result.push_back(Engine::RuleSource::inlineRules(source.inline_rules().name(),
                                                               source.inline_rules().rules()));
              break;
            case ConfigProto::RuleSource::SOURCE_NOT_SET:
              return absl::InvalidArgumentError("rule source must select filename or inline_rules");
          }
        }
        return result;
      });
}

absl::StatusOr<ParsedFilterSettings> parseFilterSettings(const ConfigProto::ModSecurity& proto) {
  const int configured_status = proto.has_status_on_error()
                                    ? static_cast<int>(proto.status_on_error().code())
                                    : static_cast<int>(Http::Code::InternalServerError);
  if (configured_status < 400 || configured_status > 599) {
    return absl::InvalidArgumentError("status_on_error must be a 4xx or 5xx HTTP status");
  }

  EffectiveSettings settings{
      proto.request_body().max_bytes().value(),
      proto.has_response() ? std::optional<uint64_t>(proto.response().body().max_bytes().value())
                           : std::nullopt,
      proto.failure_mode_allow(), static_cast<Http::Code>(configured_status)};
  const uint64_t max_active_body_bytes = proto.has_max_active_body_bytes()
                                             ? proto.max_active_body_bytes().value()
                                             : DefaultMaxActiveBodyBytes;
  const uint64_t largest_body_limit =
      settings.response_body_max_bytes.has_value()
          ? std::max(settings.request_body_max_bytes, *settings.response_body_max_bytes)
          : settings.request_body_max_bytes;
  if (max_active_body_bytes < largest_body_limit) {
    return absl::InvalidArgumentError(
        "max_active_body_bytes must be at least the largest configured body limit");
  }
  const uint32_t pcre_match_limit = proto.has_pcre_match_limit() ? proto.pcre_match_limit().value()
                                                                 : Engine::DefaultPcreMatchLimit;
  if (pcre_match_limit == 0 || pcre_match_limit > Engine::MaxPcreMatchLimit) {
    return absl::InvalidArgumentError("pcre_match_limit must be between 1 and 1000000");
  }
  return ParsedFilterSettings{settings, max_active_body_bytes, pcre_match_limit};
}

absl::StatusOr<std::shared_ptr<const RouteConfig>> convertRouteConfig(
    const ConfigProto::ModSecurityPerRoute& proto) {
  if (proto.override_case() == ConfigProto::ModSecurityPerRoute::OVERRIDE_NOT_SET) {
    return absl::InvalidArgumentError("per-route configuration must select an override");
  }

  const bool disabled = proto.override_case() == ConfigProto::ModSecurityPerRoute::kDisabled;
  std::optional<uint64_t> request_body_max_bytes;
  std::optional<uint64_t> response_body_max_bytes;
  RouteConfig::ResponseOverride response_override = RouteConfig::ResponseOverride::Inherit;

  if (!disabled) {
    const ConfigProto::ModSecurityPerRouteOverrides& overrides = proto.overrides();
    if (overrides.has_request_body()) {
      request_body_max_bytes = overrides.request_body().max_bytes().value();
    }
    switch (overrides.response_override_case()) {
      case ConfigProto::ModSecurityPerRouteOverrides::kDisableResponse:
        response_override = RouteConfig::ResponseOverride::Disable;
        break;
      case ConfigProto::ModSecurityPerRouteOverrides::kResponse:
        response_override = RouteConfig::ResponseOverride::Replace;
        response_body_max_bytes = overrides.response().body().max_bytes().value();
        break;
      case ConfigProto::ModSecurityPerRouteOverrides::RESPONSE_OVERRIDE_NOT_SET:
        break;
    }
  }

  return std::make_shared<const RouteConfig>(disabled, request_body_max_bytes, response_override,
                                             response_body_max_bytes);
}

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
