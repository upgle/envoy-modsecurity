#include "source/extensions/filters/http/modsecurity/config.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"
#include "source/engine/exception.h"
#include "source/engine/rules.h"
#include "source/extensions/filters/http/modsecurity/filter.h"
#include "source/extensions/filters/http/modsecurity/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

constexpr uint64_t DefaultMaxActiveBodyBytes = 64 * 1024 * 1024;

class RuntimeSingleton final : public Singleton::Instance {
 public:
  RuntimeSingleton() : runtime_(Engine::createRuntime()) {}

  const std::shared_ptr<Engine::Runtime>& runtime() const { return runtime_; }

 private:
  const std::shared_ptr<Engine::Runtime> runtime_;
};

SINGLETON_MANAGER_REGISTRATION(modsecurity_runtime);

std::string statsPrefix(const std::string& context_prefix, const std::string& instance_prefix) {
  std::string prefix = context_prefix;
  if (!prefix.empty() && prefix.back() != '.') {
    prefix.push_back('.');
  }
  prefix.append("modsecurity");
  if (!instance_prefix.empty()) {
    prefix.push_back('.');
    prefix.append(instance_prefix);
  }
  return prefix;
}

absl::StatusOr<std::vector<Engine::RuleSource>> ruleSources(const Proto::ModSecurity& proto) {
  uint64_t total_inline_rule_bytes = 0;
  for (const Proto::RuleSource& source : proto.rules()) {
    if (source.source_case() != Proto::RuleSource::kInlineRules) {
      continue;
    }
    const uint64_t size = source.inline_rules().rules().size();
    if (size > Engine::MaxTotalInlineRuleBytes - total_inline_rule_bytes) {
      return absl::InvalidArgumentError(
          absl::StrCat("total inline rule content exceeds ",
                       Engine::MaxTotalInlineRuleBytes, " bytes"));
    }
    total_inline_rule_bytes += size;
  }

  return Engine::catchLibraryExceptions(
      "rule source conversion", [&]() -> absl::StatusOr<std::vector<Engine::RuleSource>> {
        std::vector<Engine::RuleSource> result;
        result.reserve(proto.rules_size());
        for (const Proto::RuleSource& source : proto.rules()) {
          switch (source.source_case()) {
            case Proto::RuleSource::kFilename:
              result.push_back(Engine::RuleSource::file(source.filename()));
              break;
            case Proto::RuleSource::kInlineRules:
              result.push_back(Engine::RuleSource::inlineRules(source.inline_rules().name(),
                                                               source.inline_rules().rules()));
              break;
            case Proto::RuleSource::SOURCE_NOT_SET:
              break;
          }
        }
        return result;
      });
}

absl::StatusOr<FilterConfigSharedPtr> makeConfig(const Proto::ModSecurity& proto,
                                                 const std::string& context_stats_prefix,
                                                 Singleton::Manager& singleton_manager,
                                                 Stats::Scope& scope, TimeSource& time_source) {
  const int configured_status = proto.has_status_on_error()
                                    ? static_cast<int>(proto.status_on_error().code())
                                    : static_cast<int>(Http::Code::InternalServerError);
  if (configured_status < 400 || configured_status > 599) {
    return absl::InvalidArgumentError("status_on_error must be a 4xx or 5xx HTTP status");
  }

  auto singleton = singleton_manager.getTyped<RuntimeSingleton>(
      SINGLETON_MANAGER_REGISTERED_NAME(modsecurity_runtime),
      [] { return std::make_shared<RuntimeSingleton>(); }, true);
  auto sources = ruleSources(proto);
  if (!sources.ok()) {
    return sources.status();
  }
  auto generation = singleton->runtime()->compile(*sources);
  if (!generation.ok()) {
    // Returning a status from the exception-free factory makes an ECDS update NACK atomically;
    // the previously accepted callback and generation stay live.
    return generation.status();
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

  auto stats = std::make_shared<FilterStats>(
      FilterStats::generate(statsPrefix(context_stats_prefix, proto.stat_prefix()), scope));
  auto body_memory_budget = std::make_shared<BodyMemoryBudget>(max_active_body_bytes);
  return std::make_shared<FilterConfig>(settings, std::move(*generation), std::move(stats),
                                        std::move(body_memory_budget), time_source);
}

Http::FilterFactoryCb factoryCallback(FilterConfigSharedPtr config) {
  return [config = std::move(config)](Http::FilterChainFactoryCallbacks& callbacks) {
    callbacks.addStreamFilter(std::make_shared<Filter>(config));
  };
}

absl::StatusOr<Http::FilterFactoryCb> makeFilterFactory(const Proto::ModSecurity& proto,
                                                        const std::string& stats_prefix,
                                                        Singleton::Manager& singleton_manager,
                                                        Stats::Scope& scope,
                                                        TimeSource& time_source) {
  auto config = makeConfig(proto, stats_prefix, singleton_manager, scope, time_source);
  if (!config.ok()) {
    return config.status();
  }
  return factoryCallback(std::move(*config));
}

std::shared_ptr<const RouteConfig> routeConfig(const Proto::ModSecurityPerRoute& proto) {
  const bool disabled = proto.override_case() == Proto::ModSecurityPerRoute::kDisabled;
  std::optional<uint64_t> request_body_max_bytes;
  std::optional<uint64_t> response_body_max_bytes;
  RouteConfig::ResponseOverride response_override = RouteConfig::ResponseOverride::Inherit;

  if (!disabled && proto.override_case() == Proto::ModSecurityPerRoute::kOverrides) {
    const Proto::ModSecurityPerRouteOverrides& overrides = proto.overrides();
    if (overrides.has_request_body()) {
      request_body_max_bytes = overrides.request_body().max_bytes().value();
    }
    switch (overrides.response_override_case()) {
      case Proto::ModSecurityPerRouteOverrides::kDisableResponse:
        response_override = RouteConfig::ResponseOverride::Disable;
        break;
      case Proto::ModSecurityPerRouteOverrides::kResponse:
        response_override = RouteConfig::ResponseOverride::Replace;
        response_body_max_bytes = overrides.response().body().max_bytes().value();
        break;
      case Proto::ModSecurityPerRouteOverrides::RESPONSE_OVERRIDE_NOT_SET:
        break;
    }
  }

  return std::make_shared<const RouteConfig>(disabled, request_body_max_bytes, response_override,
                                             response_body_max_bytes);
}

}  // namespace

absl::StatusOr<Http::FilterFactoryCb> FilterFactory::createFilterFactoryFromProtoTyped(
    const Proto::ModSecurity& proto_config, const std::string& stats_prefix,
    Server::Configuration::FactoryContext& context) {
  return makeFilterFactory(proto_config, stats_prefix,
                           context.serverFactoryContext().singletonManager(), context.scope(),
                           context.serverFactoryContext().timeSource());
}

absl::StatusOr<Http::FilterFactoryCb> FilterFactory::createHttpFilterFactoryFromProtoTyped(
    const Proto::ModSecurity& proto_config, const std::string& stats_prefix,
    Server::Configuration::ServerFactoryContext& context) {
  return makeFilterFactory(proto_config, stats_prefix, context.singletonManager(), context.scope(),
                           context.timeSource());
}

absl::StatusOr<Router::RouteSpecificFilterConfigConstSharedPtr>
FilterFactory::createRouteSpecificFilterConfigTyped(const Proto::ModSecurityPerRoute& proto_config,
                                                    Server::Configuration::ServerFactoryContext&,
                                                    ProtobufMessage::ValidationVisitor&) {
  return routeConfig(proto_config);
}

REGISTER_FACTORY(FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
