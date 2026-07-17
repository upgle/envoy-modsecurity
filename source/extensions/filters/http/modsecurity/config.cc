#include "source/extensions/filters/http/modsecurity/config.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "source/extensions/filters/http/modsecurity/filter.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

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

std::vector<Engine::RuleSource> ruleSources(const Proto::ModSecurity& proto) {
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
}

absl::StatusOr<FilterConfigSharedPtr>
makeConfig(const Proto::ModSecurity& proto, const std::string& context_stats_prefix,
           Singleton::Manager& singleton_manager, Stats::Scope& scope, TimeSource& time_source) {
  const int configured_status = proto.has_status_on_error()
                                    ? static_cast<int>(proto.status_on_error().code())
                                    : static_cast<int>(Http::Code::InternalServerError);
  if (configured_status < 400 || configured_status > 599) {
    return absl::InvalidArgumentError("status_on_error must be a 4xx or 5xx HTTP status");
  }

  auto singleton = singleton_manager.getTyped<RuntimeSingleton>(
      SINGLETON_MANAGER_REGISTERED_NAME(modsecurity_runtime),
      [] { return std::make_shared<RuntimeSingleton>(); }, true);
  auto generation = singleton->runtime()->compile(ruleSources(proto));
  if (!generation.ok()) {
    // Returning a status from the exception-free factory makes an ECDS update NACK atomically;
    // the previously accepted callback and generation stay live.
    return generation.status();
  }

  EffectiveSettings settings{
      proto.request_body().max_bytes().value(),
      proto.has_response()
          ? std::optional<uint64_t>(proto.response().body().max_bytes().value())
          : std::nullopt,
      proto.failure_mode_allow(), static_cast<Http::Code>(configured_status)};
  auto stats = std::make_shared<FilterStats>(
      FilterStats::generate(statsPrefix(context_stats_prefix, proto.stat_prefix()), scope));
  return std::make_shared<FilterConfig>(settings, std::move(*generation), std::move(stats),
                                        time_source);
}

Http::FilterFactoryCb factoryCallback(FilterConfigSharedPtr config) {
  return [config = std::move(config)](Http::FilterChainFactoryCallbacks& callbacks) {
    callbacks.addStreamFilter(std::make_shared<Filter>(config));
  };
}

} // namespace

RouteConfig::RouteConfig(const Proto::ModSecurityPerRoute& proto) {
  if (proto.override_case() == Proto::ModSecurityPerRoute::kDisabled) {
    disabled_ = true;
    return;
  }
  if (proto.override_case() != Proto::ModSecurityPerRoute::kOverrides) {
    return;
  }

  const Proto::ModSecurityPerRouteOverrides& overrides = proto.overrides();
  if (overrides.has_request_body()) {
    request_body_max_bytes_ = overrides.request_body().max_bytes().value();
  }
  switch (overrides.response_override_case()) {
  case Proto::ModSecurityPerRouteOverrides::kDisableResponse:
    response_override_ = ResponseOverride::Disable;
    break;
  case Proto::ModSecurityPerRouteOverrides::kResponse:
    response_override_ = ResponseOverride::Replace;
    response_body_max_bytes_ = overrides.response().body().max_bytes().value();
    break;
  case Proto::ModSecurityPerRouteOverrides::RESPONSE_OVERRIDE_NOT_SET:
    break;
  }
}

EffectiveSettings RouteConfig::apply(const EffectiveSettings& base) const {
  EffectiveSettings result = base;
  if (request_body_max_bytes_.has_value()) {
    result.request_body_max_bytes = *request_body_max_bytes_;
  }
  if (response_override_ == ResponseOverride::Disable) {
    result.response_body_max_bytes.reset();
  } else if (response_override_ == ResponseOverride::Replace) {
    result.response_body_max_bytes = response_body_max_bytes_;
  }
  return result;
}

FilterConfig::FilterConfig(EffectiveSettings settings,
                           std::shared_ptr<const Engine::RuleGeneration> generation,
                           FilterStatsSharedPtr stats, TimeSource& time_source)
    : settings_(settings), generation_(std::move(generation)), stats_(std::move(stats)),
      time_source_(time_source) {
  stats_->active_rule_generations_.inc();
}

FilterConfig::~FilterConfig() { stats_->active_rule_generations_.dec(); }

absl::StatusOr<Http::FilterFactoryCb> FilterFactory::createFilterFactoryFromProtoTyped(
    const Proto::ModSecurity& proto_config, const std::string& stats_prefix,
    Server::Configuration::FactoryContext& context) {
  auto config = makeConfig(proto_config, stats_prefix, context.serverFactoryContext().singletonManager(),
                           context.scope(), context.serverFactoryContext().timeSource());
  if (!config.ok()) {
    return config.status();
  }
  return factoryCallback(std::move(*config));
}

absl::StatusOr<Http::FilterFactoryCb> FilterFactory::createHttpFilterFactoryFromProtoTyped(
    const Proto::ModSecurity& proto_config, const std::string& stats_prefix,
    Server::Configuration::ServerFactoryContext& context) {
  auto config = makeConfig(proto_config, stats_prefix, context.singletonManager(), context.scope(),
                           context.timeSource());
  if (!config.ok()) {
    return config.status();
  }
  return factoryCallback(std::move(*config));
}

absl::StatusOr<Router::RouteSpecificFilterConfigConstSharedPtr>
FilterFactory::createRouteSpecificFilterConfigTyped(
    const Proto::ModSecurityPerRoute& proto_config,
    Server::Configuration::ServerFactoryContext&, ProtobufMessage::ValidationVisitor&) {
  return std::make_shared<const RouteConfig>(proto_config);
}

REGISTER_FACTORY(FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
