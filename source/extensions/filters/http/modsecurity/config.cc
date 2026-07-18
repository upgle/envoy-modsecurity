#include "source/extensions/filters/http/modsecurity/config.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"
#include "source/extensions/filters/http/modsecurity/config_util.h"
#include "source/extensions/filters/http/modsecurity/filter.h"
#include "source/extensions/filters/http/modsecurity/filter_config.h"

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

absl::StatusOr<FilterConfigSharedPtr> makeConfig(const Proto::ModSecurity& proto,
                                                 const std::string& context_stats_prefix,
                                                 Singleton::Manager& singleton_manager,
                                                 Stats::Scope& scope, TimeSource& time_source) {
  auto parsed_settings = parseFilterSettings(proto);
  if (!parsed_settings.ok()) {
    return parsed_settings.status();
  }

  auto sources = convertRuleSources(proto);
  if (!sources.ok()) {
    return sources.status();
  }
  auto singleton = singleton_manager.getTyped<RuntimeSingleton>(
      SINGLETON_MANAGER_REGISTERED_NAME(modsecurity_runtime),
      [] { return std::make_shared<RuntimeSingleton>(); }, true);
  auto generation = singleton->runtime()->compile(*sources, parsed_settings->pcre_match_limit);
  if (!generation.ok()) {
    // Returning a status from the exception-free factory makes an ECDS update NACK atomically;
    // the previously accepted callback and generation stay live.
    return generation.status();
  }

  auto stats = std::make_shared<FilterStats>(
      FilterStats::generate(statsPrefix(context_stats_prefix, proto.stat_prefix()), scope));
  auto body_memory_budget =
      std::make_shared<BodyMemoryBudget>(parsed_settings->max_active_body_bytes);
  return std::make_shared<FilterConfig>(parsed_settings->settings, std::move(*generation),
                                        std::move(stats), std::move(body_memory_budget),
                                        time_source);
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
  auto route_config = convertRouteConfig(proto_config);
  if (!route_config.ok()) {
    return route_config.status();
  }
  return Router::RouteSpecificFilterConfigConstSharedPtr(std::move(*route_config));
}

REGISTER_FACTORY(FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
