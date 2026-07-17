#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "envoy/http/codes.h"
#include "envoy/router/router.h"
#include "envoy/server/factory_context.h"

#include "source/engine/engine.h"
#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/modsecurity/stats.h"

#include "envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.h"
#include "envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

namespace Proto = envoy_modsecurity::extensions::filters::http::modsecurity::v3;

struct EffectiveSettings {
  uint64_t request_body_max_bytes;
  std::optional<uint64_t> response_body_max_bytes;
  bool failure_mode_allow;
  Http::Code status_on_error;
};

class RouteConfig final : public Router::RouteSpecificFilterConfig {
public:
  explicit RouteConfig(const Proto::ModSecurityPerRoute& proto);

  EffectiveSettings apply(const EffectiveSettings& base) const;
  bool disabled() const { return disabled_; }

private:
  enum class ResponseOverride { Inherit, Disable, Replace };

  bool disabled_{false};
  std::optional<uint64_t> request_body_max_bytes_;
  ResponseOverride response_override_{ResponseOverride::Inherit};
  std::optional<uint64_t> response_body_max_bytes_;
};

class FilterConfig {
public:
  FilterConfig(EffectiveSettings settings,
               std::shared_ptr<const Engine::RuleGeneration> generation,
               FilterStatsSharedPtr stats, TimeSource& time_source);
  ~FilterConfig();

  const EffectiveSettings& settings() const { return settings_; }
  const std::shared_ptr<const Engine::RuleGeneration>& generation() const { return generation_; }
  FilterStats& stats() const { return *stats_; }
  TimeSource& timeSource() const { return time_source_; }

private:
  const EffectiveSettings settings_;
  const std::shared_ptr<const Engine::RuleGeneration> generation_;
  const FilterStatsSharedPtr stats_;
  TimeSource& time_source_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

class FilterFactory
    : public Common::ExceptionFreeFactoryBase<Proto::ModSecurity, Proto::ModSecurityPerRoute> {
public:
  FilterFactory() : ExceptionFreeFactoryBase("envoy.filters.http.modsecurity") {}

private:
  absl::StatusOr<Http::FilterFactoryCb>
  createFilterFactoryFromProtoTyped(const Proto::ModSecurity& proto_config,
                                    const std::string& stats_prefix,
                                    Server::Configuration::FactoryContext& context) override;

  absl::StatusOr<Http::FilterFactoryCb>
  createHttpFilterFactoryFromProtoTyped(const Proto::ModSecurity& proto_config,
                                        const std::string& stats_prefix,
                                        Server::Configuration::ServerFactoryContext& context) override;

  absl::StatusOr<Router::RouteSpecificFilterConfigConstSharedPtr>
  createRouteSpecificFilterConfigTyped(const Proto::ModSecurityPerRoute& proto_config,
                                       Server::Configuration::ServerFactoryContext&,
                                       ProtobufMessage::ValidationVisitor&) override;
};

DECLARE_FACTORY(FilterFactory);

} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
