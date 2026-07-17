#pragma once

#include <string>

#include "envoy/server/factory_context.h"
#include "envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.h"
#include "envoy_modsecurity/extensions/filters/http/modsecurity/v3/modsecurity.pb.validate.h"
#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {

namespace Proto = envoy_modsecurity::extensions::filters::http::modsecurity::v3;

class FilterFactory
    : public Common::ExceptionFreeFactoryBase<Proto::ModSecurity, Proto::ModSecurityPerRoute> {
 public:
  FilterFactory() : ExceptionFreeFactoryBase("envoy.filters.http.modsecurity") {}

 private:
  absl::StatusOr<Http::FilterFactoryCb> createFilterFactoryFromProtoTyped(
      const Proto::ModSecurity& proto_config, const std::string& stats_prefix,
      Server::Configuration::FactoryContext& context) override;

  absl::StatusOr<Http::FilterFactoryCb> createHttpFilterFactoryFromProtoTyped(
      const Proto::ModSecurity& proto_config, const std::string& stats_prefix,
      Server::Configuration::ServerFactoryContext& context) override;

  absl::StatusOr<Router::RouteSpecificFilterConfigConstSharedPtr>
  createRouteSpecificFilterConfigTyped(const Proto::ModSecurityPerRoute& proto_config,
                                       Server::Configuration::ServerFactoryContext&,
                                       ProtobufMessage::ValidationVisitor&) override;
};

DECLARE_FACTORY(FilterFactory);

}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
