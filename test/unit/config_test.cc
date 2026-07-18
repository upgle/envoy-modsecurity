#include "source/extensions/filters/http/modsecurity/config.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/mocks/server/mocks.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

Proto::ModSecurity validConfig() {
  Proto::ModSecurity config;
  Proto::InlineRules* rules = config.add_rules()->mutable_inline_rules();
  rules->set_name("config-test.conf");
  rules->set_rules(
      "SecRuleEngine On\n"
      "SecRule REQUEST_URI \"@streq /blocked\" \"id:9000001,phase:1,deny,status:403\"\n");
  config.mutable_request_body()->mutable_max_bytes()->set_value(1024);
  return config;
}

TEST(ConfigTest, RejectsOversizedInterventionResponseBody) {
  Proto::ModSecurity config = validConfig();
  config.mutable_intervention_response()->mutable_request_body()->set_inline_string(
      std::string(4097, 'x'));
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;

  auto result = FilterFactory().createFilterFactoryFromProto(config, "test", context);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.status().message(),
            "intervention_response.request_body is 4097 bytes; maximum is 4096");
}

TEST(ConfigTest, RejectsWatchedInterventionResponseBody) {
  Proto::ModSecurity config = validConfig();
  auto* body = config.mutable_intervention_response()->mutable_response_body();
  body->set_filename("/etc/envoy/modsecurity-response.txt");
  body->mutable_watched_directory()->set_path("/etc/envoy");
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;

  auto result = FilterFactory().createFilterFactoryFromProto(config, "test", context);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.status().message(),
            "intervention_response.response_body does not support watched_directory");
}

}  // namespace
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
