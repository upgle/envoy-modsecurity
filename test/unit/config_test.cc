#include <cstdint>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "envoy/type/v3/http_status.pb.h"
#include "gtest/gtest.h"
#include "source/extensions/filters/http/modsecurity/config_util.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace {

ConfigProto::ModSecurity baseConfig(uint32_t request_body_limit = 1024) {
  ConfigProto::ModSecurity proto;
  proto.mutable_request_body()->mutable_max_bytes()->set_value(request_body_limit);
  return proto;
}

TEST(ConfigUtilTest, ConvertsOrderedRuleSources) {
  ConfigProto::ModSecurity proto = baseConfig();
  proto.add_rules()->set_filename("/etc/modsecurity/root.conf");
  auto* inline_source = proto.add_rules()->mutable_inline_rules();
  inline_source->set_name("local.conf");
  inline_source->set_rules("SecAction \"id:1000001,phase:1,pass\"");

  auto sources = convertRuleSources(proto);
  ASSERT_TRUE(sources.ok()) << sources.status();
  ASSERT_EQ(sources->size(), 2);
  EXPECT_EQ((*sources)[0].kind, Engine::RuleSource::Kind::File);
  EXPECT_EQ((*sources)[0].name, "/etc/modsecurity/root.conf");
  EXPECT_EQ((*sources)[1].kind, Engine::RuleSource::Kind::Inline);
  EXPECT_EQ((*sources)[1].name, "local.conf");
}

TEST(ConfigUtilTest, RejectsUnsetRuleSource) {
  ConfigProto::ModSecurity proto = baseConfig();
  proto.add_rules();

  const auto sources = convertRuleSources(proto);
  ASSERT_FALSE(sources.ok());
  EXPECT_EQ(sources.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(ConfigUtilTest, RejectsAggregateInlineContentBeforeConversion) {
  ConfigProto::ModSecurity proto = baseConfig();
  for (int index = 0; index < 9; ++index) {
    auto* inline_source = proto.add_rules()->mutable_inline_rules();
    inline_source->set_name("large.conf");
    inline_source->set_rules(std::string(1024 * 1024, 'x'));
  }

  const auto sources = convertRuleSources(proto);
  ASSERT_FALSE(sources.ok());
  EXPECT_EQ(sources.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(ConfigUtilTest, ParsesDefaultsAndResponseSettings) {
  ConfigProto::ModSecurity proto = baseConfig(4096);
  proto.mutable_response()->mutable_body()->mutable_max_bytes()->set_value(8192);
  proto.set_failure_mode_allow(true);

  auto parsed = parseFilterSettings(proto);
  ASSERT_TRUE(parsed.ok()) << parsed.status();
  EXPECT_EQ(parsed->settings.request_body_max_bytes, 4096);
  ASSERT_TRUE(parsed->settings.response_body_max_bytes.has_value());
  EXPECT_EQ(*parsed->settings.response_body_max_bytes, 8192);
  EXPECT_TRUE(parsed->settings.failure_mode_allow);
  EXPECT_EQ(parsed->settings.status_on_error, Http::Code::InternalServerError);
  EXPECT_EQ(parsed->max_active_body_bytes, 64 * 1024 * 1024);
}

TEST(ConfigUtilTest, RejectsNonErrorStatus) {
  ConfigProto::ModSecurity proto = baseConfig();
  proto.mutable_status_on_error()->set_code(envoy::type::v3::StatusCode::OK);

  const auto parsed = parseFilterSettings(proto);
  ASSERT_FALSE(parsed.ok());
  EXPECT_EQ(parsed.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(ConfigUtilTest, RejectsAggregateBudgetBelowBodyLimit) {
  ConfigProto::ModSecurity proto = baseConfig(4096);
  proto.mutable_max_active_body_bytes()->set_value(2048);

  const auto parsed = parseFilterSettings(proto);
  ASSERT_FALSE(parsed.ok());
  EXPECT_EQ(parsed.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(ConfigUtilTest, ConvertsRouteOverrides) {
  ConfigProto::ModSecurityPerRoute proto;
  auto* overrides = proto.mutable_overrides();
  overrides->mutable_request_body()->mutable_max_bytes()->set_value(2048);
  overrides->mutable_response()->mutable_body()->mutable_max_bytes()->set_value(4096);

  auto route = convertRouteConfig(proto);
  ASSERT_TRUE(route.ok()) << route.status();
  const EffectiveSettings applied =
      (*route)->apply(EffectiveSettings{1024, std::nullopt, false, Http::Code::BadRequest});
  EXPECT_EQ(applied.request_body_max_bytes, 2048);
  ASSERT_TRUE(applied.response_body_max_bytes.has_value());
  EXPECT_EQ(*applied.response_body_max_bytes, 4096);
}

TEST(ConfigUtilTest, RejectsUnsetRouteOverride) {
  const auto route = convertRouteConfig(ConfigProto::ModSecurityPerRoute{});
  ASSERT_FALSE(route.ok());
  EXPECT_EQ(route.status().code(), absl::StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
