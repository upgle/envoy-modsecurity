#include "source/engine/rules.h"

#include <vector>

#include "absl/status/status.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

TEST(RuleValidationTest, AcceptsNarrowInlineRules) {
  const std::vector<RuleSource> sources{RuleSource::inlineRules(
      "local.conf",
      R"EOF(SecRule REQUEST_URI "@beginsWith /admin" "id:1000001,phase:1,deny,status:403")EOF")};

  EXPECT_TRUE(validateRuleSources(sources).ok());
}

TEST(RuleValidationTest, RejectsRemoteExecutionCapabilities) {
  const std::vector<RuleSource> sources{
      RuleSource::inlineRules("remote.conf", "SecRemoteRules key https://rules.example/rules"),
  };

  const absl::Status status = validateRuleSources(sources);
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(status.message().find("secremoterules"), std::string::npos);
}

TEST(RuleValidationTest, RejectsPersistentCollections) {
  const std::vector<RuleSource> sources{RuleSource::inlineRules(
      "collection.conf", R"EOF(SecAction "id:1000002,phase:1,pass,initcol:ip=%{REMOTE_ADDR}")EOF")};

  EXPECT_FALSE(validateRuleSources(sources).ok());
}

TEST(RuleValidationTest, IgnoresCommentedUnsafeToken) {
  const std::vector<RuleSource> sources{RuleSource::inlineRules(
      "comment.conf", "# SecRuleScript dangerous.lua\nSecAction \"id:1000003,phase:1,pass\"")};

  EXPECT_TRUE(validateRuleSources(sources).ok());
}

TEST(RuleValidationTest, RequiresAbsoluteFilePath) {
  const absl::Status status = validateRuleSources({RuleSource::file("rules.conf")});

  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(status.message().find("absolute"), std::string::npos);
}

} // namespace
} // namespace Engine
} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
