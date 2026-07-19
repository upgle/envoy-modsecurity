#include "source/engine/rules.h"

#include <string>
#include <utility>
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

TEST(RuleValidationTest, PreservesHashInsideQuotedValues) {
  const std::vector<RuleSource> safe_sources{RuleSource::inlineRules(
      "quoted-hash.conf",
      R"EOF(SecRule REQUEST_URI "@contains #fragment" "id:1000004,phase:1,pass")EOF")};
  EXPECT_TRUE(validateRuleSources(safe_sources).ok());

  const std::vector<RuleSource> unsafe_sources{RuleSource::inlineRules(
      "quoted-hash-exec.conf",
      R"EOF(SecAction "id:1000005,phase:1,pass,msg:'literal # marker',exec:/tmp/hook")EOF")};
  const absl::Status status = validateRuleSources(unsafe_sources);
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(status.message().find("exec:"), std::string::npos);
}

TEST(RuleValidationTest, NormalizesDirectiveWhitespaceAndContinuations) {
  const absl::Status whitespace = validateRuleSources(
      {RuleSource::inlineRules("xml-whitespace.conf", "SecXmlExternalEntity\t   On")});
  EXPECT_EQ(whitespace.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(whitespace.message().find("secxmlexternalentity on"), std::string::npos);

  const absl::Status continuation = validateRuleSources(
      {RuleSource::inlineRules("xml-continuation.conf", "SecXmlExternalEntity \\\n On")});
  EXPECT_EQ(continuation.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(continuation.message().find("secxmlexternalentity on"), std::string::npos);

  const absl::Status split_fragment = validateRuleSources(
      {RuleSource::inlineRules("exec-continuation.conf",
                               R"EOF(SecAction "id:1000006,phase:1,pass,ex\
ec:/tmp/hook")EOF")});
  EXPECT_EQ(split_fragment.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(split_fragment.message().find("exec:"), std::string::npos);
}

TEST(RuleValidationTest, RejectsEmbeddedNulBytes) {
  std::string contents = R"EOF(SecAction "id:1000007,phase:1,pass")EOF";
  contents.push_back('\0');
  contents.append("SecRemoteRules key https://rules.example/rules");

  const absl::Status contents_status =
      validateRuleSources({RuleSource::inlineRules("nul.conf", std::move(contents))});
  EXPECT_EQ(contents_status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(contents_status.message().find("embedded NUL"), std::string::npos);

  std::string name("nul\0.conf", 9);
  const absl::Status name_status = validateRuleSources(
      {RuleSource::inlineRules(std::move(name), R"EOF(SecAction "id:1000008,phase:1,pass")EOF")});
  EXPECT_EQ(name_status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(name_status.message().find("embedded NUL"), std::string::npos);
}

TEST(RuleValidationTest, MatchesUnsafeDirectivesAtTokenBoundaries) {
  const std::vector<RuleSource> sources{RuleSource::inlineRules(
      "directive-token.conf",
      R"EOF(SecRule REQUEST_HEADERS:Include "@streq expected" "id:1000009,phase:1,pass")EOF")};

  EXPECT_TRUE(validateRuleSources(sources).ok());
}

TEST(RuleValidationTest, RequiresAbsoluteFilePath) {
  const absl::Status status = validateRuleSources({RuleSource::file("rules.conf")});

  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(status.message().find("absolute"), std::string::npos);
}

TEST(RuleValidationTest, RejectsExcessiveAggregateInlineContent) {
  std::string oversized(8 * 1024 * 1024 + 1, 'x');
  const absl::Status status =
      validateRuleSources({RuleSource::inlineRules("oversized.conf", std::move(oversized))});

  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(status.message().find("total inline rule content"), std::string::npos);
}

} // namespace
} // namespace Engine
} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
