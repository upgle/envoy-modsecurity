#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "gtest/gtest.h"
#include "source/engine/engine.h"
#include "test/test_common/environment.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

constexpr char kPhaseOneRules[] = R"(
SecRuleEngine On
SecRule REQUEST_URI "@rx ^/blocked" "id:1000001,phase:1,deny,status:418,nolog"
)";

constexpr char kPhaseTwoRules[] = R"(
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains attack-token" "id:1000002,phase:2,deny,status:406,nolog"
)";

absl::Status processRequestHeaders(Transaction& transaction, const std::string& uri,
                                   const std::string& method = "GET") {
  absl::Status status = transaction.processConnection("192.0.2.10", 12345, "192.0.2.20", 8080);
  if (!status.ok()) {
    return status;
  }
  status = transaction.processUri(uri, method, "HTTP/1.1");
  if (!status.ok()) {
    return status;
  }
  status = transaction.addRequestHeader("host", "example.test");
  if (!status.ok()) {
    return status;
  }
  return transaction.processRequestHeaders();
}

absl::Status processResponseHeaders(Transaction& transaction, absl::string_view content_type) {
  absl::Status status = transaction.addResponseHeader("content-type", content_type);
  if (!status.ok()) {
    return status;
  }
  return transaction.processResponseHeaders(200, "HTTP/1.1");
}

std::unique_ptr<Transaction> createTransaction(
    const std::shared_ptr<const RuleGeneration>& generation) {
  auto transaction = generation->createTransaction();
  EXPECT_TRUE(transaction.ok()) << transaction.status();
  if (!transaction.ok()) {
    return nullptr;
  }
  return std::move(*transaction);
}

void expectNoIntervention(Transaction& transaction) {
  auto intervention = transaction.intervention();
  ASSERT_TRUE(intervention.ok()) << intervention.status();
  EXPECT_FALSE(intervention->has_value());
}

void expectIntervention(Transaction& transaction, int expected_status) {
  auto intervention = transaction.intervention();
  ASSERT_TRUE(intervention.ok()) << intervention.status();
  ASSERT_TRUE(intervention->has_value());
  EXPECT_EQ(intervention->value().status, expected_status);
}

TEST(EngineIntegrationTest, CompilesInlineRulesAndExecutesPhaseOne) {
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation = runtime->compile({RuleSource::inlineRules("phase-one.conf", kPhaseOneRules)});
  ASSERT_TRUE(generation.ok()) << generation.status();
  EXPECT_EQ((*generation)->sourceCount(), 1);
  EXPECT_GE((*generation)->loadedRuleCount(), 1);

  std::unique_ptr<Transaction> allowed = createTransaction(*generation);
  ASSERT_NE(allowed, nullptr);
  ASSERT_TRUE(processRequestHeaders(*allowed, "/allowed").ok());
  expectNoIntervention(*allowed);

  std::unique_ptr<Transaction> blocked = createTransaction(*generation);
  ASSERT_NE(blocked, nullptr);
  ASSERT_TRUE(processRequestHeaders(*blocked, "/blocked/resource").ok());
  expectIntervention(*blocked, 418);
}

TEST(EngineIntegrationTest, ExecutesPhaseTwoAgainstBufferedRequestBody) {
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation = runtime->compile({RuleSource::inlineRules("phase-two.conf", kPhaseTwoRules)});
  ASSERT_TRUE(generation.ok()) << generation.status();

  std::unique_ptr<Transaction> transaction = createTransaction(*generation);
  ASSERT_NE(transaction, nullptr);
  ASSERT_TRUE(transaction->processConnection("192.0.2.10", 12345, "192.0.2.20", 8080).ok());
  ASSERT_TRUE(transaction->processUri("/submit", "POST", "HTTP/1.1").ok());
  ASSERT_TRUE(transaction->addRequestHeader("host", "example.test").ok());
  ASSERT_TRUE(
      transaction->addRequestHeader("content-type", "application/x-www-form-urlencoded").ok());
  ASSERT_TRUE(transaction->addRequestHeader("content-length", "27").ok());
  ASSERT_TRUE(transaction->processRequestHeaders().ok());
  expectNoIntervention(*transaction);

  ASSERT_TRUE(transaction->appendRequestBody("value=contains-attack-token").ok());
  ASSERT_TRUE(transaction->processRequestBody().ok());
  expectIntervention(*transaction, 406);
}

TEST(EngineIntegrationTest, ReportsResponseBodyAccessDisabled) {
  constexpr char kResponseDisabledRules[] = R"(
SecRuleEngine On
SecResponseBodyAccess Off
)";
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation =
      runtime->compile({RuleSource::inlineRules("response-disabled.conf", kResponseDisabledRules)});
  ASSERT_TRUE(generation.ok()) << generation.status();

  std::unique_ptr<Transaction> transaction = createTransaction(*generation);
  ASSERT_NE(transaction, nullptr);
  ASSERT_TRUE(processRequestHeaders(*transaction, "/response-disabled").ok());
  ASSERT_TRUE(processResponseHeaders(*transaction, "text/plain").ok());
  auto should_inspect = transaction->shouldInspectResponseBody();
  ASSERT_TRUE(should_inspect.ok()) << should_inspect.status();
  EXPECT_FALSE(*should_inspect);
}

TEST(EngineIntegrationTest, ReportsWhetherResponseMimeTypeIsSelected) {
  constexpr char kResponseMimeRules[] = R"(
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "@contains blocked-response" "id:1000007,phase:4,deny,status:409,nolog"
)";
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation =
      runtime->compile({RuleSource::inlineRules("response-mime.conf", kResponseMimeRules)});
  ASSERT_TRUE(generation.ok()) << generation.status();

  std::unique_ptr<Transaction> selected = createTransaction(*generation);
  ASSERT_NE(selected, nullptr);
  ASSERT_TRUE(processRequestHeaders(*selected, "/selected").ok());
  ASSERT_TRUE(processResponseHeaders(*selected, "text/plain; charset=utf-8").ok());
  auto selected_result = selected->shouldInspectResponseBody();
  ASSERT_TRUE(selected_result.ok()) << selected_result.status();
  EXPECT_TRUE(*selected_result);

  std::unique_ptr<Transaction> unselected = createTransaction(*generation);
  ASSERT_NE(unselected, nullptr);
  ASSERT_TRUE(processRequestHeaders(*unselected, "/unselected").ok());
  ASSERT_TRUE(processResponseHeaders(*unselected, "application/octet-stream").ok());
  auto unselected_result = unselected->shouldInspectResponseBody();
  ASSERT_TRUE(unselected_result.ok()) << unselected_result.status();
  EXPECT_FALSE(*unselected_result);
}

TEST(EngineIntegrationTest, LoadsRulesFromFile) {
  const std::string filename = TestEnvironment::writeStringToFileForTest(
      "modsecurity-engine-integration.conf", kPhaseOneRules);
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation = runtime->compile({RuleSource::file(filename)});
  ASSERT_TRUE(generation.ok()) << generation.status();
  EXPECT_EQ((*generation)->sourceCount(), 1);
  EXPECT_GE((*generation)->loadedRuleCount(), 1);

  std::unique_ptr<Transaction> transaction = createTransaction(*generation);
  ASSERT_NE(transaction, nullptr);
  ASSERT_TRUE(processRequestHeaders(*transaction, "/blocked/from-file").ok());
  expectIntervention(*transaction, 418);
}

TEST(EngineIntegrationTest, RejectsInvalidSecLang) {
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation =
      runtime->compile({RuleSource::inlineRules("invalid.conf", "SecRule REQUEST_URI\n")});

  ASSERT_FALSE(generation.ok());
  EXPECT_EQ(generation.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_NE(generation.status().message().find("invalid.conf"), std::string::npos);
}

TEST(EngineIntegrationTest, NormalizesCanonicalRequestProtocolAtNativeBoundary) {
  constexpr char kProtocolRules[] = R"(
SecRuleEngine On
SecRule REQUEST_PROTOCOL "@streq HTTP/2" "id:1000004,phase:1,deny,status:419,nolog"
)";
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation =
      runtime->compile({RuleSource::inlineRules("request-protocol.conf", kProtocolRules)});
  ASSERT_TRUE(generation.ok()) << generation.status();

  std::unique_ptr<Transaction> transaction = createTransaction(*generation);
  ASSERT_NE(transaction, nullptr);
  ASSERT_TRUE(transaction->processConnection("192.0.2.10", 12345, "192.0.2.20", 8080).ok());
  ASSERT_TRUE(transaction->processUri("/protocol", "GET", "HTTP/2").ok());
  ASSERT_TRUE(transaction->addRequestHeader("host", "example.test").ok());
  ASSERT_TRUE(transaction->processRequestHeaders().ok());
  expectIntervention(*transaction, 419);
}

TEST(EngineIntegrationTest, FailsClosedWhenTheEnforcedPcreMatchLimitIsExceeded) {
  constexpr char kExpensiveRegexRules[] = R"(
SecRuleEngine On
SecPcreMatchLimit 1000000
SecRule REQUEST_URI "@rx ^/(a+)+$" "id:1000005,phase:1,deny,status:403,nolog"
)";
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation =
      runtime->compile({RuleSource::inlineRules("expensive-regex.conf", kExpensiveRegexRules)}, 1);
  ASSERT_TRUE(generation.ok()) << generation.status();

  std::unique_ptr<Transaction> transaction = createTransaction(*generation);
  ASSERT_NE(transaction, nullptr);
  const absl::Status status = processRequestHeaders(
      *transaction, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!");
  EXPECT_TRUE(isPcreMatchLimitExceeded(status)) << status;
  EXPECT_EQ(status.code(), absl::StatusCode::kResourceExhausted);
}

TEST(EngineIntegrationTest, ExposesBoundedRuleIdsForInterventionLogs) {
  constexpr char kLoggedInterventionRules[] = R"(
SecRuleEngine On
SecRule REQUEST_URI "@streq /logged-block" "id:1000006,phase:1,deny,status:431,log"
)";
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto generation = runtime->compile(
      {RuleSource::inlineRules("logged-intervention.conf", kLoggedInterventionRules)});
  ASSERT_TRUE(generation.ok()) << generation.status();

  std::unique_ptr<Transaction> transaction = createTransaction(*generation);
  ASSERT_NE(transaction, nullptr);
  ASSERT_TRUE(processRequestHeaders(*transaction, "/logged-block").ok());
  auto intervention = transaction->intervention();
  ASSERT_TRUE(intervention.ok()) << intervention.status();
  ASSERT_TRUE(intervention->has_value());
  EXPECT_EQ(intervention->value().status, 431);
  EXPECT_EQ(intervention->value().rule_ids, std::vector<int64_t>({1000006}));
  EXPECT_FALSE(intervention->value().rule_ids_truncated);
}

TEST(EngineIntegrationTest, TransactionKeepsItsCompiledGenerationAlive) {
  const std::shared_ptr<Runtime> runtime = createRuntime();
  auto old_generation = runtime->compile({RuleSource::inlineRules("old.conf", kPhaseOneRules)});
  ASSERT_TRUE(old_generation.ok()) << old_generation.status();
  std::unique_ptr<Transaction> old_transaction = createTransaction(*old_generation);
  ASSERT_NE(old_transaction, nullptr);

  constexpr char kReplacementRules[] = R"(
SecRuleEngine On
SecRule REQUEST_URI "@contains /replacement" "id:1000003,phase:1,deny,status:429,nolog"
)";
  auto new_generation =
      runtime->compile({RuleSource::inlineRules("replacement.conf", kReplacementRules)});
  ASSERT_TRUE(new_generation.ok()) << new_generation.status();
  (*old_generation).reset();

  ASSERT_TRUE(processRequestHeaders(*old_transaction, "/blocked/in-flight").ok());
  expectIntervention(*old_transaction, 418);

  std::unique_ptr<Transaction> new_transaction = createTransaction(*new_generation);
  ASSERT_NE(new_transaction, nullptr);
  ASSERT_TRUE(processRequestHeaders(*new_transaction, "/blocked/in-flight").ok());
  expectNoIntervention(*new_transaction);
}

}  // namespace
}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
