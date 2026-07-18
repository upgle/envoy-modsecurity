#include "source/engine/engine.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"
#include "source/engine/exception.h"
#include "source/engine/rules.h"
#include "source/engine/transaction.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

void discardServerLog(void*, const void*) {}

class RuntimeImpl;

class RuleGenerationImpl final : public RuleGeneration,
                                 public std::enable_shared_from_this<RuleGenerationImpl> {
 public:
  RuleGenerationImpl(std::shared_ptr<RuntimeImpl> runtime,
                     std::shared_ptr<modsecurity::RulesSet> rules, uint64_t loaded_rule_count,
                     uint64_t source_count)
      : runtime_(std::move(runtime)),
        rules_(std::move(rules)),
        loaded_rule_count_(loaded_rule_count),
        source_count_(source_count) {}

  absl::StatusOr<std::unique_ptr<Transaction>> createTransaction() const override;
  uint64_t loadedRuleCount() const override { return loaded_rule_count_; }
  uint64_t sourceCount() const override { return source_count_; }

 private:
  // Runtime must outlive every transaction because libmodsecurity transactions retain its pointer.
  const std::shared_ptr<RuntimeImpl> runtime_;
  const std::shared_ptr<modsecurity::RulesSet> rules_;
  const uint64_t loaded_rule_count_;
  const uint64_t source_count_;
};

class RuntimeImpl final : public Runtime, public std::enable_shared_from_this<RuntimeImpl> {
 public:
  RuntimeImpl() : modsecurity_(std::make_unique<modsecurity::ModSecurity>()) {
    modsecurity_->setConnectorInformation("envoy-modsecurity v0.1.0");
    // Native synchronous server logging is deliberately disabled. Interventions and Envoy stats
    // provide bounded observability without serializing worker callbacks on a shared log sink.
    modsecurity_->setServerLogCb(discardServerLog);
  }

  absl::StatusOr<std::shared_ptr<const RuleGeneration>> compile(
      const std::vector<RuleSource>& sources, uint32_t pcre_match_limit) override {
    return catchLibraryExceptions(
        "ruleset compilation", [&]() -> absl::StatusOr<std::shared_ptr<const RuleGeneration>> {
          const absl::Status validation_status = validateRuleSources(sources);
          if (!validation_status.ok()) {
            return validation_status;
          }
          if (pcre_match_limit == 0 || pcre_match_limit > MaxPcreMatchLimit) {
            return absl::InvalidArgumentError(
                absl::StrCat("pcre_match_limit must be between 1 and ", MaxPcreMatchLimit));
          }

          auto candidate = std::make_shared<modsecurity::RulesSet>();
          const std::string cpu_guard = absl::StrCat("SecPcreMatchLimit ", pcre_match_limit, "\n");
          if (candidate->load(cpu_guard.c_str(), "<envoy-modsecurity-cpu-guard>") < 0) {
            return absl::InternalError(absl::StrCat("failed to install the PCRE match limit: ",
                                                    candidate->getParserError()));
          }
          uint64_t loaded_rule_count = 0;
          for (const RuleSource& source : sources) {
            const int loaded = source.kind == RuleSource::Kind::File
                                   ? candidate->loadFromUri(source.name.c_str())
                                   : candidate->load(source.contents.c_str(), source.name);
            if (loaded < 0) {
              return absl::InvalidArgumentError(absl::StrCat(
                  "failed to load rule source '", source.name, "': ", candidate->getParserError()));
            }
            loaded_rule_count += static_cast<uint64_t>(loaded);
          }

          return std::shared_ptr<const RuleGeneration>(new RuleGenerationImpl(
              shared_from_this(), std::move(candidate), loaded_rule_count, sources.size()));
        });
  }

  modsecurity::ModSecurity* native() const { return modsecurity_.get(); }

 private:
  std::unique_ptr<modsecurity::ModSecurity> modsecurity_;
};

absl::StatusOr<std::unique_ptr<Transaction>> RuleGenerationImpl::createTransaction() const {
  return catchLibraryExceptions(
      "transaction creation", [&]() -> absl::StatusOr<std::unique_ptr<Transaction>> {
        return std::unique_ptr<Transaction>(new TransactionImpl(
            std::make_unique<modsecurity::Transaction>(runtime_->native(), rules_.get(), nullptr),
            shared_from_this()));
      });
}

}  // namespace

std::shared_ptr<Runtime> createRuntime() { return std::make_shared<RuntimeImpl>(); }

}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
