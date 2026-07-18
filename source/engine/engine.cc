#include "source/engine/engine.h"

#include <atomic>
#include <memory>
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
                     uint64_t source_count, uint64_t generation_id)
      : runtime_(std::move(runtime)),
        rules_(std::move(rules)),
        loaded_rule_count_(loaded_rule_count),
        source_count_(source_count),
        generation_id_(generation_id) {}

  absl::StatusOr<std::unique_ptr<Transaction>> createTransaction() const override;
  uint64_t generationId() const override { return generation_id_; }
  uint64_t loadedRuleCount() const override { return loaded_rule_count_; }
  uint64_t sourceCount() const override { return source_count_; }

 private:
  // Runtime must outlive every transaction because libmodsecurity transactions retain its pointer.
  const std::shared_ptr<RuntimeImpl> runtime_;
  const std::shared_ptr<modsecurity::RulesSet> rules_;
  const uint64_t loaded_rule_count_;
  const uint64_t source_count_;
  const uint64_t generation_id_;
};

class RuntimeImpl final : public Runtime, public std::enable_shared_from_this<RuntimeImpl> {
 public:
  RuntimeImpl() : modsecurity_(std::make_unique<modsecurity::ModSecurity>()) {
    modsecurity_->setConnectorInformation("envoy-modsecurity v0.1.0");
    // Native synchronous server logging is deliberately disabled. Structured stream metadata and
    // Envoy stats provide bounded observability without a shared log sink in worker callbacks.
    modsecurity_->setServerLogCb(discardServerLog);
  }

  absl::StatusOr<std::shared_ptr<const RuleGeneration>> compile(
      const std::vector<RuleSource>& sources) override {
    return catchLibraryExceptions(
        "ruleset compilation", [&]() -> absl::StatusOr<std::shared_ptr<const RuleGeneration>> {
          const absl::Status validation_status = validateRuleSources(sources);
          if (!validation_status.ok()) {
            return validation_status;
          }

          auto candidate = std::make_shared<modsecurity::RulesSet>();
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
              shared_from_this(), std::move(candidate), loaded_rule_count, sources.size(),
              next_generation_id_.fetch_add(1, std::memory_order_relaxed)));
        });
  }

  modsecurity::ModSecurity* native() const { return modsecurity_.get(); }

 private:
  std::unique_ptr<modsecurity::ModSecurity> modsecurity_;
  std::atomic<uint64_t> next_generation_id_{1};
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
