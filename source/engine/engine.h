#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {

// Envoy-independent representation of the ordered SecLang sources in the filter proto.
struct RuleSource {
  enum class Kind { File, Inline };

  Kind kind;
  std::string name;
  std::string contents;

  static RuleSource file(std::string filename) { return {Kind::File, std::move(filename), {}}; }
  static RuleSource inlineRules(std::string name, std::string contents) {
    return {Kind::Inline, std::move(name), std::move(contents)};
  }
};

struct Intervention {
  int status{403};
  std::string redirect_url;
};

// Bounded, non-sensitive information retained from one native RuleMessage. The connector does not
// expose the free-form message, matched value, URI, addresses, or request/response contents.
struct RuleEvent {
  int64_t id{0};
  uint32_t phase{0};
  bool disruptive{false};
};

// Phase-5 result made available to the Envoy filter without enabling libmodsecurity's synchronous
// audit-file writer. Rule events are records selected by SecLang for logging, not every rule that
// evaluated or matched.
struct LoggingResult {
  static constexpr size_t MaxRuleEvents = 32;

  std::vector<RuleEvent> rules;
  bool rules_truncated{false};
  std::optional<int64_t> blocking_inbound_anomaly_score;
  std::optional<int64_t> detection_inbound_anomaly_score;
  std::optional<int64_t> inbound_anomaly_score_threshold;
  std::optional<int64_t> blocking_outbound_anomaly_score;
  std::optional<int64_t> detection_outbound_anomaly_score;
  std::optional<int64_t> outbound_anomaly_score_threshold;
};

// One instance belongs to one HTTP stream and must stay on that stream's Envoy worker.
class Transaction {
 public:
  virtual ~Transaction() = default;

  virtual absl::Status processConnection(absl::string_view client_address, uint32_t client_port,
                                         absl::string_view server_address,
                                         uint32_t server_port) = 0;
  virtual absl::Status processUri(absl::string_view uri, absl::string_view method,
                                  absl::string_view http_version) = 0;
  virtual absl::Status addRequestHeader(absl::string_view name, absl::string_view value) = 0;
  virtual absl::Status processRequestHeaders() = 0;
  virtual absl::Status appendRequestBody(absl::string_view data) = 0;
  virtual absl::Status processRequestBody() = 0;
  virtual absl::Status addResponseHeader(absl::string_view name, absl::string_view value) = 0;
  virtual absl::Status processResponseHeaders(uint32_t status, absl::string_view http_version) = 0;
  virtual absl::Status appendResponseBody(absl::string_view data) = 0;
  virtual absl::Status processResponseBody() = 0;
  virtual absl::StatusOr<LoggingResult> processLogging() = 0;
  virtual absl::StatusOr<std::optional<Intervention>> intervention() = 0;
};

// A successfully compiled generation is immutable. Its lifetime is extended by in-flight streams.
class RuleGeneration {
 public:
  virtual ~RuleGeneration() = default;

  virtual absl::StatusOr<std::unique_ptr<Transaction>> createTransaction() const = 0;
  virtual uint64_t generationId() const = 0;
  virtual uint64_t loadedRuleCount() const = 0;
  virtual uint64_t sourceCount() const = 0;
};

// One Runtime is shared by the Envoy process. Every compile creates a fresh candidate generation.
class Runtime {
 public:
  virtual ~Runtime() = default;

  virtual absl::StatusOr<std::shared_ptr<const RuleGeneration>> compile(
      const std::vector<RuleSource>& sources) = 0;
};

std::shared_ptr<Runtime> createRuntime();

}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
