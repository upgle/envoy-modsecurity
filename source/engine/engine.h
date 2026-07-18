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
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {

inline constexpr uint32_t DefaultPcreMatchLimit = 1000;
inline constexpr uint32_t MaxPcreMatchLimit = 1000000;
inline constexpr size_t MaxInterventionRuleIds = 8;
inline constexpr absl::string_view PcreMatchLimitStatusPrefix =
    "libmodsecurity PCRE match limit exceeded during ";

inline absl::Status pcreMatchLimitExceededStatus(absl::string_view operation) {
  return absl::ResourceExhaustedError(absl::StrCat(PcreMatchLimitStatusPrefix, operation));
}

inline bool isPcreMatchLimitExceeded(const absl::Status& status) {
  return status.code() == absl::StatusCode::kResourceExhausted &&
         absl::StartsWith(status.message(), PcreMatchLimitStatusPrefix);
}

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
  std::vector<int64_t> rule_ids;
  bool rule_ids_truncated{false};
};

// One instance belongs to one HTTP stream and must stay on that stream's Envoy worker.
class Transaction {
 public:
  virtual ~Transaction() = default;

  virtual absl::Status processConnection(absl::string_view client_address, uint32_t client_port,
                                         absl::string_view server_address,
                                         uint32_t server_port) = 0;
  // Protocol values use Envoy's canonical "HTTP/<version>" representation on both paths. The
  // native adapter owns any libmodsecurity-specific normalization.
  virtual absl::Status processUri(absl::string_view uri, absl::string_view method,
                                  absl::string_view http_protocol) = 0;
  virtual absl::Status addRequestHeader(absl::string_view name, absl::string_view value) = 0;
  virtual absl::Status processRequestHeaders() = 0;
  virtual absl::Status appendRequestBody(absl::string_view data) = 0;
  virtual absl::Status processRequestBody() = 0;
  virtual absl::Status addResponseHeader(absl::string_view name, absl::string_view value) = 0;
  virtual absl::Status processResponseHeaders(uint32_t status, absl::string_view http_protocol) = 0;
  // Called after response headers have been processed. False means libmodsecurity would skip the
  // response-body phase because SecResponseBodyAccess is disabled or the response MIME type is not
  // selected by SecResponseBodyMimeType.
  virtual absl::StatusOr<bool> shouldInspectResponseBody() const = 0;
  virtual absl::Status appendResponseBody(absl::string_view data) = 0;
  virtual absl::Status processResponseBody() = 0;
  virtual absl::Status processLogging() = 0;
  virtual absl::StatusOr<std::optional<Intervention>> intervention() = 0;
};

// A successfully compiled generation is immutable. Its lifetime is extended by in-flight streams.
class RuleGeneration {
 public:
  virtual ~RuleGeneration() = default;

  virtual absl::StatusOr<std::unique_ptr<Transaction>> createTransaction() const = 0;
  virtual uint64_t loadedRuleCount() const = 0;
  virtual uint64_t sourceCount() const = 0;
};

// One Runtime is shared by the Envoy process. Every compile creates a fresh candidate generation.
class Runtime {
 public:
  virtual ~Runtime() = default;

  virtual absl::StatusOr<std::shared_ptr<const RuleGeneration>> compile(
      const std::vector<RuleSource>& sources,
      uint32_t pcre_match_limit = DefaultPcreMatchLimit) = 0;
};

std::shared_ptr<Runtime> createRuntime();

}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
