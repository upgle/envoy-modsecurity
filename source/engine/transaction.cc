#include "source/engine/transaction.h"

#include <algorithm>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "modsecurity/intervention.h"
#include "modsecurity/rule_message.h"
#include "modsecurity/transaction.h"
#include "source/engine/exception.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

template <class Callback>
absl::Status call(absl::string_view operation, Callback&& callback) {
  return catchLibraryExceptions(operation, [&]() -> absl::Status {
    if (callback() == 1) {
      return absl::OkStatus();
    }
    return absl::InternalError(absl::StrCat("libmodsecurity operation failed: ", operation));
  });
}

class NativeIntervention {
 public:
  NativeIntervention() { modsecurity::intervention::clean(&value_); }
  ~NativeIntervention() { modsecurity::intervention::free(&value_); }

  modsecurity::ModSecurityIntervention* get() { return &value_; }
  const modsecurity::ModSecurityIntervention& value() const { return value_; }

 private:
  modsecurity::ModSecurityIntervention value_;
};

struct TransactionKeys {
  const std::string blocking_inbound_anomaly_score{"blocking_inbound_anomaly_score"};
  const std::string detection_inbound_anomaly_score{"detection_inbound_anomaly_score"};
  const std::string inbound_anomaly_score_threshold{"inbound_anomaly_score_threshold"};
  const std::string blocking_outbound_anomaly_score{"blocking_outbound_anomaly_score"};
  const std::string detection_outbound_anomaly_score{"detection_outbound_anomaly_score"};
  const std::string outbound_anomaly_score_threshold{"outbound_anomaly_score_threshold"};
};

const TransactionKeys& transactionKeys() {
  static const TransactionKeys keys;
  return keys;
}

std::optional<int64_t> transactionInteger(const modsecurity::Transaction& transaction,
                                          const std::string& name) {
  const std::unique_ptr<std::string> value =
      transaction.m_collections.m_tx_collection->resolveFirst(name);
  int64_t parsed = 0;
  if (value == nullptr || !absl::SimpleAtoi(*value, &parsed)) {
    return std::nullopt;
  }
  return parsed;
}

LoggingResult loggingResult(const modsecurity::Transaction& transaction) {
  const TransactionKeys& keys = transactionKeys();
  LoggingResult result;
  result.rules.reserve(std::min(transaction.m_rulesMessages.size(), LoggingResult::MaxRuleEvents));
  for (const modsecurity::RuleMessage& message : transaction.m_rulesMessages) {
    if (result.rules.size() == LoggingResult::MaxRuleEvents) {
      result.rules_truncated = true;
      break;
    }
    result.rules.push_back({message.m_rule.m_ruleId, static_cast<uint32_t>(message.getPhase()),
                            message.m_isDisruptive});
  }

  result.blocking_inbound_anomaly_score =
      transactionInteger(transaction, keys.blocking_inbound_anomaly_score);
  result.detection_inbound_anomaly_score =
      transactionInteger(transaction, keys.detection_inbound_anomaly_score);
  result.inbound_anomaly_score_threshold =
      transactionInteger(transaction, keys.inbound_anomaly_score_threshold);
  result.blocking_outbound_anomaly_score =
      transactionInteger(transaction, keys.blocking_outbound_anomaly_score);
  result.detection_outbound_anomaly_score =
      transactionInteger(transaction, keys.detection_outbound_anomaly_score);
  result.outbound_anomaly_score_threshold =
      transactionInteger(transaction, keys.outbound_anomaly_score_threshold);
  return result;
}

}  // namespace

TransactionImpl::TransactionImpl(std::unique_ptr<modsecurity::Transaction> transaction,
                                 std::shared_ptr<const RuleGeneration> generation)
    : generation_(std::move(generation)), transaction_(std::move(transaction)) {}

TransactionImpl::~TransactionImpl() = default;

absl::Status TransactionImpl::processConnection(absl::string_view client_address,
                                                uint32_t client_port,
                                                absl::string_view server_address,
                                                uint32_t server_port) {
  return call("processConnection", [&] {
    const std::string client(client_address);
    const std::string server(server_address);
    return transaction_->processConnection(client.c_str(), static_cast<int>(client_port),
                                           server.c_str(), static_cast<int>(server_port));
  });
}

absl::Status TransactionImpl::processUri(absl::string_view uri, absl::string_view method,
                                         absl::string_view http_version) {
  return call("processURI", [&] {
    const std::string uri_string(uri);
    const std::string method_string(method);
    const std::string version_string(http_version);
    return transaction_->processURI(uri_string.c_str(), method_string.c_str(),
                                    version_string.c_str());
  });
}

absl::Status TransactionImpl::addRequestHeader(absl::string_view name, absl::string_view value) {
  return call("addRequestHeader", [&] {
    return transaction_->addRequestHeader(
        reinterpret_cast<const unsigned char*>(name.data()), name.size(),
        reinterpret_cast<const unsigned char*>(value.data()), value.size());
  });
}

absl::Status TransactionImpl::processRequestHeaders() {
  return call("processRequestHeaders", [&] { return transaction_->processRequestHeaders(); });
}

absl::Status TransactionImpl::appendRequestBody(absl::string_view data) {
  return call("appendRequestBody", [&] {
    return transaction_->appendRequestBody(reinterpret_cast<const unsigned char*>(data.data()),
                                           data.size());
  });
}

absl::Status TransactionImpl::processRequestBody() {
  return call("processRequestBody", [&] { return transaction_->processRequestBody(); });
}

absl::Status TransactionImpl::addResponseHeader(absl::string_view name, absl::string_view value) {
  return call("addResponseHeader", [&] {
    return transaction_->addResponseHeader(
        reinterpret_cast<const unsigned char*>(name.data()), name.size(),
        reinterpret_cast<const unsigned char*>(value.data()), value.size());
  });
}

absl::Status TransactionImpl::processResponseHeaders(uint32_t status,
                                                     absl::string_view http_version) {
  return call("processResponseHeaders", [&] {
    const std::string version(http_version);
    return transaction_->processResponseHeaders(static_cast<int>(status), version);
  });
}

absl::Status TransactionImpl::appendResponseBody(absl::string_view data) {
  return call("appendResponseBody", [&] {
    return transaction_->appendResponseBody(reinterpret_cast<const unsigned char*>(data.data()),
                                            data.size());
  });
}

absl::Status TransactionImpl::processResponseBody() {
  return call("processResponseBody", [&] { return transaction_->processResponseBody(); });
}

absl::StatusOr<LoggingResult> TransactionImpl::processLogging() {
  return catchLibraryExceptions("processLogging", [&]() -> absl::StatusOr<LoggingResult> {
    if (transaction_->processLogging() != 1) {
      return absl::InternalError("libmodsecurity operation failed: processLogging");
    }
    return loggingResult(*transaction_);
  });
}

absl::StatusOr<std::optional<Intervention>> TransactionImpl::intervention() {
  return catchLibraryExceptions("intervention check",
                                [&]() -> absl::StatusOr<std::optional<Intervention>> {
                                  // The transaction is stream-confined. Reading the pending flag
                                  // avoids initializing and freeing an intervention structure on
                                  // the overwhelmingly common non-disruptive path.
                                  if (!transaction_->m_it.disruptive) {
                                    return std::nullopt;
                                  }
                                  NativeIntervention native;
                                  if (!transaction_->intervention(native.get())) {
                                    return std::nullopt;
                                  }

                                  Intervention result;
                                  result.status = native.value().status;
                                  if (native.value().url != nullptr) {
                                    result.redirect_url = native.value().url;
                                  }
                                  return result;
                                });
}

}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
