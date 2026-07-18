#include "source/engine/transaction.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "modsecurity/intervention.h"
#include "modsecurity/transaction.h"
#include "source/engine/exception.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

template <class Callback>
absl::Status callNativeOperation(absl::string_view operation, Callback&& callback) {
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

}  // namespace

TransactionImpl::TransactionImpl(std::unique_ptr<modsecurity::Transaction> transaction,
                                 std::shared_ptr<const RuleGeneration> generation)
    : generation_(std::move(generation)), transaction_(std::move(transaction)) {}

TransactionImpl::~TransactionImpl() = default;

absl::Status TransactionImpl::processConnection(absl::string_view client_address,
                                                uint32_t client_port,
                                                absl::string_view server_address,
                                                uint32_t server_port) {
  return callNativeOperation("processConnection", [&] {
    const std::string client(client_address);
    const std::string server(server_address);
    return transaction_->processConnection(client.c_str(), static_cast<int>(client_port),
                                           server.c_str(), static_cast<int>(server_port));
  });
}

absl::Status TransactionImpl::processUri(absl::string_view uri, absl::string_view method,
                                         absl::string_view http_protocol) {
  return callNativeOperation("processURI", [&] {
    const std::string uri_string(uri);
    const std::string method_string(method);
    constexpr absl::string_view protocol_prefix = "HTTP/";
    if (absl::StartsWith(http_protocol, protocol_prefix)) {
      http_protocol.remove_prefix(protocol_prefix.size());
    }
    const std::string version_string(http_protocol);
    return transaction_->processURI(uri_string.c_str(), method_string.c_str(),
                                    version_string.c_str());
  });
}

absl::Status TransactionImpl::addRequestHeader(absl::string_view name, absl::string_view value) {
  return callNativeOperation("addRequestHeader", [&] {
    return transaction_->addRequestHeader(
        reinterpret_cast<const unsigned char*>(name.data()), name.size(),
        reinterpret_cast<const unsigned char*>(value.data()), value.size());
  });
}

absl::Status TransactionImpl::processRequestHeaders() {
  return callNativeOperation("processRequestHeaders",
                             [&] { return transaction_->processRequestHeaders(); });
}

absl::Status TransactionImpl::appendRequestBody(absl::string_view data) {
  return callNativeOperation("appendRequestBody", [&] {
    return transaction_->appendRequestBody(reinterpret_cast<const unsigned char*>(data.data()),
                                           data.size());
  });
}

absl::Status TransactionImpl::processRequestBody() {
  return callNativeOperation("processRequestBody",
                             [&] { return transaction_->processRequestBody(); });
}

absl::Status TransactionImpl::addResponseHeader(absl::string_view name, absl::string_view value) {
  return callNativeOperation("addResponseHeader", [&] {
    return transaction_->addResponseHeader(
        reinterpret_cast<const unsigned char*>(name.data()), name.size(),
        reinterpret_cast<const unsigned char*>(value.data()), value.size());
  });
}

absl::Status TransactionImpl::processResponseHeaders(uint32_t status,
                                                     absl::string_view http_protocol) {
  return callNativeOperation("processResponseHeaders", [&] {
    const std::string protocol(http_protocol);
    return transaction_->processResponseHeaders(static_cast<int>(status), protocol);
  });
}

absl::Status TransactionImpl::appendResponseBody(absl::string_view data) {
  return callNativeOperation("appendResponseBody", [&] {
    return transaction_->appendResponseBody(reinterpret_cast<const unsigned char*>(data.data()),
                                            data.size());
  });
}

absl::Status TransactionImpl::processResponseBody() {
  return callNativeOperation("processResponseBody",
                             [&] { return transaction_->processResponseBody(); });
}

absl::Status TransactionImpl::processLogging() {
  return callNativeOperation("processLogging", [&] { return transaction_->processLogging(); });
}

absl::StatusOr<std::optional<Intervention>> TransactionImpl::intervention() {
  return catchLibraryExceptions("intervention check",
                                [&]() -> absl::StatusOr<std::optional<Intervention>> {
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
