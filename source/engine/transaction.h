#pragma once

#include <memory>

#include "source/engine/engine.h"

namespace modsecurity {
class Transaction;
}

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {

class TransactionImpl final : public Transaction {
public:
  explicit TransactionImpl(std::unique_ptr<modsecurity::Transaction> transaction);
  ~TransactionImpl() override;

  absl::Status processConnection(absl::string_view client_address, uint32_t client_port,
                                 absl::string_view server_address,
                                 uint32_t server_port) override;
  absl::Status processUri(absl::string_view uri, absl::string_view method,
                          absl::string_view http_version) override;
  absl::Status addRequestHeader(absl::string_view name, absl::string_view value) override;
  absl::Status processRequestHeaders() override;
  absl::Status appendRequestBody(absl::string_view data) override;
  absl::Status processRequestBody() override;
  absl::Status addResponseHeader(absl::string_view name, absl::string_view value) override;
  absl::Status processResponseHeaders(uint32_t status,
                                      absl::string_view http_version) override;
  absl::Status appendResponseBody(absl::string_view data) override;
  absl::Status processResponseBody() override;
  absl::Status processLogging() override;
  absl::StatusOr<std::optional<Intervention>> intervention() override;

private:
  std::unique_ptr<modsecurity::Transaction> transaction_;
};

} // namespace Engine
} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
