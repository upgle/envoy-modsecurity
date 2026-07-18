#include "source/engine/exception.h"

#include <new>

#include "absl/status/status.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

TEST(ExceptionTest, ConvertsAllocationFailureToResourceExhausted) {
  const absl::Status status = catchLibraryExceptions("allocation test", []() -> absl::Status {
    throw std::bad_alloc();
  });

  EXPECT_EQ(status.code(), absl::StatusCode::kResourceExhausted);
  EXPECT_NE(status.message().find("allocation test"), absl::string_view::npos);
}

}  // namespace
}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
