#pragma once

#include <exception>
#include <new>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {

// Converts exceptions crossing the native library boundary into the Status/StatusOr return type
// produced by callback. libmodsecurity normally reports integer errors, but allocation and parser
// internals may still throw C++ exceptions.
template <class Callback>
auto catchLibraryExceptions(absl::string_view operation,
                            Callback&& callback) -> decltype(callback()) {
  try {
    return std::forward<Callback>(callback)();
  } catch (const std::bad_alloc&) {
    return absl::ResourceExhaustedError(
        absl::StrCat("libmodsecurity exhausted memory in ", operation));
  } catch (const std::exception& error) {
    return absl::InternalError(
        absl::StrCat("libmodsecurity threw in ", operation, ": ", error.what()));
  } catch (...) {
    return absl::InternalError(absl::StrCat("libmodsecurity threw in ", operation));
  }
}

}  // namespace Engine
}  // namespace ModSecurityFilter
}  // namespace HttpFilters
}  // namespace Extensions
}  // namespace Envoy
