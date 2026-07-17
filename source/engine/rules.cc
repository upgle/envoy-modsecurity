#include "source/engine/rules.h"

#include <filesystem>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

// Inline rules arrive over xDS and therefore use a deliberately narrow initial capability set.
// The check is conservative: a false positive must be resolved by moving the trusted rule into the
// read-only image rather than weakening the data-plane policy.
constexpr absl::string_view UnsafeInlineTokens[] = {
    "include",          "secremoterules", "secrulescript", "secdebuglog",
    "secauditlog",      "secuploaddir",   "secuploadkeepfiles",
    "sectmpdir",        "secdatadir",     "@inspectfile",  "exec:",
    "initcol:",         "setuid",         "setsid",        "setrsc",
    "setvar:global.",   "setvar:ip.",      "setvar:resource.",
    "setvar:session.",  "setvar:user.",    "secxmlexternalentity on",
};

std::string withoutCommentsAndLowercase(absl::string_view rules) {
  std::string normalized;
  normalized.reserve(rules.size());
  bool in_comment = false;
  for (const char character : rules) {
    if (character == '\n') {
      in_comment = false;
      normalized.push_back(character);
      continue;
    }
    if (!in_comment && character == '#') {
      in_comment = true;
      continue;
    }
    if (!in_comment) {
      normalized.push_back(absl::ascii_tolower(character));
    }
  }
  return normalized;
}

absl::Status validateInlineSource(const RuleSource& source) {
  const std::string normalized = withoutCommentsAndLowercase(source.contents);
  for (const absl::string_view token : UnsafeInlineTokens) {
    if (absl::StrContains(normalized, token)) {
      return absl::InvalidArgumentError(
          absl::StrCat("inline rule source '", source.name,
                       "' uses a capability disabled by the initial safe profile: ", token));
    }
  }
  return absl::OkStatus();
}

absl::Status validateFileSource(const RuleSource& source) {
  try {
    const std::filesystem::path path(source.name);
    if (!path.is_absolute()) {
      return absl::InvalidArgumentError(
          absl::StrCat("rule filename must be absolute: ", source.name));
    }
    if (!std::filesystem::is_regular_file(path)) {
      return absl::InvalidArgumentError(
          absl::StrCat("rule filename is not a regular file: ", source.name));
    }
  } catch (const std::filesystem::filesystem_error& error) {
    return absl::InvalidArgumentError(
        absl::StrCat("cannot inspect rule filename '", source.name, "': ", error.what()));
  }
  return absl::OkStatus();
}

} // namespace

absl::Status validateRuleSources(const std::vector<RuleSource>& sources) {
  if (sources.empty()) {
    return absl::InvalidArgumentError("at least one rule source is required");
  }

  for (const RuleSource& source : sources) {
    if (source.name.empty()) {
      return absl::InvalidArgumentError("rule source name must not be empty");
    }
    if (source.kind == RuleSource::Kind::File) {
      const absl::Status status = validateFileSource(source);
      if (!status.ok()) {
        return status;
      }
      continue;
    }
    if (source.contents.empty()) {
      return absl::InvalidArgumentError(
          absl::StrCat("inline rule source '", source.name, "' must not be empty"));
    }
    const absl::Status status = validateInlineSource(source);
    if (!status.ok()) {
      return status;
    }
  }
  return absl::OkStatus();
}

} // namespace Engine
} // namespace ModSecurityFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
