#include "source/engine/rules.h"

#include <filesystem>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/strip.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurityFilter {
namespace Engine {
namespace {

// Inline rules arrive over xDS and therefore use a deliberately narrow initial capability set.
// The check is conservative: a false positive must be resolved by moving the trusted rule into the
// read-only image rather than weakening the data-plane policy.
constexpr absl::string_view UnsafeInlineDirectives[] = {
    "include",       "secremoterules",    "secrulescript", "secdebuglog",
    "secauditlog",   "secuploaddir",      "secuploadkeepfiles",
    "sectmpdir",     "secdatadir",
};

constexpr absl::string_view UnsafeInlineFragments[] = {
    "@inspectfile",     "exec:",            "initcol:",         "setuid",
    "setsid",           "setrsc",           "setvar:global.",   "setvar:ip.",
    "setvar:resource.", "setvar:session.", "setvar:user.",
};

bool isHorizontalWhitespace(char character) {
  return character == ' ' || character == '\t' || character == '\r' || character == '\f' ||
         character == '\v';
}

void appendNormalizedSpace(std::string& line) {
  if (!line.empty() && line.back() != ' ') {
    line.push_back(' ');
  }
}

std::optional<absl::string_view> unsafeInlineCapability(absl::string_view line) {
  line = absl::StripAsciiWhitespace(line);
  if (line.empty()) {
    return std::nullopt;
  }

  const size_t separator = line.find(' ');
  const absl::string_view directive = line.substr(0, separator);
  for (const absl::string_view unsafe_directive : UnsafeInlineDirectives) {
    if (absl::EqualsIgnoreCase(directive, unsafe_directive)) {
      return unsafe_directive;
    }
  }

  if (absl::EqualsIgnoreCase(directive, "secxmlexternalentity") &&
      separator != absl::string_view::npos) {
    absl::string_view argument = absl::StripAsciiWhitespace(line.substr(separator + 1));
    const size_t argument_end = argument.find(' ');
    if (absl::EqualsIgnoreCase(argument.substr(0, argument_end), "on")) {
      return "secxmlexternalentity on";
    }
  }

  for (const absl::string_view unsafe_fragment : UnsafeInlineFragments) {
    if (absl::StrContainsIgnoreCase(line, unsafe_fragment)) {
      return unsafe_fragment;
    }
  }
  return std::nullopt;
}

absl::Status validateNormalizedInlineLine(const RuleSource& source, absl::string_view line) {
  const std::optional<absl::string_view> capability = unsafeInlineCapability(line);
  if (!capability.has_value()) {
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError(
      absl::StrCat("inline rule source '", source.name,
                   "' uses a capability disabled by the initial safe profile: ", *capability));
}

absl::Status validateInlineSource(const RuleSource& source) {
  if (source.contents.find('\0') != std::string::npos) {
    return absl::InvalidArgumentError(
        absl::StrCat("inline rule source '", source.name, "' contains an embedded NUL byte"));
  }

  std::string normalized_line;
  char quote = '\0';
  bool escaped = false;
  bool comment = false;
  for (size_t index = 0; index < source.contents.size(); ++index) {
    const char character = source.contents[index];

    if (comment) {
      if (character == '\n') {
        comment = false;
        const absl::Status status = validateNormalizedInlineLine(source, normalized_line);
        if (!status.ok()) {
          return status;
        }
        normalized_line.clear();
      }
      continue;
    }

    if (escaped) {
      normalized_line.push_back(character);
      escaped = false;
      continue;
    }

    if (character == '\\') {
      const bool line_feed_continuation =
          index + 1 < source.contents.size() && source.contents[index + 1] == '\n';
      const bool crlf_continuation =
          index + 2 < source.contents.size() && source.contents[index + 1] == '\r' &&
          source.contents[index + 2] == '\n';
      if (line_feed_continuation || crlf_continuation) {
        index += crlf_continuation ? 2 : 1;
      } else {
        normalized_line.push_back(character);
        escaped = true;
      }
      continue;
    }

    if (quote != '\0') {
      normalized_line.push_back(character);
      if (character == quote) {
        quote = '\0';
      } else if (character == '\n') {
        return absl::InvalidArgumentError(
            absl::StrCat("inline rule source '", source.name,
                         "' contains an unterminated quoted value"));
      }
      continue;
    }

    if (character == '"' || character == '\'') {
      quote = character;
      normalized_line.push_back(character);
    } else if (character == '#') {
      comment = true;
    } else if (character == '\n') {
      const absl::Status status = validateNormalizedInlineLine(source, normalized_line);
      if (!status.ok()) {
        return status;
      }
      normalized_line.clear();
    } else if (isHorizontalWhitespace(character)) {
      appendNormalizedSpace(normalized_line);
    } else {
      normalized_line.push_back(character);
    }
  }

  if (quote != '\0') {
    return absl::InvalidArgumentError(
        absl::StrCat("inline rule source '", source.name,
                     "' contains an unterminated quoted value"));
  }
  if (escaped) {
    return absl::InvalidArgumentError(
        absl::StrCat("inline rule source '", source.name, "' ends with an incomplete escape"));
  }
  return validateNormalizedInlineLine(source, normalized_line);
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

  uint64_t total_inline_rule_bytes = 0;
  for (const RuleSource& source : sources) {
    if (source.name.empty()) {
      return absl::InvalidArgumentError("rule source name must not be empty");
    }
    if (source.name.find('\0') != std::string::npos) {
      return absl::InvalidArgumentError("rule source name must not contain an embedded NUL byte");
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
    if (source.contents.size() > MaxTotalInlineRuleBytes - total_inline_rule_bytes) {
      return absl::InvalidArgumentError(
          absl::StrCat("total inline rule content exceeds ", MaxTotalInlineRuleBytes, " bytes"));
    }
    total_inline_rule_bytes += source.contents.size();
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
