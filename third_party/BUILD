load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

package(default_visibility = ["//visibility:public"])

# Keep the pinned CRS inputs available to black-box tests without copying the
# third-party distribution into project-owned fixtures.
filegroup(
    name = "owasp_crs_rules",
    srcs = glob(["coreruleset/rules/*.conf"]),
)

filegroup(
    name = "owasp_crs_rules_marker",
    srcs = ["coreruleset/rules/REQUEST-901-INITIALIZATION.conf"],
)

filegroup(
    name = "owasp_crs_setup",
    srcs = ["coreruleset/crs-setup.conf.example"],
)

filegroup(
    name = "modsecurity_unicode_mapping",
    srcs = ["modsecurity/unicode.mapping"],
)

# Builds the pinned ModSecurity source and its pinned libinjection/mbedtls submodules. Optional
# parsers are discovered by configure from the build image; the release image installs PCRE2 and
# YAJL development packages so CRS regular expressions and JSON request bodies are supported.
configure_make(
    name = "libmodsecurity",
    autogen = True,
    autogen_command = "build.sh",
    configure_in_place = True,
    configure_options = [
        "--disable-shared",
        "--enable-static",
        "--without-curl",
        "--without-geoip",
        "--without-lmdb",
        "--without-lua",
        "--without-maxmind",
        "--without-ssdeep",
    ] + select({
        "@platforms//os:macos": [
            "--with-pcre2=/opt/homebrew/opt/pcre2",
            "ARFLAGS=cr",
            "AR_FLAGS=cr",
            "RANLIB=/usr/bin/ranlib",
        ],
        "//conditions:default": [],
    }),
    # On Darwin, let configure discover /usr/bin/ar because Bazel's static-link tool is libtool.
    env = select({
        "@platforms//os:macos": {"AR": ""},
        "//conditions:default": {},
    }),
    lib_source = "@modsecurity_source//:all",
    # libmodsecurity.a intentionally remains a static archive, so its system-library dependencies
    # must be propagated to every Bazel consumer.
    linkopts = select({
        "@platforms//os:linux": [
            "-lpcre2-8",
            "-lyajl",
        ],
        "@platforms//os:macos": [
            "-L/opt/homebrew/opt/pcre2/lib",
            "-lpcre2-8",
        ],
        "//conditions:default": ["-lpcre2-8"],
    }),
    out_static_libs = ["libmodsecurity.a"],
    tags = [
        "nocompdb",
        "skip_on_windows",
    ],
)
