load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

package(default_visibility = ["//visibility:public"])

# Builds the pinned ModSecurity source and its pinned libinjection/mbedtls submodules. Optional
# parsers are discovered by configure from the build image; the release image installs PCRE2 and
# YAJL development packages so CRS regular expressions and JSON request bodies are supported.
configure_make(
    name = "libmodsecurity",
    autogen = True,
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
    ],
    lib_source = "@modsecurity_source//:all",
    out_static_libs = ["libmodsecurity.a"],
    tags = [
        "nocompdb",
        "skip_on_windows",
    ],
)
