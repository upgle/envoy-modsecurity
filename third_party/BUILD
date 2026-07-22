load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("@bazel_skylib//lib:selects.bzl", "selects")

package(default_visibility = ["//visibility:public"])

# These opt-in settings keep benchmark-only profile flags out of normal project builds. The Linux
# comparison script owns the stable profile paths used by the foreign build.
config_setting(
    name = "linux",
    constraint_values = ["@platforms//os:linux"],
    visibility = ["//visibility:private"],
)

config_setting(
    name = "modsecurity_benchmark_pgo_instrument",
    define_values = {"modsecurity_benchmark_pgo": "instrument"},
    visibility = ["//visibility:private"],
)

config_setting(
    name = "modsecurity_benchmark_pgo_use",
    define_values = {"modsecurity_benchmark_pgo": "use"},
    visibility = ["//visibility:private"],
)

selects.config_setting_group(
    name = "linux_modsecurity_benchmark_pgo_instrument",
    match_all = [
        ":linux",
        ":modsecurity_benchmark_pgo_instrument",
    ],
    visibility = ["//visibility:private"],
)

selects.config_setting_group(
    name = "linux_modsecurity_benchmark_pgo_use",
    match_all = [
        ":linux",
        ":modsecurity_benchmark_pgo_use",
    ],
    visibility = ["//visibility:private"],
)

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

# Builds the pinned ModSecurity source and its pinned libinjection/mbedtls submodules. Structured
# request-body parsers are mandatory: configure must fail instead of silently producing a reduced
# libmodsecurity when YAJL or LibXML2 is unavailable.
configure_make(
    name = "libmodsecurity",
    autogen = True,
    autogen_command = "build.sh",
    build_data = [
        "//bazel:apply-libmodsecurity-patch.sh",
        "//bazel:libmodsecurity-set-var-nonthrow.patch",
    ],
    configure_prefix = "bash $(execpath //bazel:apply-libmodsecurity-patch.sh) $(execpath //bazel:libmodsecurity-set-var-nonthrow.patch)",
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
            "--with-libxml=/opt/homebrew/opt/libxml2",
            "--with-pcre2=/opt/homebrew/opt/pcre2",
            "--with-yajl=/opt/homebrew/opt/yajl",
            "ARFLAGS=cr",
            "AR_FLAGS=cr",
            "RANLIB=/usr/bin/ranlib",
        ],
        "//conditions:default": [
            "--with-libxml=yes",
            "--with-yajl=yes",
        ],
    }),
    # On Darwin, let configure discover /usr/bin/ar because Bazel's static-link tool is libtool.
    env = select({
        ":linux_modsecurity_benchmark_pgo_instrument": {
            "CFLAGS": "-flto=thin -fprofile-generate=/build/waf-comparison-pgo/raw",
            "CXXFLAGS": "-flto=thin -fprofile-generate=/build/waf-comparison-pgo/raw",
            "LDFLAGS": "-flto=thin -fprofile-generate=/build/waf-comparison-pgo/raw",
            "PKG_CONFIG_PATH": "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig",
        },
        ":linux_modsecurity_benchmark_pgo_use": {
            "CFLAGS": "-flto=thin -fprofile-use=/build/waf-comparison-pgo/waf-comparison.profdata -Wno-profile-instr-unprofiled -Wno-profile-instr-out-of-date",
            "CXXFLAGS": "-flto=thin -fprofile-use=/build/waf-comparison-pgo/waf-comparison.profdata -Wno-profile-instr-unprofiled -Wno-profile-instr-out-of-date",
            "LDFLAGS": "-flto=thin -fprofile-use=/build/waf-comparison-pgo/waf-comparison.profdata",
            "PKG_CONFIG_PATH": "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig",
        },
        "@platforms//os:linux": {
            # rules_foreign_cc builds pkg-config with an isolated prefix, so it does not discover
            # Debian's system package metadata by default. The pinned CI image is linux/amd64.
            "PKG_CONFIG_PATH": "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig",
        },
        "@platforms//os:macos": {
            "AR": "",
            # Homebrew's keg-only LibXML2 pkg-config file has a private zlib requirement. The
            # foreign_cc pkg-config wrapper needs Homebrew's deployment-target metadata to resolve
            # that requirement during the mandatory configure check.
            "PKG_CONFIG_PATH": "/opt/homebrew/Library/Homebrew/os/mac/pkgconfig/10.15",
        },
        "//conditions:default": {},
    }),
    lib_source = "@modsecurity_source//:all",
    # libmodsecurity.a intentionally remains a static archive, so its system-library dependencies
    # must be propagated to every Bazel consumer.
    linkopts = select({
        "@platforms//os:linux": [
            "-lxml2",
            "-lpcre2-8",
            "-lyajl",
        ],
        "@platforms//os:macos": [
            "-L/opt/homebrew/opt/libxml2/lib",
            "-L/opt/homebrew/opt/yajl/lib",
            "-L/opt/homebrew/opt/pcre2/lib",
            "-lxml2",
            "-lpcre2-8",
            "-lyajl",
        ],
        "//conditions:default": ["-lpcre2-8"],
    }),
    out_static_libs = ["libmodsecurity.a"],
    tags = [
        "nocompdb",
        "skip_on_windows",
    ],
)
