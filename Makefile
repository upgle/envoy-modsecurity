.PHONY: bootstrap build-api check verify-deps

bootstrap:
	git submodule update --init --recursive --depth 1
	./tools/verify-dependency-pins.sh

verify-deps:
	./tools/verify-dependency-pins.sh

build-api: verify-deps
	bazel build //:api_bindings

check: verify-deps
	bazel build //:api_bindings
