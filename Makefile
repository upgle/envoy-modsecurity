.PHONY: bootstrap build build-api check integration-test owasp-lab qualification-benchmark test verify-deps

bootstrap:
	git submodule update --init --recursive --depth 1
	./tools/verify-dependency-pins.sh

verify-deps:
	./tools/verify-dependency-pins.sh

build-api: verify-deps
	bazel build //:api_bindings

build: verify-deps
	bazel build //:envoy-modsecurity

test: verify-deps
	bazel test \
		//test/engine:exception_test \
		//test/engine:rules_test \
		//test/engine:engine_integration_test \
		//test/unit:config_test \
		//test/unit:filter_test

integration-test: verify-deps
	bazel test \
		//test/integration:filter_ecds_integration_test \
		//test/integration:envoy_http_integration_test \
		//test/integration:filter_protocol_integration_test \
		//test/integration:owasp_crs_smoke_test

owasp-lab: verify-deps
	./tools/run-owasp-crs-lab.sh

qualification-benchmark: verify-deps
	./tools/run-qualification-benchmark.sh --enforce

check: verify-deps
	bazel build //:api_bindings //source/extensions/filters/http/modsecurity:config
	bazel test \
		//test/engine:exception_test \
		//test/engine:rules_test \
		//test/engine:engine_integration_test \
		//test/integration:filter_ecds_integration_test \
		//test/integration:envoy_http_integration_test \
		//test/integration:filter_protocol_integration_test \
		//test/integration:owasp_crs_smoke_test \
		//test/unit:config_test \
		//test/unit:filter_test
