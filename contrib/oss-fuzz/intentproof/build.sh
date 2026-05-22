#!/usr/bin/env bash
# OSS-Fuzz build script for IntentProof platform fuzz targets.
#
# Intended for google/oss-fuzz/projects/intentproof/build.sh after the upstream
# project is accepted. Clones intentproof-tools, intentproof-spec, and
# intentproof-core at pinned refs, then registers native Go fuzzers.
set -euo pipefail

TOOLS_SRC="${SRC}/intentproof-tools"
SPEC_SRC="${SRC}/intentproof-spec"
CORE_SRC="${SRC}/intentproof-core"

cd "$TOOLS_SRC"
export INTENTPROOF_SPEC_DIR="$SPEC_SRC"
export GOWORK=off

compile_go_fuzzer github.com/intentproof/intentproof-tools/pkg/canon FuzzMarshalRaw fuzz_marshal_raw
compile_go_fuzzer github.com/intentproof/intentproof-tools/pkg/verifier FuzzVerify fuzz_verify
compile_go_fuzzer github.com/intentproof/intentproof-tools/pkg/bundle FuzzBundleVerify fuzz_bundle_verify
compile_go_fuzzer github.com/intentproof/intentproof-tools/pkg/policy FuzzCompile fuzz_compile

cd "$CORE_SRC"
export INTENTPROOF_SPEC_DIR="$SPEC_SRC"
compile_go_fuzzer github.com/intentproof/intentproof-core/pkg/ingest FuzzParseExecutionEvent fuzz_parse_execution_event
