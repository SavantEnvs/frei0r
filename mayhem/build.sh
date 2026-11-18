#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Upstream builds every plugin as a dlopen()ed module, but also ships a static bundle (all
# plugins + a descriptor registry, include/frei0r/bundle.h). The harness links that bundle, so the
# plugin code is instrumented and runs in-process. OpenCV plugins (facebl0r, facedetect) stay out:
# the bundle excludes shadert0y/colgate/ndvi on its own (EGL context / dlopen), OpenCV is skipped
# here to keep the image small (apt has no pinned OpenCV in the base).
CMAKE_COMMON=(-DWITHOUT_OPENCV=ON -DFREI0R_BUILD_BUNDLE=ON -DFREI0R_BUNDLE_PROFILE=all)

# 1) Test suite + known-answer probe, built with the project's NORMAL flags (clean, separate tree).
cmake -S . -B build-tests "${CMAKE_COMMON[@]}" -DBUILD_TESTING=ON \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests -j"$MAYHEM_JOBS"
# -ffp-contract=off: the answer table must not depend on FMA contraction
$CXX -O2 -ffp-contract=off $COVERAGE_FLAGS -x c "$SRC/mayhem/kat.c" -x none -Iinclude \
     build-tests/libfrei0r-bundle-static.a $(pkg-config --libs cairo gavl) -lm -lpthread \
     -o build-tests/kat

# 2) Instrumented bundle: ASan+UBSan (halting) + DWARF 3 + fuzzer coverage on every plugin.
#    CMAKE_BUILD_TYPE=None keeps upstream's asserts live (no -DNDEBUG).
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
cmake -S . -B build-fuzz "${CMAKE_COMMON[@]}" -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=None \
      -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS"
cmake --build build-fuzz -j"$MAYHEM_JOBS" --target frei0r-bundle

# 3) One harness source, one fuzzer per plugin kind (+ curves, whose string parser is the one
#    place frei0r reads structured untrusted text), each with a -standalone reproducer.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build-fuzz/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build-fuzz/lsan_off.o
LIBS=(build-fuzz/libfrei0r-bundle-static.a $(pkg-config --libs cairo gavl) -lm -lpthread)
build_target() {  # <name> <compile defs...>
  local name="$1"; shift
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -Iinclude "$@" -c mayhem/fuzz_frei0r.c -o "build-fuzz/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build-fuzz/$name.o" build-fuzz/lsan_off.o \
       "${LIBS[@]}" -o "/mayhem/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "build-fuzz/$name.o" build-fuzz/standalone_main.o \
       build-fuzz/lsan_off.o "${LIBS[@]}" -o "/mayhem/$name-standalone"
}
build_target frei0r_filter -DFUZZ_KIND=F0R_PLUGIN_TYPE_FILTER
build_target frei0r_source -DFUZZ_KIND=F0R_PLUGIN_TYPE_SOURCE
build_target frei0r_mixer2 -DFUZZ_KIND=F0R_PLUGIN_TYPE_MIXER2
build_target frei0r_mixer3 -DFUZZ_KIND=F0R_PLUGIN_TYPE_MIXER3
build_target frei0r_curves -DFUZZ_KIND=F0R_PLUGIN_TYPE_FILTER '-DFUZZ_ONLY_PLUGIN="curves"'
