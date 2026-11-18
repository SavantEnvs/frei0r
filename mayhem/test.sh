#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# 1) Known-answer probe (mayhem/kat.c): every bundled plugin is run through the frei0r ABI on fixed
#    parameters/frames and its output hash is compared, line by line, with mayhem/kat.expected. The
#    comparison happens here in bash, so a probe that exits 0 without computing anything (or a plugin
#    that computes something else) fails: missing/changed lines count as failed tests.
KAT=build-tests/kat
EXPECTED=mayhem/kat.expected
[ -x "$KAT" ] || { echo "$KAT missing: mayhem/build.sh builds it" >&2; emit_ctrf "frei0r-kat" 0 1 0; exit 1; }
ACTUAL=$(mktemp)
"$KAT" > "$ACTUAL" 2>/dev/null
kat_total=$(wc -l < "$EXPECTED")
kat_pass=$(grep -c -F -x -f "$EXPECTED" "$ACTUAL")
kat_fail=$(( kat_total - kat_pass ))
[ "$kat_fail" -gt 0 ] && { echo "known-answer mismatches:"; diff "$EXPECTED" "$ACTUAL" | head -30; }
# a line in the probe output that is not expected is a failure too (e.g. a plugin that now crashes)
extra=$(grep -c -v -F -x -f "$EXPECTED" "$ACTUAL" || true)
[ "$extra" -gt "$kat_fail" ] && kat_fail=$extra
kat_pass=$(( kat_total - kat_fail ))
[ "$kat_pass" -lt 0 ] && kat_pass=0
rm -f "$ACTUAL"

# 2) Upstream's own ctest suite (plugin contract tests, bundle/registry tests). The two
#    bundle-profile-* tests re-configure the project without WITHOUT_OPENCV, so they cannot pass in
#    an image that has no OpenCV.
ctest_out=$(cd build-tests && ctest -j"$MAYHEM_JOBS" -E 'bundle-profile-(all|explicit)' 2>&1)
echo "$ctest_out" | tail -8
ct_summary=$(echo "$ctest_out" | grep -E 'tests passed, [0-9]+ tests failed out of' || true)
if [ -n "$ct_summary" ]; then
  ct_total=$(echo "$ct_summary" | sed -E 's/.* out of ([0-9]+).*/\1/')
  ct_fail=$(echo "$ct_summary" | sed -E 's/.*, ([0-9]+) tests failed.*/\1/')
else
  ct_total=1; ct_fail=1
fi
ct_pass=$(( ct_total - ct_fail ))

emit_ctrf "frei0r-kat+ctest" $(( kat_pass + ct_pass )) $(( kat_fail + ct_fail )) 0
