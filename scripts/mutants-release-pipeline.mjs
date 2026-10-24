// Release and CI consumers must install the same artifact on both supported Node majors, and a retained
// mutation transcript must not mask the runner's failing exit status.
export default [
  ["package required check skips when an artifact consumer fails", ".github/workflows/ci.yml", "    needs: [build-package, verify-package]\n    if: always()\n", "    needs: [build-package, verify-package]\n    if: success()\n"],
  ["package required check ignores an unsuccessful artifact consumer", ".github/workflows/ci.yml", 'test "$BUILD_RESULT" = success && test "$CONSUMER_RESULT" = success', 'test "$BUILD_RESULT" = success'],
  ["release publishes before its installed consumers pass", ".github/workflows/release.yml", "    needs: [build, verify-package]", "    needs: build"],
  ["package CI omits the Node 22 tarball consumer", ".github/workflows/ci.yml", "        node: [22, 24]", "        node: [24]"],
  ["mutation transcript pipeline hides the runner failure", ".github/workflows/ci.yml", "          set -o pipefail\n", "          set +o pipefail\n"],
];
