#!/bin/bash

# Fail on any error.
set -e
# Display commands to stderr.
set -x

if [[ -z "${BAZELISK_VERSION}" ]]; then
  BAZELISK_VERSION=v1.15.0
fi

# Downloads bazelisk to ~/bin as `bazel`.
# Copied from google3/hardware/chips/infra/kokoro/utils/scripts/build_functions.sh,
# as there is no easy way to import a shell lib.
function install_bazelisk {
  case "$(uname -s)" in
    Darwin) local name=bazelisk-darwin-amd64 ;;
    Linux)
      case "$(uname -m)" in
       x86_64) local name=bazelisk-linux-amd64 ;;
       aarch64) local name=bazelisk-linux-arm64 ;;
       *) die "Unknown machine type: $(uname -m)" ;;
      esac ;;
    *) die "Unknown OS: $(uname -s)" ;;
  esac

  mkdir -p "$HOME/bin"
  wget --no-verbose -O "$HOME/bin/bazel" \
      "https://github.com/bazelbuild/bazelisk/releases/download/$BAZELISK_VERSION/$name" \
      2> /dev/null

  chmod u+x "$HOME/bin/bazel"
  if [[ ! ":$PATH:" =~ :"$HOME"/bin/?: ]]; then
    export PATH="$HOME/bin:$PATH"
  fi
  echo "Bazelisk ${BAZELISK_VERSION} installation completed."
}

install_bazelisk

cd ${KOKORO_ARTIFACTS_DIR}/git/prtoken-reference

bazel test prtoken:storage_test
bazel test prtoken:command_test

current_epoch_seconds=$(date +%s)

PRTOKEN_TMP=/tmp/prtoken_temp
mkdir -p "${PRTOKEN_TMP}"
EXPECTED_IP=1.2.3.4
PRIVATE_KEY_FILE="test_key_${current_epoch_seconds}.json"
RESULT_TABLE="results_${current_epoch_seconds}"

bazel run //prtoken:prtoken issue -- \
    --custom_db_filename=test.db \
    --custom_key_filename="${PRIVATE_KEY_FILE}" \
    --output_dir="${PRTOKEN_TMP}" \
    --num_tokens=10 \
    --ip="${EXPECTED_IP}"

bazel run  //prtoken:prtoken verify -- \
    --token_db "${PRTOKEN_TMP}/test.db" \
    --private_key "${PRTOKEN_TMP}/${PRIVATE_KEY_FILE}" \
    --result_table "${RESULT_TABLE}"

# Run the query to get the output
query="select t.e, r.m, r.ordinal from tokens as t join ${RESULT_TABLE} as r where t.e = r.e"
output=$(sqlite3 "${PRTOKEN_TMP}/test.db" "${query}" 2>&1)

# Check if the output contains the expected string
if [[ "$output" == *"${EXPECTED_IP}"* ]]; then
  echo "Verification successful: Found $EXPECTED_IP in output."
  exit 0
fi

echo "Verification failed: Did not find $EXPECTED_IP in output."
echo "Output was:"
echo "$output"
exit 1
