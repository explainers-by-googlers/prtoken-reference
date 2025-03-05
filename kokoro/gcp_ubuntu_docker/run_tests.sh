#!/bin/bash

# Fail on any error.
set -e

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
bazel build prtoken:all
