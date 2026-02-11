#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -CeEuo pipefail
IFS=$'\n\t'
trap -- 's=$?; printf >&2 "%s\n" "${0##*/}:${LINENO}: \`${BASH_COMMAND}\` exit with ${s}"; exit ${s}' ERR
cd -- "$(dirname -- "$0")"/..

# Run code generators.
#
# USAGE:
#    ./tools/gen.sh

set -x

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  retry() {
    for i in {1..10}; do
      if "$@"; then
        return 0
      else
        sleep "${i}"
      fi
    done
    "$@"
  }
  apt_packages=(
    gcc-aarch64-linux-gnu
    gcc-arm-linux-gnueabi
    # gcc-i686-linux-gnu # x86-64-linux-gnu-gcc -m32
    gcc-13-loongarch64-linux-gnu
    gcc-m68k-linux-gnu
    # gcc-mips-linux-gnu # mips64el-linux-gnuabi64-gcc -mabi=32 -mips32r2 -meb
    # gcc-mips64-linux-gnuabi64 # mips64el-linux-gnuabi64-gcc -mips64r2 -meb
    gcc-mips64el-linux-gnuabi64
    # gcc-mipsel-linux-gnu # mips64el-linux-gnuabi64-gcc -mabi=32 -mips32r2
    # gcc-mipsisa32r6-linux-gnu # mips64el-linux-gnuabi64-gcc -mabi=32 -mips32r6 -meb
    # gcc-mipsisa32r6el-linux-gnu # mips64el-linux-gnuabi64-gcc -mabi=32 -mips32r6
    # gcc-mipsisa64r6-linux-gnuabi64 # mips64el-linux-gnuabi64-gcc -mips64r6 -meb
    # gcc-mipsisa64r6el-linux-gnuabi64 # mips64el-linux-gnuabi64-gcc -mips64r6
    # gcc-powerpc-linux-gnu # powerpc64le-linux-gnu-gcc -m32 -mbig-endian
    # gcc-powerpc64-linux-gnu # powerpc64le-linux-gnu-gcc -mbig-endian
    gcc-powerpc64le-linux-gnu
    gcc-riscv64-linux-gnu
    gcc-s390x-linux-gnu
    gcc-sparc64-linux-gnu
    # gcc-x86-64-linux-gnux32 # x86-64-linux-gnu-gcc -mx32
    gettext
  )
  retry sudo apt-get -o Acquire::Retries=10 -qq update
  retry sudo apt-get -o Acquire::Retries=10 -o Dpkg::Use-Pty=0 install -y --no-install-recommends "${apt_packages[@]}"
  # https://github.com/taiki-e/rust-cross-toolchain/pkgs/container/rust-cross-toolchain
  retry docker create --name gcc-csky-linux-gnuabiv2 "ghcr.io/taiki-e/rust-cross-toolchain:csky-unknown-linux-gnuabiv2-dev-amd64"
  docker cp -- "gcc-csky-linux-gnuabiv2:/csky-unknown-linux-gnuabiv2" "${HOME}"/gcc-csky-linux-gnuabiv2
  docker rm -f -- gcc-csky-linux-gnuabiv2 >/dev/null
  printf '%s\n' "${HOME}"/gcc-csky-linux-gnuabiv2/bin >>"${GITHUB_PATH}"
fi

cargo run --manifest-path tools/codegen/Cargo.toml
