// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    unreachable_pub,
    unknown_lints,
    unnameable_types,
    clippy::cast_sign_loss,
    clippy::pub_underscore_fields,
    clippy::unnecessary_cast,
)]
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_linux_gnu;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_linux_gnu::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod aarch64_be_linux_gnu;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_be_linux_gnu::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod aarch64_linux_gnu_ilp32;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::aarch64_linux_gnu_ilp32::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "32"
    )
)]
mod aarch64_be_linux_gnu_ilp32;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "32"
    )
)]
pub use self::aarch64_be_linux_gnu_ilp32::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod armv5te_linux_gnueabi;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::armv5te_linux_gnueabi::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "32"
    )
)]
mod armeb_linux_gnueabi;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "32"
    )
)]
pub use self::armeb_linux_gnueabi::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod powerpc64_linux_gnu;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64_linux_gnu::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod powerpc64le_linux_gnu;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64le_linux_gnu::*;
#[cfg(
    all(
        target_arch = "riscv32",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod riscv32gc_linux_gnu;
#[cfg(
    all(
        target_arch = "riscv32",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::riscv32gc_linux_gnu::*;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod riscv64gc_linux_gnu;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "linux",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::riscv64gc_linux_gnu::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_linux_musl;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_linux_musl::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod armv5te_linux_musleabi;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::armv5te_linux_musleabi::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod powerpc64_linux_musl;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64_linux_musl::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod powerpc64le_linux_musl;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64le_linux_musl::*;
#[cfg(
    all(
        target_arch = "riscv32",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod riscv32gc_linux_musl;
#[cfg(
    all(
        target_arch = "riscv32",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::riscv32gc_linux_musl::*;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod riscv64gc_linux_musl;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "linux",
        target_env = "musl",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::riscv64gc_linux_musl::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "uclibc",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_linux_uclibc;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "uclibc",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_linux_uclibc::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "uclibc",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod armv5te_linux_uclibceabi;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "linux",
        target_env = "uclibc",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::armv5te_linux_uclibceabi::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "l4re",
        target_env = "uclibc",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_l4re_uclibc;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "l4re",
        target_env = "uclibc",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_l4re_uclibc::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "android",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_linux_android;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "android",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_linux_android::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "android",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod arm_linux_androideabi;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "android",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::arm_linux_androideabi::*;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "android",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod riscv64_linux_android;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "android",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::riscv64_linux_android::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "macos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_apple_darwin;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "macos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_apple_darwin::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "ios",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_apple_ios;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "ios",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_apple_ios::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "tvos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_apple_tvos;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "tvos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_apple_tvos::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "visionos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_apple_visionos;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "visionos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_apple_visionos::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "watchos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_apple_watchos;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "watchos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_apple_watchos::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "watchos",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod arm64_32_apple_watchos;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "watchos",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::arm64_32_apple_watchos::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_freebsd;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_freebsd::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod armv6_freebsd;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::armv6_freebsd::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "freebsd",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod powerpc64_freebsd;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "freebsd",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64_freebsd::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod powerpc64le_freebsd;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64le_freebsd::*;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod riscv64gc_freebsd;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "freebsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::riscv64gc_freebsd::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "netbsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_netbsd;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "netbsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_netbsd::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "netbsd",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod aarch64_be_netbsd;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "netbsd",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_be_netbsd::*;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "netbsd",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
mod armv6_netbsd_eabihf;
#[cfg(
    all(
        target_arch = "arm",
        target_os = "netbsd",
        target_endian = "little",
        target_pointer_width = "32"
    )
)]
pub use self::armv6_netbsd_eabihf::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "openbsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_openbsd;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "openbsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_openbsd::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "openbsd",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod powerpc64_openbsd;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "openbsd",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64_openbsd::*;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "openbsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod riscv64gc_openbsd;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "openbsd",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::riscv64gc_openbsd::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "illumos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_illumos;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "illumos",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_illumos::*;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "aix",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
mod powerpc64_ibm_aix;
#[cfg(
    all(
        target_arch = "powerpc64",
        target_os = "aix",
        target_endian = "big",
        target_pointer_width = "64"
    )
)]
pub use self::powerpc64_ibm_aix::*;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "fuchsia",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod aarch64_fuchsia;
#[cfg(
    all(
        target_arch = "aarch64",
        target_os = "fuchsia",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::aarch64_fuchsia::*;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "fuchsia",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
mod riscv64gc_fuchsia;
#[cfg(
    all(
        target_arch = "riscv64",
        target_os = "fuchsia",
        target_endian = "little",
        target_pointer_width = "64"
    )
)]
pub use self::riscv64gc_fuchsia::*;
