// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf32_Auxinfo {
    pub a_type: ::std::os::raw::c_int,
    pub a_un: Elf32_Auxinfo__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union Elf32_Auxinfo__bindgen_ty_1 {
    pub a_val: ::std::os::raw::c_long,
    pub a_ptr: *mut ::core::ffi::c_void,
    pub a_fcn: ::core::option::Option<unsafe extern "C" fn()>,
}
pub type Elf_Auxinfo = Elf32_Auxinfo;
pub const HWCAP_SWP: u32 = 1;
pub const HWCAP_HALF: u32 = 2;
pub const HWCAP_THUMB: u32 = 4;
pub const HWCAP_26BIT: u32 = 8;
pub const HWCAP_FAST_MULT: u32 = 16;
pub const HWCAP_FPA: u32 = 32;
pub const HWCAP_VFP: u32 = 64;
pub const HWCAP_EDSP: u32 = 128;
pub const HWCAP_JAVA: u32 = 256;
pub const HWCAP_IWMMXT: u32 = 512;
pub const HWCAP_CRUNCH: u32 = 1024;
pub const HWCAP_THUMBEE: u32 = 2048;
pub const HWCAP_NEON: u32 = 4096;
pub const HWCAP_VFPv3: u32 = 8192;
pub const HWCAP_VFPv3D16: u32 = 16384;
pub const HWCAP_TLS: u32 = 32768;
pub const HWCAP_VFPv4: u32 = 65536;
pub const HWCAP_IDIVA: u32 = 131072;
pub const HWCAP_IDIVT: u32 = 262144;
pub const HWCAP_VFPD32: u32 = 524288;
pub const HWCAP_IDIV: u32 = 393216;
pub const HWCAP_LPAE: u32 = 1048576;
pub const HWCAP_EVTSTRM: u32 = 2097152;
pub const HWCAP2_AES: u32 = 1;
pub const HWCAP2_PMULL: u32 = 2;
pub const HWCAP2_SHA1: u32 = 4;
pub const HWCAP2_SHA2: u32 = 8;
pub const HWCAP2_CRC32: u32 = 16;
