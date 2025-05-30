// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub const HWCAP_S390_ESAN3: u32 = 1;
pub const HWCAP_S390_ZARCH: u32 = 2;
pub const HWCAP_S390_STFLE: u32 = 4;
pub const HWCAP_S390_MSA: u32 = 8;
pub const HWCAP_S390_LDISP: u32 = 16;
pub const HWCAP_S390_EIMM: u32 = 32;
pub const HWCAP_S390_DFP: u32 = 64;
pub const HWCAP_S390_HPAGE: u32 = 128;
pub const HWCAP_S390_ETF3EH: u32 = 256;
pub const HWCAP_S390_HIGH_GPRS: u32 = 512;
pub const HWCAP_S390_TE: u32 = 1024;
pub const HWCAP_S390_VX: u32 = 2048;
pub const HWCAP_S390_VXRS: u32 = 2048;
pub const HWCAP_S390_VXD: u32 = 4096;
pub const HWCAP_S390_VXRS_BCD: u32 = 4096;
pub const HWCAP_S390_VXE: u32 = 8192;
pub const HWCAP_S390_VXRS_EXT: u32 = 8192;
pub const HWCAP_S390_GS: u32 = 16384;
pub const HWCAP_S390_VXRS_EXT2: u32 = 32768;
pub const HWCAP_S390_VXRS_PDE: u32 = 65536;
pub const HWCAP_S390_SORT: u32 = 131072;
pub const HWCAP_S390_DFLT: u32 = 262144;
pub const HWCAP_S390_VXRS_PDE2: u32 = 524288;
pub const HWCAP_S390_NNPA: u32 = 1048576;
pub const HWCAP_S390_PCI_MIO: u32 = 2097152;
pub const HWCAP_S390_SIE: u32 = 4194304;
extern "C" {
    pub fn getauxval(__type: ::std::os::raw::c_ulong) -> ::std::os::raw::c_ulong;
}
