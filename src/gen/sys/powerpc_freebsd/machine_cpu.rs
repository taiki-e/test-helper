// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub const PPC_FEATURE_32: u32 = 2147483648;
pub const PPC_FEATURE_64: u32 = 1073741824;
pub const PPC_FEATURE_601_INSTR: u32 = 536870912;
pub const PPC_FEATURE_HAS_ALTIVEC: u32 = 268435456;
pub const PPC_FEATURE_HAS_FPU: u32 = 134217728;
pub const PPC_FEATURE_HAS_MMU: u32 = 67108864;
pub const PPC_FEATURE_UNIFIED_CACHE: u32 = 16777216;
pub const PPC_FEATURE_HAS_SPE: u32 = 8388608;
pub const PPC_FEATURE_HAS_EFP_SINGLE: u32 = 4194304;
pub const PPC_FEATURE_HAS_EFP_DOUBLE: u32 = 2097152;
pub const PPC_FEATURE_NO_TB: u32 = 1048576;
pub const PPC_FEATURE_POWER4: u32 = 524288;
pub const PPC_FEATURE_POWER5: u32 = 262144;
pub const PPC_FEATURE_POWER5_PLUS: u32 = 131072;
pub const PPC_FEATURE_CELL: u32 = 65536;
pub const PPC_FEATURE_BOOKE: u32 = 32768;
pub const PPC_FEATURE_SMT: u32 = 16384;
pub const PPC_FEATURE_ICACHE_SNOOP: u32 = 8192;
pub const PPC_FEATURE_ARCH_2_05: u32 = 4096;
pub const PPC_FEATURE_HAS_DFP: u32 = 1024;
pub const PPC_FEATURE_POWER6_EXT: u32 = 512;
pub const PPC_FEATURE_ARCH_2_06: u32 = 256;
pub const PPC_FEATURE_HAS_VSX: u32 = 128;
pub const PPC_FEATURE_TRUE_LE: u32 = 2;
pub const PPC_FEATURE_PPC_LE: u32 = 1;
pub const PPC_FEATURE2_ARCH_2_07: u32 = 2147483648;
pub const PPC_FEATURE2_HTM: u32 = 1073741824;
pub const PPC_FEATURE2_DSCR: u32 = 536870912;
pub const PPC_FEATURE2_EBB: u32 = 268435456;
pub const PPC_FEATURE2_ISEL: u32 = 134217728;
pub const PPC_FEATURE2_TAR: u32 = 67108864;
pub const PPC_FEATURE2_HAS_VEC_CRYPTO: u32 = 33554432;
pub const PPC_FEATURE2_HTM_NOSC: u32 = 16777216;
pub const PPC_FEATURE2_ARCH_3_00: u32 = 8388608;
pub const PPC_FEATURE2_HAS_IEEE128: u32 = 4194304;
pub const PPC_FEATURE2_DARN: u32 = 2097152;
pub const PPC_FEATURE2_SCV: u32 = 1048576;
pub const PPC_FEATURE2_HTM_NOSUSPEND: u32 = 524288;
pub const PPC_FEATURE_BITMASK: &[u8; 153] = b"\x10 PPC32\x1FPPC64\x1EPPC601\x1DALTIVEC\x1CFPU\x1BMMU\x19UNIFIEDCACHE\x18SPE\x17SPESFP\x16DPESFP\x15NOTB\x14POWER4\x13POWER5\x12P5PLUS\x11CELL\x10BOOKE\x0FSMT\x0EISNOOP\rARCH205\x0BDFP\tARCH206\x08VSX\x02TRUELE\x01PPCLE\0";
pub const PPC_FEATURE2_BITMASK: &[u8; 79] = b"\x10 ARCH207\x1FHTM\x1EDSCR\x1CISEL\x1BTAR\x1AVCRYPTO\x19HTMNOSC\x18ARCH300\x17IEEE128\x16DARN\x15SCV\x14HTMNOSUSP\0";