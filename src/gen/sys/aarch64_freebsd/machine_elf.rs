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
    pub a_val: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf64_Auxinfo {
    pub a_type: ::std::os::raw::c_long,
    pub a_un: Elf64_Auxinfo__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union Elf64_Auxinfo__bindgen_ty_1 {
    pub a_val: ::std::os::raw::c_long,
    pub a_ptr: *mut ::core::ffi::c_void,
    pub a_fcn: ::core::option::Option<unsafe extern "C" fn()>,
}
pub type Elf_Auxinfo = Elf64_Auxinfo;
pub const HWCAP_FP: u32 = 1;
pub const HWCAP_ASIMD: u32 = 2;
pub const HWCAP_EVTSTRM: u32 = 4;
pub const HWCAP_AES: u32 = 8;
pub const HWCAP_PMULL: u32 = 16;
pub const HWCAP_SHA1: u32 = 32;
pub const HWCAP_SHA2: u32 = 64;
pub const HWCAP_CRC32: u32 = 128;
pub const HWCAP_ATOMICS: u32 = 256;
pub const HWCAP_FPHP: u32 = 512;
pub const HWCAP_ASIMDHP: u32 = 1024;
pub const HWCAP_CPUID: u32 = 2048;
pub const HWCAP_ASIMDRDM: u32 = 4096;
pub const HWCAP_JSCVT: u32 = 8192;
pub const HWCAP_FCMA: u32 = 16384;
pub const HWCAP_LRCPC: u32 = 32768;
pub const HWCAP_DCPOP: u32 = 65536;
pub const HWCAP_SHA3: u32 = 131072;
pub const HWCAP_SM3: u32 = 262144;
pub const HWCAP_SM4: u32 = 524288;
pub const HWCAP_ASIMDDP: u32 = 1048576;
pub const HWCAP_SHA512: u32 = 2097152;
pub const HWCAP_SVE: u32 = 4194304;
pub const HWCAP_ASIMDFHM: u32 = 8388608;
pub const HWCAP_DIT: u32 = 16777216;
pub const HWCAP_USCAT: u32 = 33554432;
pub const HWCAP_ILRCPC: u32 = 67108864;
pub const HWCAP_FLAGM: u32 = 134217728;
pub const HWCAP_SSBS: u32 = 268435456;
pub const HWCAP_SB: u32 = 536870912;
pub const HWCAP_PACA: u32 = 1073741824;
pub const HWCAP_PACG: u32 = 2147483648;
pub const HWCAP_GCS: u64 = 4294967296;
pub const HWCAP2_DCPODP: u32 = 1;
pub const HWCAP2_SVE2: u32 = 2;
pub const HWCAP2_SVEAES: u32 = 4;
pub const HWCAP2_SVEPMULL: u32 = 8;
pub const HWCAP2_SVEBITPERM: u32 = 16;
pub const HWCAP2_SVESHA3: u32 = 32;
pub const HWCAP2_SVESM4: u32 = 64;
pub const HWCAP2_FLAGM2: u32 = 128;
pub const HWCAP2_FRINT: u32 = 256;
pub const HWCAP2_SVEI8MM: u32 = 512;
pub const HWCAP2_SVEF32MM: u32 = 1024;
pub const HWCAP2_SVEF64MM: u32 = 2048;
pub const HWCAP2_SVEBF16: u32 = 4096;
pub const HWCAP2_I8MM: u32 = 8192;
pub const HWCAP2_BF16: u32 = 16384;
pub const HWCAP2_DGH: u32 = 32768;
pub const HWCAP2_RNG: u32 = 65536;
pub const HWCAP2_BTI: u32 = 131072;
pub const HWCAP2_MTE: u32 = 262144;
pub const HWCAP2_ECV: u32 = 524288;
pub const HWCAP2_AFP: u32 = 1048576;
pub const HWCAP2_RPRES: u32 = 2097152;
pub const HWCAP2_MTE3: u32 = 4194304;
pub const HWCAP2_SME: u32 = 8388608;
pub const HWCAP2_SME_I16I64: u32 = 16777216;
pub const HWCAP2_SME_F64F64: u32 = 33554432;
pub const HWCAP2_SME_I8I32: u32 = 67108864;
pub const HWCAP2_SME_F16F32: u32 = 134217728;
pub const HWCAP2_SME_B16F32: u32 = 268435456;
pub const HWCAP2_SME_F32F32: u32 = 536870912;
pub const HWCAP2_SME_FA64: u32 = 1073741824;
pub const HWCAP2_WFXT: u32 = 2147483648;
pub const HWCAP2_EBF16: u64 = 4294967296;
pub const HWCAP2_SVE_EBF16: u64 = 8589934592;
pub const HWCAP2_CSSC: u64 = 17179869184;
pub const HWCAP2_RPRFM: u64 = 34359738368;
pub const HWCAP2_SVE2P1: u64 = 68719476736;
pub const HWCAP2_SME2: u64 = 137438953472;
pub const HWCAP2_SME2P1: u64 = 274877906944;
pub const HWCAP2_SME_I16I32: u64 = 549755813888;
pub const HWCAP2_SME_BI32I32: u64 = 1099511627776;
pub const HWCAP2_SME_B16B16: u64 = 2199023255552;
pub const HWCAP2_SME_F16F16: u64 = 4398046511104;
pub const HWCAP2_MOPS: u64 = 8796093022208;
pub const HWCAP2_HBC: u64 = 17592186044416;
pub const HWCAP2_SVE_B16B16: u64 = 35184372088832;
pub const HWCAP2_LRCPC3: u64 = 70368744177664;
pub const HWCAP2_LSE128: u64 = 140737488355328;
pub const HWCAP2_FPMR: u64 = 281474976710656;
pub const HWCAP2_LUT: u64 = 562949953421312;
pub const HWCAP2_FAMINMAX: u64 = 1125899906842624;
pub const HWCAP2_F8CVT: u64 = 2251799813685248;
pub const HWCAP2_F8FMA: u64 = 4503599627370496;
pub const HWCAP2_F8DP4: u64 = 9007199254740992;
pub const HWCAP2_F8DP2: u64 = 18014398509481984;
pub const HWCAP2_F8E4M3: u64 = 36028797018963968;
pub const HWCAP2_F8E5M2: u64 = 72057594037927936;
pub const HWCAP2_SME_LUTV2: u64 = 144115188075855872;
pub const HWCAP2_SME_F8F16: u64 = 288230376151711744;
pub const HWCAP2_SME_F8F32: u64 = 576460752303423488;
pub const HWCAP2_SME_SF8FMA: u64 = 1152921504606846976;
pub const HWCAP2_SME_SF8DP4: u64 = 2305843009213693952;
pub const HWCAP2_SME_SF8DP2: u64 = 4611686018427387904;
pub const HWCAP2_POE: u64 = 9223372036854775808;
