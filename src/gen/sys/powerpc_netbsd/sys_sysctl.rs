// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub type u_int = ::std::os::raw::c_uint;
pub type u_quad_t = u64;
pub const SYSCTL_VERS_1: u32 = 16777216;
pub const SYSCTL_VERSION: u32 = 16777216;
pub const CTL_QUERY: i32 = -2;
pub const CTL_MACHDEP: u32 = 7;
pub type sysctlfn = *mut ::core::ffi::c_void;
extern "C" {
    pub fn sysctl(
        arg1: *const ::std::os::raw::c_int,
        arg2: u_int,
        arg3: *mut ::core::ffi::c_void,
        arg4: *mut usize,
        arg5: *const ::core::ffi::c_void,
        arg6: usize,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn sysctlbyname(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut ::core::ffi::c_void,
        arg3: *mut usize,
        arg4: *const ::core::ffi::c_void,
        arg5: usize,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode {
    pub sysctl_flags: u32,
    pub sysctl_num: i32,
    pub sysctl_name: [::std::os::raw::c_char; 32usize],
    pub sysctl_ver: u32,
    pub __rsvd: u32,
    pub sysctl_un: sysctlnode__bindgen_ty_1,
    pub _sysctl_size: sysctlnode__bindgen_ty_2,
    pub _sysctl_func: sysctlnode__bindgen_ty_3,
    pub _sysctl_parent: sysctlnode__bindgen_ty_4,
    pub _sysctl_desc: sysctlnode__bindgen_ty_5,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_1 {
    pub scu_child: sysctlnode__bindgen_ty_1__bindgen_ty_1,
    pub scu_data: sysctlnode__bindgen_ty_1__bindgen_ty_2,
    pub scu_alias: i32,
    pub scu_idata: i32,
    pub scu_qdata: u_quad_t,
    pub scu_bdata: bool,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_1__bindgen_ty_1 {
    pub suc_csize: u32,
    pub suc_clen: u32,
    pub _suc_child: sysctlnode__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: *mut sysctlnode,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_1__bindgen_ty_2 {
    pub _sud_data: sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1,
    pub _sud_offset: sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_2,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: *mut ::core::ffi::c_void,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_2 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_2__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_1__bindgen_ty_2__bindgen_ty_2__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: usize,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_2 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_2__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_2__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: usize,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_3 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_3__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_3__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: sysctlfn,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_4 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_4__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_4__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: *mut sysctlnode,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sysctlnode__bindgen_ty_5 {
    pub __sysc_upad: u64,
    pub __sysc_ustr: sysctlnode__bindgen_ty_5__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sysctlnode__bindgen_ty_5__bindgen_ty_1 {
    pub __sysc_spad: u32,
    pub __sysc_sdatum: *const ::std::os::raw::c_char,
}
