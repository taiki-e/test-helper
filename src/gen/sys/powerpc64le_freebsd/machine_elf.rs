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
