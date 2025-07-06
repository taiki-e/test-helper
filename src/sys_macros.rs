// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Static assertions for FFI bindings.
/// This checks that FFI bindings defined in this crate and FFI bindings generated for
/// the platform's latest header file using bindgen have the same types.
/// Since this is static assertion, we can detect problems with
/// `cargo check --tests --target <target>` run in CI
/// without actually running tests on these platforms.
/// See also tools/codegen/src/ffi.rs.
#[macro_export]
macro_rules! static_assert_sys_type {
    ($(
        $(#[$attr:meta])*
        type $([$($windows_path:ident)::+])? $name:ident;
    )*) => {
        #[allow(
            unused_imports,
            clippy::cast_possible_wrap,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation
        )]
        const _: fn() = || {
            #[cfg(not(any(target_os = "aix", windows)))]
            use $crate::sys;
            #[cfg(target_os = "aix")]
            use ::libc as sys;
            $(
                $(#[$attr])*
                {
                    $(use ::windows_sys::$($windows_path)::+ as sys;)?
                    let _: $name = 0 as sys::$name;
                }
            )*
        };
    };
}

/// Static assertions for FFI bindings.
/// This checks that FFI bindings defined in this crate and FFI bindings generated for
/// the platform's latest header file using bindgen have the same fields.
/// Since this is static assertion, we can detect problems with
/// `cargo check --tests --target <target>` run in CI
/// without actually running tests on these platforms.
/// See also tools/codegen/src/ffi.rs.
#[macro_export]
macro_rules! static_assert_sys_struct {
    ($(
        $(#[$attr:meta])*
        struct $([$($windows_path:ident)::+])? $name:ident {$(
            $(#[$field_attr:meta])*
            $field_name:ident: $field_ty:ty,
        )*}
    )*) => {
        #[allow(unused_imports, clippy::undocumented_unsafe_blocks)]
        const _: fn() = || {
            #[cfg(not(any(target_os = "aix", windows)))]
            use $crate::sys;
            #[cfg(target_os = "aix")]
            use ::libc as sys;
            $(
                $(#[$attr])*
                {
                    $(use ::windows_sys::$($windows_path)::+ as sys;)?
                    $crate::__static_assert!(
                        ::core::mem::size_of::<$name>()
                            == ::core::mem::size_of::<sys::$name>()
                    );
                    let s: $name = unsafe { ::core::mem::zeroed() };
                    // field names and types
                    let _ = sys::$name {$(
                        $(#[$field_attr])*
                        $field_name: s.$field_name,
                    )*};
                    // field offsets
                    $(
                        $(#[$field_attr])*
                        $crate::__static_assert!(
                            $crate::memoffset::offset_of!($name, $field_name) ==
                                $crate::memoffset::offset_of!(sys::$name, $field_name),
                        );
                    )*
                }
            )*
        };
    };
}

/// Static assertions for FFI bindings.
/// This checks that FFI bindings defined in this crate and FFI bindings generated for
/// the platform's latest header file using bindgen have the same values.
/// Since this is static assertion, we can detect problems with
/// `cargo check --tests --target <target>` run in CI
/// without actually running tests on these platforms.
/// See also tools/codegen/src/ffi.rs.
#[macro_export]
macro_rules! static_assert_sys_const {
    ($(
        $(#[$attr:meta])*
        const $([$($windows_path:ident)::+])? $name:ident: $ty:ty;
    )*) => {
        #[allow(
            unused_attributes, // for #[allow(..)] in $(#[$attr])*
            unused_imports,
            clippy::cast_possible_wrap,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
        )]
        const _: fn() = || {
            #[cfg(not(any(target_os = "aix", windows)))]
            use $crate::sys;
            #[cfg(target_os = "aix")]
            use ::libc as sys;
            $(
                $(#[$attr])*
                {
                    $(use ::windows_sys::$($windows_path)::+ as sys;)?
                    $crate::__static_assert_sys_const_cmp!($name, $ty);
                }
            )*
        };
    };
}
#[macro_export]
#[doc(hidden)]
macro_rules! __static_assert_sys_const_cmp {
    (RTLD_DEFAULT, $ty:ty) => {
        // ptr comparison and ptr-to-int cast are not stable on const context, so use ptr-to-int
        // transmute and compare its result.
        $crate::__static_assert!(
            // SAFETY: Pointer-to-integer transmutes are valid (since we are okay with losing the
            // provenance here). (Same as <pointer>::addr().)
            unsafe {
                ::core::mem::transmute::<$ty, usize>(RTLD_DEFAULT)
                    == ::core::mem::transmute::<$ty, usize>(sys::RTLD_DEFAULT)
            }
        );
    };
    ($name:ident, $ty:ty) => {
        $crate::__static_assert!($name == sys::$name as $ty);
    };
}

/// Static assertions for FFI bindings.
/// This checks that FFI bindings defined in this crate and FFI bindings generated for
/// the platform's latest header file using bindgen have the same signatures.
/// Since this is static assertion, we can detect problems with
/// `cargo check --tests --target <target>` run in CI
/// without actually running tests on these platforms.
/// See also tools/codegen/src/ffi.rs.
#[macro_export]
macro_rules! static_assert_sys_fn {
    (
        $(#[$extern_attr:meta])*
        extern $abi:literal {$(
            $(#[$fn_attr:meta])*
            fn $([$($windows_path:ident)::+])? $name:ident($($args:tt)*) $(-> $ret_ty:ty)?;
        )*}
    ) => {
        #[allow(unused_imports)]
        const _: fn() = || {
            #[cfg(not(any(target_os = "aix", windows)))]
            use $crate::sys;
            #[cfg(target_os = "aix")]
            use ::libc as sys;
            $(
                $(#[$fn_attr])*
                {
                    $(use ::windows_sys::$($windows_path)::+ as sys;)?
                    $crate::__static_assert_sys_fn_cmp!($abi fn $name($($args)*) $(-> $ret_ty)?);
                }
            )*
        };
    };
}
#[macro_export]
#[doc(hidden)]
macro_rules! __static_assert_sys_fn_cmp {
    (
        $abi:literal fn $name:ident($($_arg_pat:ident: $arg_ty:ty),*, ...) $(-> $ret_ty:ty)?
    ) => {
        let mut _f: unsafe extern $abi fn($($arg_ty),*, ...) $(-> $ret_ty)? = $name;
        _f = sys::$name;
    };
    (
        $abi:literal fn $name:ident($($_arg_pat:ident: $arg_ty:ty),* $(,)?) $(-> $ret_ty:ty)?
    ) => {
        let mut _f: unsafe extern $abi fn($($arg_ty),*) $(-> $ret_ty)? = $name;
        _f = sys::$name;
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __static_assert {
    ($cond:expr $(,)?) => {{
        let [()] = [(); (true /* type check */ & $cond) as usize];
    }};
}
