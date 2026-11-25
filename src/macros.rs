// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(feature = "std")]
#[macro_export]
macro_rules! eprintln_nocapture {
    ($($arg:tt)*) => {{
        use $crate::__private::Write as _;
        let __stderr = $crate::__private::stderr(); // Not buffered because it is written at once.
        let mut __stderr = __stderr.lock();
        let _ = $crate::__private::writeln!(
            __stderr,
            $($arg)*
        );
        let _ = __stderr.flush();
    }};
}

// Inspired by https://stackoverflow.com/a/63904992.
#[macro_export]
macro_rules! function_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static $crate::__private::str {
            $crate::__private::type_name::<T>()
        }
        let name = type_name_of(f);
        name[..name.len() - 3].rsplit_once(':').unwrap().1
    }};
}

#[macro_export]
macro_rules! bin_name {
    () => {
        $crate::__private::env!("CARGO_BIN_NAME")
    };
}

// Inspired by assert_value! in Tokio's tests/async_send_sync.rs.
#[macro_export]
macro_rules! assert_value {
    ($ty:ty: $bound:ident $(& $($rest:tt)+)?) => {
        const _: fn(*const $ty) = |value| {
            fn check<T: ?$crate::__private::Sized + $crate::__private::$bound>(_: *const T) {}
            check(value);
        };
        $($crate::assert_value!($ty: $($rest)+);)?
    };
    ($ty:ty: !$bound:ident $(& $($rest:tt)+)?) => {
        const _: fn(*const $ty) = |value| {
            trait AmbiguousIfImpl<A> {}
            impl<T: ?$crate::__private::Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?$crate::__private::Sized + $crate::__private::$bound> AmbiguousIfImpl<((),)>
                for T {}
            fn check<T: ?$crate::__private::Sized + AmbiguousIfImpl<A>, A>(_: *const T) {}
            check(value);
        };
        $($crate::assert_value!($ty: $($rest)+);)?
    };
}
