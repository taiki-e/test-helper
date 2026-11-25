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
