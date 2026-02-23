// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(feature = "std")]
#[macro_export]
macro_rules! eprintln_nocapture {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let __stderr = ::std::io::stderr(); // Not buffered because it is written at once.
        let mut __stderr = __stderr.lock();
        let _ = ::std::writeln!(
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
        fn type_name_of<T>(_: T) -> &'static str {
            ::core::any::type_name::<T>()
        }
        let name = type_name_of(f);
        name[..name.len() - 3].rsplit_once(':').unwrap().1
    }};
}

#[macro_export]
macro_rules! bin_name {
    () => {
        env!("CARGO_BIN_NAME")
    };
}
