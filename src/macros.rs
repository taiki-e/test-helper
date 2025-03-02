// SPDX-License-Identifier: Apache-2.0 OR MIT

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
