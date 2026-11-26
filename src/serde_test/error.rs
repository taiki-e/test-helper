// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    error,
    fmt::{self, Display},
    string::{String, ToString as _},
};

use serde::{de, ser};

#[derive(Clone, Debug)]
#[allow(unknown_lints, unnameable_types)] // unnameable_types is available on Rust 1.79+
pub struct Error {
    msg: String,
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error { msg: msg.to_string() }
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error { msg: msg.to_string() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.msg)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl PartialEq<str> for Error {
    fn eq(&self, other: &str) -> bool {
        self.msg == other
    }
}
