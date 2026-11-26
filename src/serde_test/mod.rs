// SPDX-License-Identifier: Apache-2.0 OR MIT

// This module is a fork of unmaintained https://github.com/serde-deprecated/test, licensed under "Apache-2.0 OR MIT".
//
// This includes {i,u}128 support (https://github.com/taiki-e/serde_test/commit/df513c55a97f0a72fa67bad5396ed09123e5676c).
// Doctests using serde_derive were removed because serde_derive doesn't work with serde crate renamed in Cargo.toml.
//
// See the license files included in this directory for copyright & license.

#![allow(clippy::needless_doctest_main)]

mod assert;
mod configure;
mod de;
mod error;
mod ser;
mod token;

pub use self::{
    assert::{
        assert_de_tokens, assert_de_tokens_error, assert_ser_tokens, assert_ser_tokens_error,
        assert_tokens,
    },
    configure::{Compact, Configure, Readable},
    token::Token,
};
