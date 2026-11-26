// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt::Debug;

use serde::{de::Deserialize, ser::Serialize};

use super::{de::Deserializer, ser::Serializer, token::Token};

/// Runs both `assert_ser_tokens` and `assert_de_tokens`.
#[track_caller]
pub fn assert_tokens<'de, T>(value: &T, tokens: &'de [Token])
where
    T: Serialize + Deserialize<'de> + PartialEq + Debug,
{
    assert_ser_tokens(value, tokens);
    assert_de_tokens(value, tokens);
}

/// Asserts that `value` serializes to the given `tokens`.
#[track_caller]
pub fn assert_ser_tokens<T>(value: &T, tokens: &[Token])
where
    T: ?Sized + Serialize,
{
    let mut ser = Serializer::new(tokens);
    match value.serialize(&mut ser) {
        Ok(()) => {}
        Err(err) => panic!("value failed to serialize: {}", err),
    }

    if ser.remaining() > 0 {
        panic!("{} remaining tokens", ser.remaining());
    }
}

/// Asserts that `value` serializes to the given `tokens`, and then yields
/// `error`.
#[track_caller]
pub fn assert_ser_tokens_error<T>(value: &T, tokens: &[Token], error: &str)
where
    T: ?Sized + Serialize,
{
    let mut ser = Serializer::new(tokens);
    match value.serialize(&mut ser) {
        Ok(()) => panic!("value serialized successfully"),
        Err(e) => assert_eq!(e, *error),
    }

    if ser.remaining() > 0 {
        panic!("{} remaining tokens", ser.remaining());
    }
}

/// Asserts that the given `tokens` deserialize into `value`.
#[track_caller]
pub fn assert_de_tokens<'de, T>(value: &T, tokens: &'de [Token])
where
    T: Deserialize<'de> + PartialEq + Debug,
{
    let mut de = Deserializer::new(tokens);
    let mut deserialized_val = match T::deserialize(&mut de) {
        Ok(v) => {
            assert_eq!(v, *value);
            v
        }
        Err(e) => panic!("tokens failed to deserialize: {}", e),
    };
    if de.remaining() > 0 {
        panic!("{} remaining tokens", de.remaining());
    }

    // Do the same thing for deserialize_in_place. This isn't *great* because a
    // no-op impl of deserialize_in_place can technically succeed here. Still,
    // this should catch a lot of junk.
    let mut de = Deserializer::new(tokens);
    match T::deserialize_in_place(&mut de, &mut deserialized_val) {
        Ok(()) => {
            assert_eq!(deserialized_val, *value);
        }
        Err(e) => panic!("tokens failed to deserialize_in_place: {}", e),
    }
    if de.remaining() > 0 {
        panic!("{} remaining tokens", de.remaining());
    }
}

/// Asserts that the given `tokens` yield `error` when deserializing.
#[track_caller]
pub fn assert_de_tokens_error<'de, T>(tokens: &'de [Token], error: &str)
where
    T: Deserialize<'de>,
{
    let mut de = Deserializer::new(tokens);
    match T::deserialize(&mut de) {
        Ok(_) => panic!("tokens deserialized successfully"),
        Err(e) => assert_eq!(e, *error),
    }

    // There may be one token left if a peek caused the error
    de.next_token_opt();

    if de.remaining() > 0 {
        panic!("{} remaining tokens", de.remaining());
    }
}
