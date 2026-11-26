// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt::{self, Debug, Display};

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Token {
    /// A serialized `bool`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&true, &[Token::Bool(true)]);
    /// ```
    Bool(bool),

    /// A serialized `i8`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0i8, &[Token::I8(0)]);
    /// ```
    I8(i8),

    /// A serialized `i16`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0i16, &[Token::I16(0)]);
    /// ```
    I16(i16),

    /// A serialized `i32`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0i32, &[Token::I32(0)]);
    /// ```
    I32(i32),

    /// A serialized `i64`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0i64, &[Token::I64(0)]);
    /// ```
    I64(i64),

    /// A serialized `i128`.
    ///
    /// ```
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0i128, &[Token::I128(0)]);
    /// ```
    I128(i128),

    /// A serialized `u8`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0u8, &[Token::U8(0)]);
    /// ```
    U8(u8),

    /// A serialized `u16`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0u16, &[Token::U16(0)]);
    /// ```
    U16(u16),

    /// A serialized `u32`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0u32, &[Token::U32(0)]);
    /// ```
    U32(u32),

    /// A serialized `u64`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0u64, &[Token::U64(0)]);
    /// ```
    U64(u64),

    /// A serialized `u128`.
    ///
    /// ```
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0u128, &[Token::U128(0)]);
    /// ```
    U128(u128),

    /// A serialized `f32`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0f32, &[Token::F32(0.0)]);
    /// ```
    F32(f32),

    /// A serialized `f64`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&0f64, &[Token::F64(0.0)]);
    /// ```
    F64(f64),

    /// A serialized `char`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&'\n', &[Token::Char('\n')]);
    /// ```
    Char(char),

    /// A serialized `str`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let s = String::from("transient");
    /// assert_tokens(&s, &[Token::Str("transient")]);
    /// ```
    Str(&'static str),

    /// A borrowed `str`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let s: &str = "borrowed";
    /// assert_tokens(&s, &[Token::BorrowedStr("borrowed")]);
    /// ```
    BorrowedStr(&'static str),

    /// A serialized `String`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let s = String::from("owned");
    /// assert_tokens(&s, &[Token::String("owned")]);
    /// ```
    String(&'static str),

    /// A serialized `[u8]`
    Bytes(&'static [u8]),

    /// A borrowed `[u8]`.
    BorrowedBytes(&'static [u8]),

    /// A serialized `ByteBuf`
    ByteBuf(&'static [u8]),

    /// A serialized `Option<T>` containing none.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let opt = None::<char>;
    /// assert_tokens(&opt, &[Token::None]);
    /// ```
    None,

    /// The header to a serialized `Option<T>` containing some value.
    ///
    /// The tokens of the value follow after this header.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let opt = Some('c');
    /// assert_tokens(&opt, &[Token::Some, Token::Char('c')]);
    /// ```
    Some,

    /// A serialized `()`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// assert_tokens(&(), &[Token::Unit]);
    /// ```
    Unit,

    /// A serialized unit struct of the given name.
    UnitStruct { name: &'static str },

    /// A unit variant of an enum.
    UnitVariant { name: &'static str, variant: &'static str },

    /// The header to a serialized newtype struct of the given name.
    ///
    /// After this header is the value contained in the newtype struct.
    NewtypeStruct { name: &'static str },

    /// The header to a newtype variant of an enum.
    ///
    /// After this header is the value contained in the newtype variant.
    NewtypeVariant { name: &'static str, variant: &'static str },

    /// The header to a sequence.
    ///
    /// After this header are the elements of the sequence, followed by
    /// `SeqEnd`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let vec = vec!['a', 'b', 'c'];
    /// assert_tokens(&vec, &[
    ///     Token::Seq { len: Some(3) },
    ///     Token::Char('a'),
    ///     Token::Char('b'),
    ///     Token::Char('c'),
    ///     Token::SeqEnd,
    /// ]);
    /// ```
    Seq { len: Option<usize> },

    /// An indicator of the end of a sequence.
    SeqEnd,

    /// The header to a tuple.
    ///
    /// After this header are the elements of the tuple, followed by `TupleEnd`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// let tuple = ('a', 100);
    /// assert_tokens(&tuple, &[
    ///     Token::Tuple { len: 2 },
    ///     Token::Char('a'),
    ///     Token::I32(100),
    ///     Token::TupleEnd,
    /// ]);
    /// ```
    Tuple { len: usize },

    /// An indicator of the end of a tuple.
    TupleEnd,

    /// The header to a tuple struct.
    ///
    /// After this header are the fields of the tuple struct, followed by
    /// `TupleStructEnd`.
    TupleStruct { name: &'static str, len: usize },

    /// An indicator of the end of a tuple struct.
    TupleStructEnd,

    /// The header to a tuple variant of an enum.
    ///
    /// After this header are the fields of the tuple variant, followed by
    /// `TupleVariantEnd`.
    TupleVariant { name: &'static str, variant: &'static str, len: usize },

    /// An indicator of the end of a tuple variant.
    TupleVariantEnd,

    /// The header to a map.
    ///
    /// After this header are the entries of the map, followed by `MapEnd`.
    ///
    /// ```edition2021
    /// # use test_helper::serde_test::{assert_tokens, Token};
    /// #
    /// use std::collections::BTreeMap;
    ///
    /// let mut map = BTreeMap::new();
    /// map.insert('A', 65);
    /// map.insert('Z', 90);
    ///
    /// assert_tokens(&map, &[
    ///     Token::Map { len: Some(2) },
    ///     Token::Char('A'),
    ///     Token::I32(65),
    ///     Token::Char('Z'),
    ///     Token::I32(90),
    ///     Token::MapEnd,
    /// ]);
    /// ```
    Map { len: Option<usize> },

    /// An indicator of the end of a map.
    MapEnd,

    /// The header of a struct.
    ///
    /// After this header are the fields of the struct, followed by `StructEnd`.
    Struct { name: &'static str, len: usize },

    /// An indicator of the end of a struct.
    StructEnd,

    /// The header of a struct variant of an enum.
    ///
    /// After this header are the fields of the struct variant, followed by
    /// `StructVariantEnd`.
    StructVariant { name: &'static str, variant: &'static str, len: usize },

    /// An indicator of the end of a struct variant.
    StructVariantEnd,

    /// The header to an enum of the given name.
    Enum { name: &'static str },
}

impl Display for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}
