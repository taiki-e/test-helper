// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::{
    cell::UnsafeCell,
    marker::{PhantomData, PhantomPinned},
};

/// A marker that is `!Send` and `Sync`.
pub struct NotSend(PhantomData<*const ()>);
// SAFETY: this is a marker type and we'll never access the value.
unsafe impl Sync for NotSend {}

/// A marker that is `Send` and `!Sync`.
pub struct NotSync(PhantomData<*const ()>);
// SAFETY: this is a marker type and we'll never access the value.
unsafe impl Send for NotSync {}

/// A marker that is `!Send` and `!Sync`.
pub struct NotSendSync(PhantomData<*const ()>);

/// A marker that is `!Unpin`.
pub struct NotUnpin(PhantomPinned);

/// A marker that is `!UnwindSafe`.
pub struct NotUnwindSafe(PhantomData<&'static mut ()>);

/// A marker that is `!RefUnwindSafe`.
pub struct NotRefUnwindSafe(PhantomData<UnsafeCell<()>>);
// SAFETY: this is a marker type and we'll never access the value.
unsafe impl Sync for NotRefUnwindSafe {}

#[cfg(test)]
mod tests {
    use super::*;

    assert_value!(NotSend: !Send & Sync & Unpin & UnwindSafe & RefUnwindSafe);
    assert_value!(NotSync: Send & !Sync & Unpin & UnwindSafe & RefUnwindSafe);
    assert_value!(NotSendSync: !Send & !Sync & Unpin & UnwindSafe & RefUnwindSafe);
    assert_value!(NotUnpin: Send & Sync & !Unpin & UnwindSafe & RefUnwindSafe);
    assert_value!(NotUnwindSafe: Send & Sync & Unpin & !UnwindSafe & RefUnwindSafe);
    assert_value!(NotRefUnwindSafe: Send & Sync & Unpin & UnwindSafe & !RefUnwindSafe);
}
