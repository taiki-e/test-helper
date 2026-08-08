// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Interfaces to [Valgrind Client Requests](https://valgrind.org/docs/manual/manual-core-adv.html#manual-core-adv.clientreq)).

// This code was originally written when we encountered https://github.com/2dav/crabgrind/issues/8,
// but was later abandoned. It was later revived to address several issues encountered some time later:
// https://github.com/taiki-e/portable-atomic/pull/240#issuecomment-5224532302
// https://github.com/taiki-e/atomic-maybe-uninit/pull/69#issuecomment-5224554732

use core::arch::asm;

#[repr(C)]
union Value {
    ptr: *mut c_void,
    int: usize,
}
impl From<usize> for Value {
    #[inline(always)]
    fn from(value: usize) -> Self {
        Self { int: value }
    }
}
impl From<u32> for Value {
    #[inline(always)]
    fn from(value: u32) -> Self {
        Self { int: value as usize }
    }
}
impl<T> From<*mut T> for Value {
    #[inline(always)]
    fn from(value: *mut T) -> Self {
        Self { ptr: value.cast::<c_void>() }
    }
}
const _: () = assert!(core::mem::size_of::<Value>() == core::mem::size_of::<usize>());

// -----------------------------------------------------------------------------
// valgrind

#[inline(always)]
unsafe fn do_client_req(
    default: usize,
    request: u32,
    arg1: Value,
    arg2: Value,
    arg3: Value,
    arg4: Value,
    arg5: Value,
) -> usize {
    let args = [request.into(), arg1, arg2, arg3, arg4, arg5];
    let mut result;
    unsafe {
        // Refs: https://sourceware.org/git/?p=valgrind.git;a=blob;f=include/valgrind.h.in;t=VALGRIND_3_27_1
        #[cfg(target_arch = "x86")]
        asm!(
            "
            rol edi, 3
            rol edi, 13
            rol edi, 29
            rol edi, 19
            xchg ebx, ebx
            ",
            inout("edx") default => result,
            in("eax") args.as_ptr(),
            options(nostack),
        );
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        asm!(
            "
            rol rdi, 3
            rol rdi, 13
            rol rdi, 61
            rol rdi, 51
            xchg rbx, rbx
            ",
            inout("rdx") default => result,
            in("rax") args.as_ptr(),
            options(nostack),
        );
        #[cfg(target_arch = "powerpc")]
        asm!(
            "
            rlwinm 0, 0, 3, 0, 31
            rlwinm 0, 0, 13, 0, 31
            rlwinm 0, 0, 29, 0, 31
            rlwinm 0, 0, 19, 0, 31
            or %r1, %r1, %r1
            ",
            inout("r3") default => result,
            in("r4") args.as_ptr(),
            out("cr0") _,
            options(nostack),
        );
        #[cfg(all(target_arch = "powerpc64", target_pointer_width = "64"))]
        asm!(
            "
            rotldi 0, 0, 3
            rotldi 0, 0, 13
            rotldi 0, 0, 61
            rotldi 0, 0, 51
            or %r1, %r1, %r1
            ",
            inout("r3") default => result,
            in("r4") args.as_ptr(),
            out("cr0") _,
            options(nostack, preserves_flags),
        );
        #[cfg(target_arch = "arm")]
        asm!(
            "
            mov r12, r12, ror #3
            mov r12, r12, ror #13
            mov r12, r12, ror #29
            mov r12, r12, ror #19
            orr r10, r10, r10
            ",
            inout("r3") default => result,
            in("r4") args.as_ptr(),
            options(nostack),
        );
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        asm!(
            "
            ror x12, x12, #3
            ror x12, x12, #13
            ror x12, x12, #51
            ror x12, x12, #61
            orr x10, x10, x10
            ",
            inout("x3") default => result,
            in("x4") args.as_ptr(),
            options(nostack),
        );
        #[cfg(all(target_arch = "s390x", target_pointer_width = "64"))]
        asm!(
            "
            lr %r15, %r15
            lr %r1, %r1
            lr %r2, %r2
            lr %r3, %r3
            lr %r2, %r2
            ",
            inout("r3") default => result,
            in("r2") args.as_ptr(),
            options(nostack),
        );
        #[cfg(any(target_arch = "mips", target_arch = "mips32r6"))]
        asm!(
            "
            srl $0, $0, 13
            srl $0, $0, 29
            srl $0, $0, 3
            srl $0, $0, 19
            or $13, $13, $13
            ",
            inout("$11") default => result,
            in("$12") args.as_ptr(),
            options(nostack, preserves_flags),
        );
        #[cfg(all(
            any(target_arch = "mips64", target_arch = "mips64r6"),
            target_pointer_width = "64",
        ))]
        asm!(
            "
            dsll $0, $0, 3
            dsll $0, $0, 13
            dsll $0, $0, 29
            dsll $0, $0, 19
            or $13, $13, $13
            ",
            inout("$11") default => result,
            in("$12") args.as_ptr(),
            options(nostack, preserves_flags),
        );
        #[cfg(all(target_arch = "riscv64", target_pointer_width = "64"))]
        asm!(
            "
            .option push
            .option norvc
            srli zero, zero, 3
            srli zero, zero, 13
            srli zero, zero, 51
            srli zero, zero, 61
            or a0, a0, a0
            .option pop
            ",
            inout("a3") default => result,
            in("a4") args.as_ptr(),
            options(nostack, preserves_flags),
        );
        // Refs: https://github.com/FreeFlyingSheep/valgrind-loongarch64/blob/131f7852b25c79e0279347f0801bc0075de23640/include/valgrind.h.in#L1219
        #[cfg(all(target_arch = "loongarch64", target_pointer_width = "64"))]
        asm!(
            "
            srli.d $zero, $zero, 3
            srli.d $zero, $zero, 13
            srli.d $zero, $zero, 29
            srli.d $zero, $zero, 19
            or $t1, $t1, $t1
            ",
            inout("a7") default => result,
            in("t0") args.as_ptr(),
            options(nostack, preserves_flags),
        );
        // Refs: https://github.com/glaubitz/valgrind-sparc/blob/3155f4fc3f1779e505d09490c2678921cfbb7c71/include/valgrind.h#L1051
        #[cfg(all(target_arch = "sparc64", target_pointer_width = "64"))]
        asm!(
            "
            .register %g6, #ignore
            .register %g7, #ignore
            srax %g6, %g7, %g0
            or %o0, %o1, %g0
            ",
            inout("o0") default => result,
            in("o1") args.as_ptr(),
            options(nostack, preserves_flags),
        );
    }
    result
}

const fn req_base(a: u8, b: u8) -> u32 {
    (a as u32) << 24 | (b as u32) << 16
}

// -----------------------------------------------------------------------------
// memcheck

// Refs: https://sourceware.org/git/?p=valgrind.git;a=blob;f=memcheck/memcheck.h;t=VALGRIND_3_27_1
const MAKE_MEM_NOACCESS: u32 = req_base(b'M', b'C') + 0;
const MAKE_MEM_UNDEFINED: u32 = req_base(b'M', b'C') + 1;
const MAKE_MEM_DEFINED: u32 = req_base(b'M', b'C') + 2;
const MAKE_MEM_DEFINED_IF_ADDRESSABLE: u32 = req_base(b'M', b'C') + 11;

macro_rules! make_mem {
    ($name:ident, $req:ident) => {
        #[inline(always)]
        #[track_caller]
        pub fn $name<T: ?Sized>(addr: &T) {
            let num_bytes = mem::size_of_val(addr);
            let addr = addr as *const T as *mut c_void;
            let res = unsafe {
                do_client_req(
                    0,
                    $req,
                    addr.into(),
                    num_bytes.into(),
                    0_usize.into(),
                    0_usize.into(),
                    0_usize.into(),
                )
            };
            assert_eq!(res, usize::MAX);
        }
    };
}
make_mem!(make_mem_noaccess, MAKE_MEM_NOACCESS);
make_mem!(make_mem_undefined, MAKE_MEM_UNDEFINED);
make_mem!(make_mem_defined, MAKE_MEM_DEFINED);
make_mem!(make_mem_defined_if_addressable, MAKE_MEM_DEFINED_IF_ADDRESSABLE);
