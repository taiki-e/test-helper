// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod dlfcn;
pub use self::dlfcn::RTLD_DEFAULT;
pub use self::dlfcn::dlsym;
mod sys_auxv;
pub use self::sys_auxv::AT_NULL;
pub use self::sys_auxv::AT_IGNORE;
pub use self::sys_auxv::AT_PAGESZ;
pub use self::sys_auxv::AT_HWCAP;
pub use self::sys_auxv::AT_HWCAP2;
pub use self::sys_auxv::AT_COUNT;
pub use self::sys_auxv::elf_aux_info;
mod sys_sysctl;
pub use self::sys_sysctl::CTL_MACHDEP;
pub use self::sys_sysctl::sysctl;
mod machine_cpu;
pub use self::machine_cpu::CPU_LED_BLINK;
pub use self::machine_cpu::CPU_ALLOWAPERTURE;
pub use self::machine_cpu::CPU_CPUTYPE;
pub use self::machine_cpu::CPU_CECCERRORS;
pub use self::machine_cpu::CPU_CECCLAST;
pub use self::machine_cpu::CPU_MAXID;
mod machine_elf;
pub type c_char = i8;
