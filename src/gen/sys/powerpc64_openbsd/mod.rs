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
pub use self::machine_cpu::CPU_ALTIVEC;
pub use self::machine_cpu::CPU_MAXID;
mod machine_elf;
pub use self::machine_elf::PPC_FEATURE_32;
pub use self::machine_elf::PPC_FEATURE_64;
pub use self::machine_elf::PPC_FEATURE_601_INSTR;
pub use self::machine_elf::PPC_FEATURE_HAS_ALTIVEC;
pub use self::machine_elf::PPC_FEATURE_HAS_FPU;
pub use self::machine_elf::PPC_FEATURE_HAS_MMU;
pub use self::machine_elf::PPC_FEATURE_UNIFIED_CACHE;
pub use self::machine_elf::PPC_FEATURE_HAS_SPE;
pub use self::machine_elf::PPC_FEATURE_HAS_EFP_SINGLE;
pub use self::machine_elf::PPC_FEATURE_HAS_EFP_DOUBLE;
pub use self::machine_elf::PPC_FEATURE_NO_TB;
pub use self::machine_elf::PPC_FEATURE_POWER4;
pub use self::machine_elf::PPC_FEATURE_POWER5;
pub use self::machine_elf::PPC_FEATURE_POWER5_PLUS;
pub use self::machine_elf::PPC_FEATURE_CELL;
pub use self::machine_elf::PPC_FEATURE_BOOKE;
pub use self::machine_elf::PPC_FEATURE_SMT;
pub use self::machine_elf::PPC_FEATURE_ICACHE_SNOOP;
pub use self::machine_elf::PPC_FEATURE_ARCH_2_05;
pub use self::machine_elf::PPC_FEATURE_HAS_DFP;
pub use self::machine_elf::PPC_FEATURE_POWER6_EXT;
pub use self::machine_elf::PPC_FEATURE_ARCH_2_06;
pub use self::machine_elf::PPC_FEATURE_HAS_VSX;
pub use self::machine_elf::PPC_FEATURE_TRUE_LE;
pub use self::machine_elf::PPC_FEATURE_PPC_LE;
pub use self::machine_elf::PPC_FEATURE2_ARCH_2_07;
pub use self::machine_elf::PPC_FEATURE2_HTM;
pub use self::machine_elf::PPC_FEATURE2_DSCR;
pub use self::machine_elf::PPC_FEATURE2_EBB;
pub use self::machine_elf::PPC_FEATURE2_ISEL;
pub use self::machine_elf::PPC_FEATURE2_TAR;
pub use self::machine_elf::PPC_FEATURE2_HAS_VEC_CRYPTO;
pub use self::machine_elf::PPC_FEATURE2_HTM_NOSC;
pub use self::machine_elf::PPC_FEATURE2_ARCH_3_00;
pub use self::machine_elf::PPC_FEATURE2_HAS_IEEE128;
pub use self::machine_elf::PPC_FEATURE2_DARN;
pub use self::machine_elf::PPC_FEATURE2_SCV;
pub use self::machine_elf::PPC_FEATURE2_HTM_NOSUSPEND;
pub type c_char = u8;
