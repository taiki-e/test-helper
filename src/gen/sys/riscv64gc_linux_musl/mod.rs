// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod linux_headers_asm_hwcap;
mod linux_headers_asm_hwprobe;
pub use linux_headers_asm_hwprobe::riscv_hwprobe;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_MVENDORID;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_MARCHID;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_MIMPID;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_BASE_BEHAVIOR;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_BASE_BEHAVIOR_IMA;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_IMA_EXT_0;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_IMA_FD;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_IMA_C;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_IMA_V;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBA;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBB;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBS;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZICBOZ;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBC;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBKB;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBKC;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZBKX;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZKND;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZKNE;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZKNH;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZKSED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZKSH;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZKT;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVBB;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVBC;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKB;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKG;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKNED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKNHA;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKNHB;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKSED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKSH;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVKT;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZFH;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZFHMIN;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZIHINTNTL;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVFH;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVFHMIN;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZFA;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZTSO;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZACAS;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZICOND;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZIHINTPAUSE;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVE32X;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVE32F;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVE64X;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVE64F;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZVE64D;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZIMOP;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZCA;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZCB;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZCD;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZCF;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZCMOP;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_ZAWRS;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_EXT_SUPM;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_CPUPERF_0;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_UNKNOWN;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_EMULATED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_SLOW;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_FAST;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_UNSUPPORTED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_MASK;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_TIME_CSR_FREQ;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_SCALAR_UNKNOWN;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_SCALAR_SLOW;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_SCALAR_FAST;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_SCALAR_UNSUPPORTED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_VECTOR_UNKNOWN;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_VECTOR_FAST;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_MISALIGNED_VECTOR_UNSUPPORTED;
pub use linux_headers_asm_hwprobe::RISCV_HWPROBE_WHICH_CPUS;
mod linux_headers_asm_unistd;
pub use linux_headers_asm_unistd::__NR_io_setup;
pub use linux_headers_asm_unistd::__NR_io_destroy;
pub use linux_headers_asm_unistd::__NR_io_submit;
pub use linux_headers_asm_unistd::__NR_io_cancel;
pub use linux_headers_asm_unistd::__NR_io_getevents;
pub use linux_headers_asm_unistd::__NR_setxattr;
pub use linux_headers_asm_unistd::__NR_lsetxattr;
pub use linux_headers_asm_unistd::__NR_fsetxattr;
pub use linux_headers_asm_unistd::__NR_getxattr;
pub use linux_headers_asm_unistd::__NR_lgetxattr;
pub use linux_headers_asm_unistd::__NR_fgetxattr;
pub use linux_headers_asm_unistd::__NR_listxattr;
pub use linux_headers_asm_unistd::__NR_llistxattr;
pub use linux_headers_asm_unistd::__NR_flistxattr;
pub use linux_headers_asm_unistd::__NR_removexattr;
pub use linux_headers_asm_unistd::__NR_lremovexattr;
pub use linux_headers_asm_unistd::__NR_fremovexattr;
pub use linux_headers_asm_unistd::__NR_getcwd;
pub use linux_headers_asm_unistd::__NR_lookup_dcookie;
pub use linux_headers_asm_unistd::__NR_eventfd2;
pub use linux_headers_asm_unistd::__NR_epoll_create1;
pub use linux_headers_asm_unistd::__NR_epoll_ctl;
pub use linux_headers_asm_unistd::__NR_epoll_pwait;
pub use linux_headers_asm_unistd::__NR_dup;
pub use linux_headers_asm_unistd::__NR_dup3;
pub use linux_headers_asm_unistd::__NR_fcntl;
pub use linux_headers_asm_unistd::__NR_inotify_init1;
pub use linux_headers_asm_unistd::__NR_inotify_add_watch;
pub use linux_headers_asm_unistd::__NR_inotify_rm_watch;
pub use linux_headers_asm_unistd::__NR_ioctl;
pub use linux_headers_asm_unistd::__NR_ioprio_set;
pub use linux_headers_asm_unistd::__NR_ioprio_get;
pub use linux_headers_asm_unistd::__NR_flock;
pub use linux_headers_asm_unistd::__NR_mknodat;
pub use linux_headers_asm_unistd::__NR_mkdirat;
pub use linux_headers_asm_unistd::__NR_unlinkat;
pub use linux_headers_asm_unistd::__NR_symlinkat;
pub use linux_headers_asm_unistd::__NR_linkat;
pub use linux_headers_asm_unistd::__NR_umount2;
pub use linux_headers_asm_unistd::__NR_mount;
pub use linux_headers_asm_unistd::__NR_pivot_root;
pub use linux_headers_asm_unistd::__NR_nfsservctl;
pub use linux_headers_asm_unistd::__NR_statfs;
pub use linux_headers_asm_unistd::__NR_fstatfs;
pub use linux_headers_asm_unistd::__NR_truncate;
pub use linux_headers_asm_unistd::__NR_ftruncate;
pub use linux_headers_asm_unistd::__NR_fallocate;
pub use linux_headers_asm_unistd::__NR_faccessat;
pub use linux_headers_asm_unistd::__NR_chdir;
pub use linux_headers_asm_unistd::__NR_fchdir;
pub use linux_headers_asm_unistd::__NR_chroot;
pub use linux_headers_asm_unistd::__NR_fchmod;
pub use linux_headers_asm_unistd::__NR_fchmodat;
pub use linux_headers_asm_unistd::__NR_fchownat;
pub use linux_headers_asm_unistd::__NR_fchown;
pub use linux_headers_asm_unistd::__NR_openat;
pub use linux_headers_asm_unistd::__NR_close;
pub use linux_headers_asm_unistd::__NR_vhangup;
pub use linux_headers_asm_unistd::__NR_pipe2;
pub use linux_headers_asm_unistd::__NR_quotactl;
pub use linux_headers_asm_unistd::__NR_getdents64;
pub use linux_headers_asm_unistd::__NR_lseek;
pub use linux_headers_asm_unistd::__NR_read;
pub use linux_headers_asm_unistd::__NR_write;
pub use linux_headers_asm_unistd::__NR_readv;
pub use linux_headers_asm_unistd::__NR_writev;
pub use linux_headers_asm_unistd::__NR_pread64;
pub use linux_headers_asm_unistd::__NR_pwrite64;
pub use linux_headers_asm_unistd::__NR_preadv;
pub use linux_headers_asm_unistd::__NR_pwritev;
pub use linux_headers_asm_unistd::__NR_sendfile;
pub use linux_headers_asm_unistd::__NR_pselect6;
pub use linux_headers_asm_unistd::__NR_ppoll;
pub use linux_headers_asm_unistd::__NR_signalfd4;
pub use linux_headers_asm_unistd::__NR_vmsplice;
pub use linux_headers_asm_unistd::__NR_splice;
pub use linux_headers_asm_unistd::__NR_tee;
pub use linux_headers_asm_unistd::__NR_readlinkat;
pub use linux_headers_asm_unistd::__NR_newfstatat;
pub use linux_headers_asm_unistd::__NR_fstat;
pub use linux_headers_asm_unistd::__NR_sync;
pub use linux_headers_asm_unistd::__NR_fsync;
pub use linux_headers_asm_unistd::__NR_fdatasync;
pub use linux_headers_asm_unistd::__NR_sync_file_range;
pub use linux_headers_asm_unistd::__NR_timerfd_create;
pub use linux_headers_asm_unistd::__NR_timerfd_settime;
pub use linux_headers_asm_unistd::__NR_timerfd_gettime;
pub use linux_headers_asm_unistd::__NR_utimensat;
pub use linux_headers_asm_unistd::__NR_acct;
pub use linux_headers_asm_unistd::__NR_capget;
pub use linux_headers_asm_unistd::__NR_capset;
pub use linux_headers_asm_unistd::__NR_personality;
pub use linux_headers_asm_unistd::__NR_exit;
pub use linux_headers_asm_unistd::__NR_exit_group;
pub use linux_headers_asm_unistd::__NR_waitid;
pub use linux_headers_asm_unistd::__NR_set_tid_address;
pub use linux_headers_asm_unistd::__NR_unshare;
pub use linux_headers_asm_unistd::__NR_futex;
pub use linux_headers_asm_unistd::__NR_set_robust_list;
pub use linux_headers_asm_unistd::__NR_get_robust_list;
pub use linux_headers_asm_unistd::__NR_nanosleep;
pub use linux_headers_asm_unistd::__NR_getitimer;
pub use linux_headers_asm_unistd::__NR_setitimer;
pub use linux_headers_asm_unistd::__NR_kexec_load;
pub use linux_headers_asm_unistd::__NR_init_module;
pub use linux_headers_asm_unistd::__NR_delete_module;
pub use linux_headers_asm_unistd::__NR_timer_create;
pub use linux_headers_asm_unistd::__NR_timer_gettime;
pub use linux_headers_asm_unistd::__NR_timer_getoverrun;
pub use linux_headers_asm_unistd::__NR_timer_settime;
pub use linux_headers_asm_unistd::__NR_timer_delete;
pub use linux_headers_asm_unistd::__NR_clock_settime;
pub use linux_headers_asm_unistd::__NR_clock_gettime;
pub use linux_headers_asm_unistd::__NR_clock_getres;
pub use linux_headers_asm_unistd::__NR_clock_nanosleep;
pub use linux_headers_asm_unistd::__NR_syslog;
pub use linux_headers_asm_unistd::__NR_ptrace;
pub use linux_headers_asm_unistd::__NR_sched_setparam;
pub use linux_headers_asm_unistd::__NR_sched_setscheduler;
pub use linux_headers_asm_unistd::__NR_sched_getscheduler;
pub use linux_headers_asm_unistd::__NR_sched_getparam;
pub use linux_headers_asm_unistd::__NR_sched_setaffinity;
pub use linux_headers_asm_unistd::__NR_sched_getaffinity;
pub use linux_headers_asm_unistd::__NR_sched_yield;
pub use linux_headers_asm_unistd::__NR_sched_get_priority_max;
pub use linux_headers_asm_unistd::__NR_sched_get_priority_min;
pub use linux_headers_asm_unistd::__NR_sched_rr_get_interval;
pub use linux_headers_asm_unistd::__NR_restart_syscall;
pub use linux_headers_asm_unistd::__NR_kill;
pub use linux_headers_asm_unistd::__NR_tkill;
pub use linux_headers_asm_unistd::__NR_tgkill;
pub use linux_headers_asm_unistd::__NR_sigaltstack;
pub use linux_headers_asm_unistd::__NR_rt_sigsuspend;
pub use linux_headers_asm_unistd::__NR_rt_sigaction;
pub use linux_headers_asm_unistd::__NR_rt_sigprocmask;
pub use linux_headers_asm_unistd::__NR_rt_sigpending;
pub use linux_headers_asm_unistd::__NR_rt_sigtimedwait;
pub use linux_headers_asm_unistd::__NR_rt_sigqueueinfo;
pub use linux_headers_asm_unistd::__NR_rt_sigreturn;
pub use linux_headers_asm_unistd::__NR_setpriority;
pub use linux_headers_asm_unistd::__NR_getpriority;
pub use linux_headers_asm_unistd::__NR_reboot;
pub use linux_headers_asm_unistd::__NR_setregid;
pub use linux_headers_asm_unistd::__NR_setgid;
pub use linux_headers_asm_unistd::__NR_setreuid;
pub use linux_headers_asm_unistd::__NR_setuid;
pub use linux_headers_asm_unistd::__NR_setresuid;
pub use linux_headers_asm_unistd::__NR_getresuid;
pub use linux_headers_asm_unistd::__NR_setresgid;
pub use linux_headers_asm_unistd::__NR_getresgid;
pub use linux_headers_asm_unistd::__NR_setfsuid;
pub use linux_headers_asm_unistd::__NR_setfsgid;
pub use linux_headers_asm_unistd::__NR_times;
pub use linux_headers_asm_unistd::__NR_setpgid;
pub use linux_headers_asm_unistd::__NR_getpgid;
pub use linux_headers_asm_unistd::__NR_getsid;
pub use linux_headers_asm_unistd::__NR_setsid;
pub use linux_headers_asm_unistd::__NR_getgroups;
pub use linux_headers_asm_unistd::__NR_setgroups;
pub use linux_headers_asm_unistd::__NR_uname;
pub use linux_headers_asm_unistd::__NR_sethostname;
pub use linux_headers_asm_unistd::__NR_setdomainname;
pub use linux_headers_asm_unistd::__NR_getrlimit;
pub use linux_headers_asm_unistd::__NR_setrlimit;
pub use linux_headers_asm_unistd::__NR_getrusage;
pub use linux_headers_asm_unistd::__NR_umask;
pub use linux_headers_asm_unistd::__NR_prctl;
pub use linux_headers_asm_unistd::__NR_getcpu;
pub use linux_headers_asm_unistd::__NR_gettimeofday;
pub use linux_headers_asm_unistd::__NR_settimeofday;
pub use linux_headers_asm_unistd::__NR_adjtimex;
pub use linux_headers_asm_unistd::__NR_getpid;
pub use linux_headers_asm_unistd::__NR_getppid;
pub use linux_headers_asm_unistd::__NR_getuid;
pub use linux_headers_asm_unistd::__NR_geteuid;
pub use linux_headers_asm_unistd::__NR_getgid;
pub use linux_headers_asm_unistd::__NR_getegid;
pub use linux_headers_asm_unistd::__NR_gettid;
pub use linux_headers_asm_unistd::__NR_sysinfo;
pub use linux_headers_asm_unistd::__NR_mq_open;
pub use linux_headers_asm_unistd::__NR_mq_unlink;
pub use linux_headers_asm_unistd::__NR_mq_timedsend;
pub use linux_headers_asm_unistd::__NR_mq_timedreceive;
pub use linux_headers_asm_unistd::__NR_mq_notify;
pub use linux_headers_asm_unistd::__NR_mq_getsetattr;
pub use linux_headers_asm_unistd::__NR_msgget;
pub use linux_headers_asm_unistd::__NR_msgctl;
pub use linux_headers_asm_unistd::__NR_msgrcv;
pub use linux_headers_asm_unistd::__NR_msgsnd;
pub use linux_headers_asm_unistd::__NR_semget;
pub use linux_headers_asm_unistd::__NR_semctl;
pub use linux_headers_asm_unistd::__NR_semtimedop;
pub use linux_headers_asm_unistd::__NR_semop;
pub use linux_headers_asm_unistd::__NR_shmget;
pub use linux_headers_asm_unistd::__NR_shmctl;
pub use linux_headers_asm_unistd::__NR_shmat;
pub use linux_headers_asm_unistd::__NR_shmdt;
pub use linux_headers_asm_unistd::__NR_socket;
pub use linux_headers_asm_unistd::__NR_socketpair;
pub use linux_headers_asm_unistd::__NR_bind;
pub use linux_headers_asm_unistd::__NR_listen;
pub use linux_headers_asm_unistd::__NR_accept;
pub use linux_headers_asm_unistd::__NR_connect;
pub use linux_headers_asm_unistd::__NR_getsockname;
pub use linux_headers_asm_unistd::__NR_getpeername;
pub use linux_headers_asm_unistd::__NR_sendto;
pub use linux_headers_asm_unistd::__NR_recvfrom;
pub use linux_headers_asm_unistd::__NR_setsockopt;
pub use linux_headers_asm_unistd::__NR_getsockopt;
pub use linux_headers_asm_unistd::__NR_shutdown;
pub use linux_headers_asm_unistd::__NR_sendmsg;
pub use linux_headers_asm_unistd::__NR_recvmsg;
pub use linux_headers_asm_unistd::__NR_readahead;
pub use linux_headers_asm_unistd::__NR_brk;
pub use linux_headers_asm_unistd::__NR_munmap;
pub use linux_headers_asm_unistd::__NR_mremap;
pub use linux_headers_asm_unistd::__NR_add_key;
pub use linux_headers_asm_unistd::__NR_request_key;
pub use linux_headers_asm_unistd::__NR_keyctl;
pub use linux_headers_asm_unistd::__NR_clone;
pub use linux_headers_asm_unistd::__NR_execve;
pub use linux_headers_asm_unistd::__NR_mmap;
pub use linux_headers_asm_unistd::__NR_fadvise64;
pub use linux_headers_asm_unistd::__NR_swapon;
pub use linux_headers_asm_unistd::__NR_swapoff;
pub use linux_headers_asm_unistd::__NR_mprotect;
pub use linux_headers_asm_unistd::__NR_msync;
pub use linux_headers_asm_unistd::__NR_mlock;
pub use linux_headers_asm_unistd::__NR_munlock;
pub use linux_headers_asm_unistd::__NR_mlockall;
pub use linux_headers_asm_unistd::__NR_munlockall;
pub use linux_headers_asm_unistd::__NR_mincore;
pub use linux_headers_asm_unistd::__NR_madvise;
pub use linux_headers_asm_unistd::__NR_remap_file_pages;
pub use linux_headers_asm_unistd::__NR_mbind;
pub use linux_headers_asm_unistd::__NR_get_mempolicy;
pub use linux_headers_asm_unistd::__NR_set_mempolicy;
pub use linux_headers_asm_unistd::__NR_migrate_pages;
pub use linux_headers_asm_unistd::__NR_move_pages;
pub use linux_headers_asm_unistd::__NR_rt_tgsigqueueinfo;
pub use linux_headers_asm_unistd::__NR_perf_event_open;
pub use linux_headers_asm_unistd::__NR_accept4;
pub use linux_headers_asm_unistd::__NR_recvmmsg;
pub use linux_headers_asm_unistd::__NR_riscv_hwprobe;
pub use linux_headers_asm_unistd::__NR_riscv_flush_icache;
pub use linux_headers_asm_unistd::__NR_wait4;
pub use linux_headers_asm_unistd::__NR_prlimit64;
pub use linux_headers_asm_unistd::__NR_fanotify_init;
pub use linux_headers_asm_unistd::__NR_fanotify_mark;
pub use linux_headers_asm_unistd::__NR_name_to_handle_at;
pub use linux_headers_asm_unistd::__NR_open_by_handle_at;
pub use linux_headers_asm_unistd::__NR_clock_adjtime;
pub use linux_headers_asm_unistd::__NR_syncfs;
pub use linux_headers_asm_unistd::__NR_setns;
pub use linux_headers_asm_unistd::__NR_sendmmsg;
pub use linux_headers_asm_unistd::__NR_process_vm_readv;
pub use linux_headers_asm_unistd::__NR_process_vm_writev;
pub use linux_headers_asm_unistd::__NR_kcmp;
pub use linux_headers_asm_unistd::__NR_finit_module;
pub use linux_headers_asm_unistd::__NR_sched_setattr;
pub use linux_headers_asm_unistd::__NR_sched_getattr;
pub use linux_headers_asm_unistd::__NR_renameat2;
pub use linux_headers_asm_unistd::__NR_seccomp;
pub use linux_headers_asm_unistd::__NR_getrandom;
pub use linux_headers_asm_unistd::__NR_memfd_create;
pub use linux_headers_asm_unistd::__NR_bpf;
pub use linux_headers_asm_unistd::__NR_execveat;
pub use linux_headers_asm_unistd::__NR_userfaultfd;
pub use linux_headers_asm_unistd::__NR_membarrier;
pub use linux_headers_asm_unistd::__NR_mlock2;
pub use linux_headers_asm_unistd::__NR_copy_file_range;
pub use linux_headers_asm_unistd::__NR_preadv2;
pub use linux_headers_asm_unistd::__NR_pwritev2;
pub use linux_headers_asm_unistd::__NR_pkey_mprotect;
pub use linux_headers_asm_unistd::__NR_pkey_alloc;
pub use linux_headers_asm_unistd::__NR_pkey_free;
pub use linux_headers_asm_unistd::__NR_statx;
pub use linux_headers_asm_unistd::__NR_io_pgetevents;
pub use linux_headers_asm_unistd::__NR_rseq;
pub use linux_headers_asm_unistd::__NR_kexec_file_load;
pub use linux_headers_asm_unistd::__NR_pidfd_send_signal;
pub use linux_headers_asm_unistd::__NR_io_uring_setup;
pub use linux_headers_asm_unistd::__NR_io_uring_enter;
pub use linux_headers_asm_unistd::__NR_io_uring_register;
pub use linux_headers_asm_unistd::__NR_open_tree;
pub use linux_headers_asm_unistd::__NR_move_mount;
pub use linux_headers_asm_unistd::__NR_fsopen;
pub use linux_headers_asm_unistd::__NR_fsconfig;
pub use linux_headers_asm_unistd::__NR_fsmount;
pub use linux_headers_asm_unistd::__NR_fspick;
pub use linux_headers_asm_unistd::__NR_pidfd_open;
pub use linux_headers_asm_unistd::__NR_clone3;
pub use linux_headers_asm_unistd::__NR_close_range;
pub use linux_headers_asm_unistd::__NR_openat2;
pub use linux_headers_asm_unistd::__NR_pidfd_getfd;
pub use linux_headers_asm_unistd::__NR_faccessat2;
pub use linux_headers_asm_unistd::__NR_process_madvise;
pub use linux_headers_asm_unistd::__NR_epoll_pwait2;
pub use linux_headers_asm_unistd::__NR_mount_setattr;
pub use linux_headers_asm_unistd::__NR_quotactl_fd;
pub use linux_headers_asm_unistd::__NR_landlock_create_ruleset;
pub use linux_headers_asm_unistd::__NR_landlock_add_rule;
pub use linux_headers_asm_unistd::__NR_landlock_restrict_self;
pub use linux_headers_asm_unistd::__NR_memfd_secret;
pub use linux_headers_asm_unistd::__NR_process_mrelease;
pub use linux_headers_asm_unistd::__NR_futex_waitv;
pub use linux_headers_asm_unistd::__NR_set_mempolicy_home_node;
pub use linux_headers_asm_unistd::__NR_cachestat;
pub use linux_headers_asm_unistd::__NR_fchmodat2;
pub use linux_headers_asm_unistd::__NR_map_shadow_stack;
pub use linux_headers_asm_unistd::__NR_futex_wake;
pub use linux_headers_asm_unistd::__NR_futex_wait;
pub use linux_headers_asm_unistd::__NR_futex_requeue;
pub use linux_headers_asm_unistd::__NR_statmount;
pub use linux_headers_asm_unistd::__NR_listmount;
pub use linux_headers_asm_unistd::__NR_lsm_get_self_attr;
pub use linux_headers_asm_unistd::__NR_lsm_set_self_attr;
pub use linux_headers_asm_unistd::__NR_lsm_list_modules;
pub use linux_headers_asm_unistd::__NR_mseal;
pub use linux_headers_asm_unistd::__NR_setxattrat;
pub use linux_headers_asm_unistd::__NR_getxattrat;
pub use linux_headers_asm_unistd::__NR_listxattrat;
pub use linux_headers_asm_unistd::__NR_removexattrat;
mod linux_headers_linux_auxvec;
pub use linux_headers_linux_auxvec::AT_SYSINFO_EHDR;
pub use linux_headers_linux_auxvec::AT_L1I_CACHESIZE;
pub use linux_headers_linux_auxvec::AT_L1I_CACHEGEOMETRY;
pub use linux_headers_linux_auxvec::AT_L1D_CACHESIZE;
pub use linux_headers_linux_auxvec::AT_L1D_CACHEGEOMETRY;
pub use linux_headers_linux_auxvec::AT_L2_CACHESIZE;
pub use linux_headers_linux_auxvec::AT_L2_CACHEGEOMETRY;
pub use linux_headers_linux_auxvec::AT_L3_CACHESIZE;
pub use linux_headers_linux_auxvec::AT_L3_CACHEGEOMETRY;
pub use linux_headers_linux_auxvec::AT_VECTOR_SIZE_ARCH;
pub use linux_headers_linux_auxvec::AT_MINSIGSTKSZ;
pub use linux_headers_linux_auxvec::AT_NULL;
pub use linux_headers_linux_auxvec::AT_IGNORE;
pub use linux_headers_linux_auxvec::AT_EXECFD;
pub use linux_headers_linux_auxvec::AT_PHDR;
pub use linux_headers_linux_auxvec::AT_PHENT;
pub use linux_headers_linux_auxvec::AT_PHNUM;
pub use linux_headers_linux_auxvec::AT_PAGESZ;
pub use linux_headers_linux_auxvec::AT_BASE;
pub use linux_headers_linux_auxvec::AT_FLAGS;
pub use linux_headers_linux_auxvec::AT_ENTRY;
pub use linux_headers_linux_auxvec::AT_NOTELF;
pub use linux_headers_linux_auxvec::AT_UID;
pub use linux_headers_linux_auxvec::AT_EUID;
pub use linux_headers_linux_auxvec::AT_GID;
pub use linux_headers_linux_auxvec::AT_EGID;
pub use linux_headers_linux_auxvec::AT_PLATFORM;
pub use linux_headers_linux_auxvec::AT_HWCAP;
pub use linux_headers_linux_auxvec::AT_CLKTCK;
pub use linux_headers_linux_auxvec::AT_SECURE;
pub use linux_headers_linux_auxvec::AT_BASE_PLATFORM;
pub use linux_headers_linux_auxvec::AT_RANDOM;
pub use linux_headers_linux_auxvec::AT_HWCAP2;
pub use linux_headers_linux_auxvec::AT_RSEQ_FEATURE_SIZE;
pub use linux_headers_linux_auxvec::AT_RSEQ_ALIGN;
pub use linux_headers_linux_auxvec::AT_HWCAP3;
pub use linux_headers_linux_auxvec::AT_HWCAP4;
pub use linux_headers_linux_auxvec::AT_EXECFN;
mod linux_headers_linux_prctl;
pub use linux_headers_linux_prctl::PR_SET_PDEATHSIG;
pub use linux_headers_linux_prctl::PR_GET_PDEATHSIG;
pub use linux_headers_linux_prctl::PR_GET_DUMPABLE;
pub use linux_headers_linux_prctl::PR_SET_DUMPABLE;
pub use linux_headers_linux_prctl::PR_GET_UNALIGN;
pub use linux_headers_linux_prctl::PR_SET_UNALIGN;
pub use linux_headers_linux_prctl::PR_UNALIGN_NOPRINT;
pub use linux_headers_linux_prctl::PR_UNALIGN_SIGBUS;
pub use linux_headers_linux_prctl::PR_GET_KEEPCAPS;
pub use linux_headers_linux_prctl::PR_SET_KEEPCAPS;
pub use linux_headers_linux_prctl::PR_GET_FPEMU;
pub use linux_headers_linux_prctl::PR_SET_FPEMU;
pub use linux_headers_linux_prctl::PR_FPEMU_NOPRINT;
pub use linux_headers_linux_prctl::PR_FPEMU_SIGFPE;
pub use linux_headers_linux_prctl::PR_GET_FPEXC;
pub use linux_headers_linux_prctl::PR_SET_FPEXC;
pub use linux_headers_linux_prctl::PR_FP_EXC_SW_ENABLE;
pub use linux_headers_linux_prctl::PR_FP_EXC_DIV;
pub use linux_headers_linux_prctl::PR_FP_EXC_OVF;
pub use linux_headers_linux_prctl::PR_FP_EXC_UND;
pub use linux_headers_linux_prctl::PR_FP_EXC_RES;
pub use linux_headers_linux_prctl::PR_FP_EXC_INV;
pub use linux_headers_linux_prctl::PR_FP_EXC_DISABLED;
pub use linux_headers_linux_prctl::PR_FP_EXC_NONRECOV;
pub use linux_headers_linux_prctl::PR_FP_EXC_ASYNC;
pub use linux_headers_linux_prctl::PR_FP_EXC_PRECISE;
pub use linux_headers_linux_prctl::PR_GET_TIMING;
pub use linux_headers_linux_prctl::PR_SET_TIMING;
pub use linux_headers_linux_prctl::PR_TIMING_STATISTICAL;
pub use linux_headers_linux_prctl::PR_TIMING_TIMESTAMP;
pub use linux_headers_linux_prctl::PR_SET_NAME;
pub use linux_headers_linux_prctl::PR_GET_NAME;
pub use linux_headers_linux_prctl::PR_GET_ENDIAN;
pub use linux_headers_linux_prctl::PR_SET_ENDIAN;
pub use linux_headers_linux_prctl::PR_ENDIAN_BIG;
pub use linux_headers_linux_prctl::PR_ENDIAN_LITTLE;
pub use linux_headers_linux_prctl::PR_ENDIAN_PPC_LITTLE;
pub use linux_headers_linux_prctl::PR_GET_SECCOMP;
pub use linux_headers_linux_prctl::PR_SET_SECCOMP;
pub use linux_headers_linux_prctl::PR_CAPBSET_READ;
pub use linux_headers_linux_prctl::PR_CAPBSET_DROP;
pub use linux_headers_linux_prctl::PR_GET_TSC;
pub use linux_headers_linux_prctl::PR_SET_TSC;
pub use linux_headers_linux_prctl::PR_TSC_ENABLE;
pub use linux_headers_linux_prctl::PR_TSC_SIGSEGV;
pub use linux_headers_linux_prctl::PR_GET_SECUREBITS;
pub use linux_headers_linux_prctl::PR_SET_SECUREBITS;
pub use linux_headers_linux_prctl::PR_SET_TIMERSLACK;
pub use linux_headers_linux_prctl::PR_GET_TIMERSLACK;
pub use linux_headers_linux_prctl::PR_TASK_PERF_EVENTS_DISABLE;
pub use linux_headers_linux_prctl::PR_TASK_PERF_EVENTS_ENABLE;
pub use linux_headers_linux_prctl::PR_MCE_KILL;
pub use linux_headers_linux_prctl::PR_MCE_KILL_CLEAR;
pub use linux_headers_linux_prctl::PR_MCE_KILL_SET;
pub use linux_headers_linux_prctl::PR_MCE_KILL_LATE;
pub use linux_headers_linux_prctl::PR_MCE_KILL_EARLY;
pub use linux_headers_linux_prctl::PR_MCE_KILL_DEFAULT;
pub use linux_headers_linux_prctl::PR_MCE_KILL_GET;
pub use linux_headers_linux_prctl::PR_SET_MM;
pub use linux_headers_linux_prctl::PR_SET_MM_START_CODE;
pub use linux_headers_linux_prctl::PR_SET_MM_END_CODE;
pub use linux_headers_linux_prctl::PR_SET_MM_START_DATA;
pub use linux_headers_linux_prctl::PR_SET_MM_END_DATA;
pub use linux_headers_linux_prctl::PR_SET_MM_START_STACK;
pub use linux_headers_linux_prctl::PR_SET_MM_START_BRK;
pub use linux_headers_linux_prctl::PR_SET_MM_BRK;
pub use linux_headers_linux_prctl::PR_SET_MM_ARG_START;
pub use linux_headers_linux_prctl::PR_SET_MM_ARG_END;
pub use linux_headers_linux_prctl::PR_SET_MM_ENV_START;
pub use linux_headers_linux_prctl::PR_SET_MM_ENV_END;
pub use linux_headers_linux_prctl::PR_SET_MM_AUXV;
pub use linux_headers_linux_prctl::PR_SET_MM_EXE_FILE;
pub use linux_headers_linux_prctl::PR_SET_MM_MAP;
pub use linux_headers_linux_prctl::PR_SET_MM_MAP_SIZE;
pub use linux_headers_linux_prctl::PR_SET_PTRACER;
pub use linux_headers_linux_prctl::PR_SET_PTRACER_ANY;
pub use linux_headers_linux_prctl::PR_SET_CHILD_SUBREAPER;
pub use linux_headers_linux_prctl::PR_GET_CHILD_SUBREAPER;
pub use linux_headers_linux_prctl::PR_SET_NO_NEW_PRIVS;
pub use linux_headers_linux_prctl::PR_GET_NO_NEW_PRIVS;
pub use linux_headers_linux_prctl::PR_GET_TID_ADDRESS;
pub use linux_headers_linux_prctl::PR_SET_THP_DISABLE;
pub use linux_headers_linux_prctl::PR_GET_THP_DISABLE;
pub use linux_headers_linux_prctl::PR_MPX_ENABLE_MANAGEMENT;
pub use linux_headers_linux_prctl::PR_MPX_DISABLE_MANAGEMENT;
pub use linux_headers_linux_prctl::PR_SET_FP_MODE;
pub use linux_headers_linux_prctl::PR_GET_FP_MODE;
pub use linux_headers_linux_prctl::PR_FP_MODE_FR;
pub use linux_headers_linux_prctl::PR_FP_MODE_FRE;
pub use linux_headers_linux_prctl::PR_CAP_AMBIENT;
pub use linux_headers_linux_prctl::PR_CAP_AMBIENT_IS_SET;
pub use linux_headers_linux_prctl::PR_CAP_AMBIENT_RAISE;
pub use linux_headers_linux_prctl::PR_CAP_AMBIENT_LOWER;
pub use linux_headers_linux_prctl::PR_CAP_AMBIENT_CLEAR_ALL;
pub use linux_headers_linux_prctl::PR_SVE_SET_VL;
pub use linux_headers_linux_prctl::PR_SVE_SET_VL_ONEXEC;
pub use linux_headers_linux_prctl::PR_SVE_GET_VL;
pub use linux_headers_linux_prctl::PR_SVE_VL_LEN_MASK;
pub use linux_headers_linux_prctl::PR_SVE_VL_INHERIT;
pub use linux_headers_linux_prctl::PR_GET_SPECULATION_CTRL;
pub use linux_headers_linux_prctl::PR_SET_SPECULATION_CTRL;
pub use linux_headers_linux_prctl::PR_SPEC_STORE_BYPASS;
pub use linux_headers_linux_prctl::PR_SPEC_INDIRECT_BRANCH;
pub use linux_headers_linux_prctl::PR_SPEC_L1D_FLUSH;
pub use linux_headers_linux_prctl::PR_SPEC_NOT_AFFECTED;
pub use linux_headers_linux_prctl::PR_SPEC_PRCTL;
pub use linux_headers_linux_prctl::PR_SPEC_ENABLE;
pub use linux_headers_linux_prctl::PR_SPEC_DISABLE;
pub use linux_headers_linux_prctl::PR_SPEC_FORCE_DISABLE;
pub use linux_headers_linux_prctl::PR_SPEC_DISABLE_NOEXEC;
pub use linux_headers_linux_prctl::PR_PAC_RESET_KEYS;
pub use linux_headers_linux_prctl::PR_PAC_APIAKEY;
pub use linux_headers_linux_prctl::PR_PAC_APIBKEY;
pub use linux_headers_linux_prctl::PR_PAC_APDAKEY;
pub use linux_headers_linux_prctl::PR_PAC_APDBKEY;
pub use linux_headers_linux_prctl::PR_PAC_APGAKEY;
pub use linux_headers_linux_prctl::PR_SET_TAGGED_ADDR_CTRL;
pub use linux_headers_linux_prctl::PR_GET_TAGGED_ADDR_CTRL;
pub use linux_headers_linux_prctl::PR_TAGGED_ADDR_ENABLE;
pub use linux_headers_linux_prctl::PR_MTE_TCF_NONE;
pub use linux_headers_linux_prctl::PR_MTE_TCF_SYNC;
pub use linux_headers_linux_prctl::PR_MTE_TCF_ASYNC;
pub use linux_headers_linux_prctl::PR_MTE_TCF_MASK;
pub use linux_headers_linux_prctl::PR_MTE_TAG_SHIFT;
pub use linux_headers_linux_prctl::PR_MTE_TAG_MASK;
pub use linux_headers_linux_prctl::PR_MTE_TCF_SHIFT;
pub use linux_headers_linux_prctl::PR_PMLEN_SHIFT;
pub use linux_headers_linux_prctl::PR_PMLEN_MASK;
pub use linux_headers_linux_prctl::PR_SET_IO_FLUSHER;
pub use linux_headers_linux_prctl::PR_GET_IO_FLUSHER;
pub use linux_headers_linux_prctl::PR_SET_SYSCALL_USER_DISPATCH;
pub use linux_headers_linux_prctl::PR_SYS_DISPATCH_OFF;
pub use linux_headers_linux_prctl::PR_SYS_DISPATCH_ON;
pub use linux_headers_linux_prctl::PR_PAC_SET_ENABLED_KEYS;
pub use linux_headers_linux_prctl::PR_PAC_GET_ENABLED_KEYS;
pub use linux_headers_linux_prctl::PR_SCHED_CORE;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_GET;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_CREATE;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_SHARE_TO;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_SHARE_FROM;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_MAX;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_SCOPE_THREAD;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_SCOPE_THREAD_GROUP;
pub use linux_headers_linux_prctl::PR_SCHED_CORE_SCOPE_PROCESS_GROUP;
pub use linux_headers_linux_prctl::PR_SME_SET_VL;
pub use linux_headers_linux_prctl::PR_SME_SET_VL_ONEXEC;
pub use linux_headers_linux_prctl::PR_SME_GET_VL;
pub use linux_headers_linux_prctl::PR_SME_VL_LEN_MASK;
pub use linux_headers_linux_prctl::PR_SME_VL_INHERIT;
pub use linux_headers_linux_prctl::PR_SET_MDWE;
pub use linux_headers_linux_prctl::PR_MDWE_REFUSE_EXEC_GAIN;
pub use linux_headers_linux_prctl::PR_MDWE_NO_INHERIT;
pub use linux_headers_linux_prctl::PR_GET_MDWE;
pub use linux_headers_linux_prctl::PR_SET_VMA;
pub use linux_headers_linux_prctl::PR_SET_VMA_ANON_NAME;
pub use linux_headers_linux_prctl::PR_GET_AUXV;
pub use linux_headers_linux_prctl::PR_SET_MEMORY_MERGE;
pub use linux_headers_linux_prctl::PR_GET_MEMORY_MERGE;
pub use linux_headers_linux_prctl::PR_RISCV_V_SET_CONTROL;
pub use linux_headers_linux_prctl::PR_RISCV_V_GET_CONTROL;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_DEFAULT;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_OFF;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_ON;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_INHERIT;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_CUR_MASK;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_NEXT_MASK;
pub use linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_MASK;
pub use linux_headers_linux_prctl::PR_RISCV_SET_ICACHE_FLUSH_CTX;
pub use linux_headers_linux_prctl::PR_RISCV_CTX_SW_FENCEI_ON;
pub use linux_headers_linux_prctl::PR_RISCV_CTX_SW_FENCEI_OFF;
pub use linux_headers_linux_prctl::PR_RISCV_SCOPE_PER_PROCESS;
pub use linux_headers_linux_prctl::PR_RISCV_SCOPE_PER_THREAD;
pub use linux_headers_linux_prctl::PR_PPC_GET_DEXCR;
pub use linux_headers_linux_prctl::PR_PPC_SET_DEXCR;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_SBHE;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_IBRTPD;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_SRAPD;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_NPHIE;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_EDITABLE;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_SET;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_CLEAR;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_SET_ONEXEC;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC;
pub use linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_MASK;
pub use linux_headers_linux_prctl::PR_GET_SHADOW_STACK_STATUS;
pub use linux_headers_linux_prctl::PR_SET_SHADOW_STACK_STATUS;
pub use linux_headers_linux_prctl::PR_SHADOW_STACK_ENABLE;
pub use linux_headers_linux_prctl::PR_SHADOW_STACK_WRITE;
pub use linux_headers_linux_prctl::PR_SHADOW_STACK_PUSH;
pub use linux_headers_linux_prctl::PR_LOCK_SHADOW_STACK_STATUS;
mod dlfcn;
pub use dlfcn::RTLD_DEFAULT;
pub use dlfcn::dlsym;
mod elf;
pub use elf::Elf32_auxv_t;
pub use elf::Elf64_auxv_t;
mod sys_auxv;
pub use sys_auxv::getauxval;
mod unistd;
pub use unistd::syscall;
pub type c_char = u8;
