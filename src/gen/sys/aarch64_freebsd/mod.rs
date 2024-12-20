// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod dlfcn;
pub use dlfcn::RTLD_DEFAULT;
pub use dlfcn::dlsym;
mod sys_auxv;
pub use sys_auxv::elf_aux_info;
mod sys_syscall;
pub use sys_syscall::SYS_syscall;
pub use sys_syscall::SYS_exit;
pub use sys_syscall::SYS_fork;
pub use sys_syscall::SYS_read;
pub use sys_syscall::SYS_write;
pub use sys_syscall::SYS_open;
pub use sys_syscall::SYS_close;
pub use sys_syscall::SYS_wait4;
pub use sys_syscall::SYS_link;
pub use sys_syscall::SYS_unlink;
pub use sys_syscall::SYS_chdir;
pub use sys_syscall::SYS_fchdir;
pub use sys_syscall::SYS_freebsd11_mknod;
pub use sys_syscall::SYS_chmod;
pub use sys_syscall::SYS_chown;
pub use sys_syscall::SYS_break;
pub use sys_syscall::SYS_getpid;
pub use sys_syscall::SYS_mount;
pub use sys_syscall::SYS_unmount;
pub use sys_syscall::SYS_setuid;
pub use sys_syscall::SYS_getuid;
pub use sys_syscall::SYS_geteuid;
pub use sys_syscall::SYS_ptrace;
pub use sys_syscall::SYS_recvmsg;
pub use sys_syscall::SYS_sendmsg;
pub use sys_syscall::SYS_recvfrom;
pub use sys_syscall::SYS_accept;
pub use sys_syscall::SYS_getpeername;
pub use sys_syscall::SYS_getsockname;
pub use sys_syscall::SYS_access;
pub use sys_syscall::SYS_chflags;
pub use sys_syscall::SYS_fchflags;
pub use sys_syscall::SYS_sync;
pub use sys_syscall::SYS_kill;
pub use sys_syscall::SYS_getppid;
pub use sys_syscall::SYS_dup;
pub use sys_syscall::SYS_freebsd10_pipe;
pub use sys_syscall::SYS_getegid;
pub use sys_syscall::SYS_profil;
pub use sys_syscall::SYS_ktrace;
pub use sys_syscall::SYS_getgid;
pub use sys_syscall::SYS_getlogin;
pub use sys_syscall::SYS_setlogin;
pub use sys_syscall::SYS_acct;
pub use sys_syscall::SYS_sigaltstack;
pub use sys_syscall::SYS_ioctl;
pub use sys_syscall::SYS_reboot;
pub use sys_syscall::SYS_revoke;
pub use sys_syscall::SYS_symlink;
pub use sys_syscall::SYS_readlink;
pub use sys_syscall::SYS_execve;
pub use sys_syscall::SYS_umask;
pub use sys_syscall::SYS_chroot;
pub use sys_syscall::SYS_msync;
pub use sys_syscall::SYS_vfork;
pub use sys_syscall::SYS_freebsd11_vadvise;
pub use sys_syscall::SYS_munmap;
pub use sys_syscall::SYS_mprotect;
pub use sys_syscall::SYS_madvise;
pub use sys_syscall::SYS_mincore;
pub use sys_syscall::SYS_getgroups;
pub use sys_syscall::SYS_setgroups;
pub use sys_syscall::SYS_getpgrp;
pub use sys_syscall::SYS_setpgid;
pub use sys_syscall::SYS_setitimer;
pub use sys_syscall::SYS_swapon;
pub use sys_syscall::SYS_getitimer;
pub use sys_syscall::SYS_getdtablesize;
pub use sys_syscall::SYS_dup2;
pub use sys_syscall::SYS_fcntl;
pub use sys_syscall::SYS_select;
pub use sys_syscall::SYS_fsync;
pub use sys_syscall::SYS_setpriority;
pub use sys_syscall::SYS_socket;
pub use sys_syscall::SYS_connect;
pub use sys_syscall::SYS_getpriority;
pub use sys_syscall::SYS_bind;
pub use sys_syscall::SYS_setsockopt;
pub use sys_syscall::SYS_listen;
pub use sys_syscall::SYS_gettimeofday;
pub use sys_syscall::SYS_getrusage;
pub use sys_syscall::SYS_getsockopt;
pub use sys_syscall::SYS_readv;
pub use sys_syscall::SYS_writev;
pub use sys_syscall::SYS_settimeofday;
pub use sys_syscall::SYS_fchown;
pub use sys_syscall::SYS_fchmod;
pub use sys_syscall::SYS_setreuid;
pub use sys_syscall::SYS_setregid;
pub use sys_syscall::SYS_rename;
pub use sys_syscall::SYS_flock;
pub use sys_syscall::SYS_mkfifo;
pub use sys_syscall::SYS_sendto;
pub use sys_syscall::SYS_shutdown;
pub use sys_syscall::SYS_socketpair;
pub use sys_syscall::SYS_mkdir;
pub use sys_syscall::SYS_rmdir;
pub use sys_syscall::SYS_utimes;
pub use sys_syscall::SYS_adjtime;
pub use sys_syscall::SYS_setsid;
pub use sys_syscall::SYS_quotactl;
pub use sys_syscall::SYS_nlm_syscall;
pub use sys_syscall::SYS_nfssvc;
pub use sys_syscall::SYS_lgetfh;
pub use sys_syscall::SYS_getfh;
pub use sys_syscall::SYS_sysarch;
pub use sys_syscall::SYS_rtprio;
pub use sys_syscall::SYS_semsys;
pub use sys_syscall::SYS_msgsys;
pub use sys_syscall::SYS_shmsys;
pub use sys_syscall::SYS_setfib;
pub use sys_syscall::SYS_ntp_adjtime;
pub use sys_syscall::SYS_setgid;
pub use sys_syscall::SYS_setegid;
pub use sys_syscall::SYS_seteuid;
pub use sys_syscall::SYS_freebsd11_stat;
pub use sys_syscall::SYS_freebsd11_fstat;
pub use sys_syscall::SYS_freebsd11_lstat;
pub use sys_syscall::SYS_pathconf;
pub use sys_syscall::SYS_fpathconf;
pub use sys_syscall::SYS_getrlimit;
pub use sys_syscall::SYS_setrlimit;
pub use sys_syscall::SYS_freebsd11_getdirentries;
pub use sys_syscall::SYS___syscall;
pub use sys_syscall::SYS___sysctl;
pub use sys_syscall::SYS_mlock;
pub use sys_syscall::SYS_munlock;
pub use sys_syscall::SYS_undelete;
pub use sys_syscall::SYS_futimes;
pub use sys_syscall::SYS_getpgid;
pub use sys_syscall::SYS_poll;
pub use sys_syscall::SYS_freebsd7___semctl;
pub use sys_syscall::SYS_semget;
pub use sys_syscall::SYS_semop;
pub use sys_syscall::SYS_freebsd7_msgctl;
pub use sys_syscall::SYS_msgget;
pub use sys_syscall::SYS_msgsnd;
pub use sys_syscall::SYS_msgrcv;
pub use sys_syscall::SYS_shmat;
pub use sys_syscall::SYS_freebsd7_shmctl;
pub use sys_syscall::SYS_shmdt;
pub use sys_syscall::SYS_shmget;
pub use sys_syscall::SYS_clock_gettime;
pub use sys_syscall::SYS_clock_settime;
pub use sys_syscall::SYS_clock_getres;
pub use sys_syscall::SYS_ktimer_create;
pub use sys_syscall::SYS_ktimer_delete;
pub use sys_syscall::SYS_ktimer_settime;
pub use sys_syscall::SYS_ktimer_gettime;
pub use sys_syscall::SYS_ktimer_getoverrun;
pub use sys_syscall::SYS_nanosleep;
pub use sys_syscall::SYS_ffclock_getcounter;
pub use sys_syscall::SYS_ffclock_setestimate;
pub use sys_syscall::SYS_ffclock_getestimate;
pub use sys_syscall::SYS_clock_nanosleep;
pub use sys_syscall::SYS_clock_getcpuclockid2;
pub use sys_syscall::SYS_ntp_gettime;
pub use sys_syscall::SYS_minherit;
pub use sys_syscall::SYS_rfork;
pub use sys_syscall::SYS_issetugid;
pub use sys_syscall::SYS_lchown;
pub use sys_syscall::SYS_aio_read;
pub use sys_syscall::SYS_aio_write;
pub use sys_syscall::SYS_lio_listio;
pub use sys_syscall::SYS_freebsd11_getdents;
pub use sys_syscall::SYS_lchmod;
pub use sys_syscall::SYS_lutimes;
pub use sys_syscall::SYS_freebsd11_nstat;
pub use sys_syscall::SYS_freebsd11_nfstat;
pub use sys_syscall::SYS_freebsd11_nlstat;
pub use sys_syscall::SYS_preadv;
pub use sys_syscall::SYS_pwritev;
pub use sys_syscall::SYS_fhopen;
pub use sys_syscall::SYS_freebsd11_fhstat;
pub use sys_syscall::SYS_modnext;
pub use sys_syscall::SYS_modstat;
pub use sys_syscall::SYS_modfnext;
pub use sys_syscall::SYS_modfind;
pub use sys_syscall::SYS_kldload;
pub use sys_syscall::SYS_kldunload;
pub use sys_syscall::SYS_kldfind;
pub use sys_syscall::SYS_kldnext;
pub use sys_syscall::SYS_kldstat;
pub use sys_syscall::SYS_kldfirstmod;
pub use sys_syscall::SYS_getsid;
pub use sys_syscall::SYS_setresuid;
pub use sys_syscall::SYS_setresgid;
pub use sys_syscall::SYS_aio_return;
pub use sys_syscall::SYS_aio_suspend;
pub use sys_syscall::SYS_aio_cancel;
pub use sys_syscall::SYS_aio_error;
pub use sys_syscall::SYS_yield;
pub use sys_syscall::SYS_mlockall;
pub use sys_syscall::SYS_munlockall;
pub use sys_syscall::SYS___getcwd;
pub use sys_syscall::SYS_sched_setparam;
pub use sys_syscall::SYS_sched_getparam;
pub use sys_syscall::SYS_sched_setscheduler;
pub use sys_syscall::SYS_sched_getscheduler;
pub use sys_syscall::SYS_sched_yield;
pub use sys_syscall::SYS_sched_get_priority_max;
pub use sys_syscall::SYS_sched_get_priority_min;
pub use sys_syscall::SYS_sched_rr_get_interval;
pub use sys_syscall::SYS_utrace;
pub use sys_syscall::SYS_kldsym;
pub use sys_syscall::SYS_jail;
pub use sys_syscall::SYS_nnpfs_syscall;
pub use sys_syscall::SYS_sigprocmask;
pub use sys_syscall::SYS_sigsuspend;
pub use sys_syscall::SYS_sigpending;
pub use sys_syscall::SYS_sigtimedwait;
pub use sys_syscall::SYS_sigwaitinfo;
pub use sys_syscall::SYS___acl_get_file;
pub use sys_syscall::SYS___acl_set_file;
pub use sys_syscall::SYS___acl_get_fd;
pub use sys_syscall::SYS___acl_set_fd;
pub use sys_syscall::SYS___acl_delete_file;
pub use sys_syscall::SYS___acl_delete_fd;
pub use sys_syscall::SYS___acl_aclcheck_file;
pub use sys_syscall::SYS___acl_aclcheck_fd;
pub use sys_syscall::SYS_extattrctl;
pub use sys_syscall::SYS_extattr_set_file;
pub use sys_syscall::SYS_extattr_get_file;
pub use sys_syscall::SYS_extattr_delete_file;
pub use sys_syscall::SYS_aio_waitcomplete;
pub use sys_syscall::SYS_getresuid;
pub use sys_syscall::SYS_getresgid;
pub use sys_syscall::SYS_kqueue;
pub use sys_syscall::SYS_freebsd11_kevent;
pub use sys_syscall::SYS_extattr_set_fd;
pub use sys_syscall::SYS_extattr_get_fd;
pub use sys_syscall::SYS_extattr_delete_fd;
pub use sys_syscall::SYS___setugid;
pub use sys_syscall::SYS_eaccess;
pub use sys_syscall::SYS_afs3_syscall;
pub use sys_syscall::SYS_nmount;
pub use sys_syscall::SYS___mac_get_proc;
pub use sys_syscall::SYS___mac_set_proc;
pub use sys_syscall::SYS___mac_get_fd;
pub use sys_syscall::SYS___mac_get_file;
pub use sys_syscall::SYS___mac_set_fd;
pub use sys_syscall::SYS___mac_set_file;
pub use sys_syscall::SYS_kenv;
pub use sys_syscall::SYS_lchflags;
pub use sys_syscall::SYS_uuidgen;
pub use sys_syscall::SYS_sendfile;
pub use sys_syscall::SYS_mac_syscall;
pub use sys_syscall::SYS_freebsd11_getfsstat;
pub use sys_syscall::SYS_freebsd11_statfs;
pub use sys_syscall::SYS_freebsd11_fstatfs;
pub use sys_syscall::SYS_freebsd11_fhstatfs;
pub use sys_syscall::SYS_ksem_close;
pub use sys_syscall::SYS_ksem_post;
pub use sys_syscall::SYS_ksem_wait;
pub use sys_syscall::SYS_ksem_trywait;
pub use sys_syscall::SYS_ksem_init;
pub use sys_syscall::SYS_ksem_open;
pub use sys_syscall::SYS_ksem_unlink;
pub use sys_syscall::SYS_ksem_getvalue;
pub use sys_syscall::SYS_ksem_destroy;
pub use sys_syscall::SYS___mac_get_pid;
pub use sys_syscall::SYS___mac_get_link;
pub use sys_syscall::SYS___mac_set_link;
pub use sys_syscall::SYS_extattr_set_link;
pub use sys_syscall::SYS_extattr_get_link;
pub use sys_syscall::SYS_extattr_delete_link;
pub use sys_syscall::SYS___mac_execve;
pub use sys_syscall::SYS_sigaction;
pub use sys_syscall::SYS_sigreturn;
pub use sys_syscall::SYS_getcontext;
pub use sys_syscall::SYS_setcontext;
pub use sys_syscall::SYS_swapcontext;
pub use sys_syscall::SYS_freebsd13_swapoff;
pub use sys_syscall::SYS___acl_get_link;
pub use sys_syscall::SYS___acl_set_link;
pub use sys_syscall::SYS___acl_delete_link;
pub use sys_syscall::SYS___acl_aclcheck_link;
pub use sys_syscall::SYS_sigwait;
pub use sys_syscall::SYS_thr_create;
pub use sys_syscall::SYS_thr_exit;
pub use sys_syscall::SYS_thr_self;
pub use sys_syscall::SYS_thr_kill;
pub use sys_syscall::SYS_freebsd10__umtx_lock;
pub use sys_syscall::SYS_freebsd10__umtx_unlock;
pub use sys_syscall::SYS_jail_attach;
pub use sys_syscall::SYS_extattr_list_fd;
pub use sys_syscall::SYS_extattr_list_file;
pub use sys_syscall::SYS_extattr_list_link;
pub use sys_syscall::SYS_ksem_timedwait;
pub use sys_syscall::SYS_thr_suspend;
pub use sys_syscall::SYS_thr_wake;
pub use sys_syscall::SYS_kldunloadf;
pub use sys_syscall::SYS_audit;
pub use sys_syscall::SYS_auditon;
pub use sys_syscall::SYS_getauid;
pub use sys_syscall::SYS_setauid;
pub use sys_syscall::SYS_getaudit;
pub use sys_syscall::SYS_setaudit;
pub use sys_syscall::SYS_getaudit_addr;
pub use sys_syscall::SYS_setaudit_addr;
pub use sys_syscall::SYS_auditctl;
pub use sys_syscall::SYS__umtx_op;
pub use sys_syscall::SYS_thr_new;
pub use sys_syscall::SYS_sigqueue;
pub use sys_syscall::SYS_kmq_open;
pub use sys_syscall::SYS_kmq_setattr;
pub use sys_syscall::SYS_kmq_timedreceive;
pub use sys_syscall::SYS_kmq_timedsend;
pub use sys_syscall::SYS_kmq_notify;
pub use sys_syscall::SYS_kmq_unlink;
pub use sys_syscall::SYS_abort2;
pub use sys_syscall::SYS_thr_set_name;
pub use sys_syscall::SYS_aio_fsync;
pub use sys_syscall::SYS_rtprio_thread;
pub use sys_syscall::SYS_sctp_peeloff;
pub use sys_syscall::SYS_sctp_generic_sendmsg;
pub use sys_syscall::SYS_sctp_generic_sendmsg_iov;
pub use sys_syscall::SYS_sctp_generic_recvmsg;
pub use sys_syscall::SYS_pread;
pub use sys_syscall::SYS_pwrite;
pub use sys_syscall::SYS_mmap;
pub use sys_syscall::SYS_lseek;
pub use sys_syscall::SYS_truncate;
pub use sys_syscall::SYS_ftruncate;
pub use sys_syscall::SYS_thr_kill2;
pub use sys_syscall::SYS_freebsd12_shm_open;
pub use sys_syscall::SYS_shm_unlink;
pub use sys_syscall::SYS_cpuset;
pub use sys_syscall::SYS_cpuset_setid;
pub use sys_syscall::SYS_cpuset_getid;
pub use sys_syscall::SYS_cpuset_getaffinity;
pub use sys_syscall::SYS_cpuset_setaffinity;
pub use sys_syscall::SYS_faccessat;
pub use sys_syscall::SYS_fchmodat;
pub use sys_syscall::SYS_fchownat;
pub use sys_syscall::SYS_fexecve;
pub use sys_syscall::SYS_freebsd11_fstatat;
pub use sys_syscall::SYS_futimesat;
pub use sys_syscall::SYS_linkat;
pub use sys_syscall::SYS_mkdirat;
pub use sys_syscall::SYS_mkfifoat;
pub use sys_syscall::SYS_freebsd11_mknodat;
pub use sys_syscall::SYS_openat;
pub use sys_syscall::SYS_readlinkat;
pub use sys_syscall::SYS_renameat;
pub use sys_syscall::SYS_symlinkat;
pub use sys_syscall::SYS_unlinkat;
pub use sys_syscall::SYS_posix_openpt;
pub use sys_syscall::SYS_gssd_syscall;
pub use sys_syscall::SYS_jail_get;
pub use sys_syscall::SYS_jail_set;
pub use sys_syscall::SYS_jail_remove;
pub use sys_syscall::SYS_freebsd12_closefrom;
pub use sys_syscall::SYS___semctl;
pub use sys_syscall::SYS_msgctl;
pub use sys_syscall::SYS_shmctl;
pub use sys_syscall::SYS_lpathconf;
pub use sys_syscall::SYS___cap_rights_get;
pub use sys_syscall::SYS_cap_enter;
pub use sys_syscall::SYS_cap_getmode;
pub use sys_syscall::SYS_pdfork;
pub use sys_syscall::SYS_pdkill;
pub use sys_syscall::SYS_pdgetpid;
pub use sys_syscall::SYS_pselect;
pub use sys_syscall::SYS_getloginclass;
pub use sys_syscall::SYS_setloginclass;
pub use sys_syscall::SYS_rctl_get_racct;
pub use sys_syscall::SYS_rctl_get_rules;
pub use sys_syscall::SYS_rctl_get_limits;
pub use sys_syscall::SYS_rctl_add_rule;
pub use sys_syscall::SYS_rctl_remove_rule;
pub use sys_syscall::SYS_posix_fallocate;
pub use sys_syscall::SYS_posix_fadvise;
pub use sys_syscall::SYS_wait6;
pub use sys_syscall::SYS_cap_rights_limit;
pub use sys_syscall::SYS_cap_ioctls_limit;
pub use sys_syscall::SYS_cap_ioctls_get;
pub use sys_syscall::SYS_cap_fcntls_limit;
pub use sys_syscall::SYS_cap_fcntls_get;
pub use sys_syscall::SYS_bindat;
pub use sys_syscall::SYS_connectat;
pub use sys_syscall::SYS_chflagsat;
pub use sys_syscall::SYS_accept4;
pub use sys_syscall::SYS_pipe2;
pub use sys_syscall::SYS_aio_mlock;
pub use sys_syscall::SYS_procctl;
pub use sys_syscall::SYS_ppoll;
pub use sys_syscall::SYS_futimens;
pub use sys_syscall::SYS_utimensat;
pub use sys_syscall::SYS_fdatasync;
pub use sys_syscall::SYS_fstat;
pub use sys_syscall::SYS_fstatat;
pub use sys_syscall::SYS_fhstat;
pub use sys_syscall::SYS_getdirentries;
pub use sys_syscall::SYS_statfs;
pub use sys_syscall::SYS_fstatfs;
pub use sys_syscall::SYS_getfsstat;
pub use sys_syscall::SYS_fhstatfs;
pub use sys_syscall::SYS_mknodat;
pub use sys_syscall::SYS_kevent;
pub use sys_syscall::SYS_cpuset_getdomain;
pub use sys_syscall::SYS_cpuset_setdomain;
pub use sys_syscall::SYS_getrandom;
pub use sys_syscall::SYS_getfhat;
pub use sys_syscall::SYS_fhlink;
pub use sys_syscall::SYS_fhlinkat;
pub use sys_syscall::SYS_fhreadlink;
pub use sys_syscall::SYS_funlinkat;
pub use sys_syscall::SYS_copy_file_range;
pub use sys_syscall::SYS___sysctlbyname;
pub use sys_syscall::SYS_shm_open2;
pub use sys_syscall::SYS_shm_rename;
pub use sys_syscall::SYS_sigfastblock;
pub use sys_syscall::SYS___realpathat;
pub use sys_syscall::SYS_close_range;
pub use sys_syscall::SYS_rpctls_syscall;
pub use sys_syscall::SYS___specialfd;
pub use sys_syscall::SYS_aio_writev;
pub use sys_syscall::SYS_aio_readv;
pub use sys_syscall::SYS_fspacectl;
pub use sys_syscall::SYS_sched_getcpu;
pub use sys_syscall::SYS_swapoff;
pub use sys_syscall::SYS_kqueuex;
pub use sys_syscall::SYS_membarrier;
pub use sys_syscall::SYS_timerfd_create;
pub use sys_syscall::SYS_timerfd_gettime;
pub use sys_syscall::SYS_timerfd_settime;
pub use sys_syscall::SYS_kcmp;
pub use sys_syscall::SYS_getrlimitusage;
pub use sys_syscall::SYS_fchroot;
pub use sys_syscall::SYS_setcred;
pub use sys_syscall::SYS_MAXSYSCALL;
mod sys_sysctl;
pub use sys_sysctl::CTL_KERN;
pub use sys_sysctl::KERN_PROC;
pub use sys_sysctl::KERN_PROC_AUXV;
mod sys_elf_common;
pub use sys_elf_common::AT_NULL;
pub use sys_elf_common::AT_IGNORE;
pub use sys_elf_common::AT_EXECFD;
pub use sys_elf_common::AT_PHDR;
pub use sys_elf_common::AT_PHENT;
pub use sys_elf_common::AT_PHNUM;
pub use sys_elf_common::AT_PAGESZ;
pub use sys_elf_common::AT_BASE;
pub use sys_elf_common::AT_FLAGS;
pub use sys_elf_common::AT_ENTRY;
pub use sys_elf_common::AT_NOTELF;
pub use sys_elf_common::AT_UID;
pub use sys_elf_common::AT_EUID;
pub use sys_elf_common::AT_GID;
pub use sys_elf_common::AT_EGID;
pub use sys_elf_common::AT_EXECPATH;
pub use sys_elf_common::AT_CANARY;
pub use sys_elf_common::AT_CANARYLEN;
pub use sys_elf_common::AT_OSRELDATE;
pub use sys_elf_common::AT_NCPUS;
pub use sys_elf_common::AT_PAGESIZES;
pub use sys_elf_common::AT_PAGESIZESLEN;
pub use sys_elf_common::AT_TIMEKEEP;
pub use sys_elf_common::AT_STACKPROT;
pub use sys_elf_common::AT_EHDRFLAGS;
pub use sys_elf_common::AT_HWCAP;
pub use sys_elf_common::AT_HWCAP2;
pub use sys_elf_common::AT_BSDFLAGS;
pub use sys_elf_common::AT_ARGC;
pub use sys_elf_common::AT_ARGV;
pub use sys_elf_common::AT_ENVC;
pub use sys_elf_common::AT_ENVV;
pub use sys_elf_common::AT_PS_STRINGS;
pub use sys_elf_common::AT_FXRNG;
pub use sys_elf_common::AT_KPRELOAD;
pub use sys_elf_common::AT_USRSTACKBASE;
pub use sys_elf_common::AT_USRSTACKLIM;
pub use sys_elf_common::AT_CHERI_STATS;
pub use sys_elf_common::AT_COUNT;
mod machine_elf;
pub use machine_elf::Elf32_Auxinfo;
pub use machine_elf::Elf64_Auxinfo;
pub use machine_elf::Elf_Auxinfo;
pub use machine_elf::HWCAP_FP;
pub use machine_elf::HWCAP_ASIMD;
pub use machine_elf::HWCAP_EVTSTRM;
pub use machine_elf::HWCAP_AES;
pub use machine_elf::HWCAP_PMULL;
pub use machine_elf::HWCAP_SHA1;
pub use machine_elf::HWCAP_SHA2;
pub use machine_elf::HWCAP_CRC32;
pub use machine_elf::HWCAP_ATOMICS;
pub use machine_elf::HWCAP_FPHP;
pub use machine_elf::HWCAP_ASIMDHP;
pub use machine_elf::HWCAP_CPUID;
pub use machine_elf::HWCAP_ASIMDRDM;
pub use machine_elf::HWCAP_JSCVT;
pub use machine_elf::HWCAP_FCMA;
pub use machine_elf::HWCAP_LRCPC;
pub use machine_elf::HWCAP_DCPOP;
pub use machine_elf::HWCAP_SHA3;
pub use machine_elf::HWCAP_SM3;
pub use machine_elf::HWCAP_SM4;
pub use machine_elf::HWCAP_ASIMDDP;
pub use machine_elf::HWCAP_SHA512;
pub use machine_elf::HWCAP_SVE;
pub use machine_elf::HWCAP_ASIMDFHM;
pub use machine_elf::HWCAP_DIT;
pub use machine_elf::HWCAP_USCAT;
pub use machine_elf::HWCAP_ILRCPC;
pub use machine_elf::HWCAP_FLAGM;
pub use machine_elf::HWCAP_SSBS;
pub use machine_elf::HWCAP_SB;
pub use machine_elf::HWCAP_PACA;
pub use machine_elf::HWCAP_PACG;
pub use machine_elf::HWCAP2_DCPODP;
pub use machine_elf::HWCAP2_SVE2;
pub use machine_elf::HWCAP2_SVEAES;
pub use machine_elf::HWCAP2_SVEPMULL;
pub use machine_elf::HWCAP2_SVEBITPERM;
pub use machine_elf::HWCAP2_SVESHA3;
pub use machine_elf::HWCAP2_SVESM4;
pub use machine_elf::HWCAP2_FLAGM2;
pub use machine_elf::HWCAP2_FRINT;
pub use machine_elf::HWCAP2_SVEI8MM;
pub use machine_elf::HWCAP2_SVEF32MM;
pub use machine_elf::HWCAP2_SVEF64MM;
pub use machine_elf::HWCAP2_SVEBF16;
pub use machine_elf::HWCAP2_I8MM;
pub use machine_elf::HWCAP2_BF16;
pub use machine_elf::HWCAP2_DGH;
pub use machine_elf::HWCAP2_RNG;
pub use machine_elf::HWCAP2_BTI;
pub use machine_elf::HWCAP2_MTE;
pub use machine_elf::HWCAP2_ECV;
pub use machine_elf::HWCAP2_AFP;
pub use machine_elf::HWCAP2_RPRES;
pub use machine_elf::HWCAP2_MTE3;
pub use machine_elf::HWCAP2_SME;
pub use machine_elf::HWCAP2_SME_I16I64;
pub use machine_elf::HWCAP2_SME_F64F64;
pub use machine_elf::HWCAP2_SME_I8I32;
pub use machine_elf::HWCAP2_SME_F16F32;
pub use machine_elf::HWCAP2_SME_B16F32;
pub use machine_elf::HWCAP2_SME_F32F32;
pub use machine_elf::HWCAP2_SME_FA64;
pub use machine_elf::HWCAP2_WFXT;
pub use machine_elf::HWCAP2_EBF16;
pub use machine_elf::HWCAP2_SVE_EBF16;
pub use machine_elf::HWCAP2_CSSC;
pub use machine_elf::HWCAP2_RPRFM;
pub use machine_elf::HWCAP2_SVE2P1;
pub use machine_elf::HWCAP2_SME2;
pub use machine_elf::HWCAP2_SME2P1;
pub use machine_elf::HWCAP2_SME_I16I32;
pub use machine_elf::HWCAP2_SME_BI32I32;
pub use machine_elf::HWCAP2_SME_B16B16;
pub use machine_elf::HWCAP2_SME_F16F16;
pub use machine_elf::HWCAP2_MOPS;
pub use machine_elf::HWCAP2_HBC;
pub type c_char = u8;
