// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod sys_syscall;
pub use self::sys_syscall::SYS_MAXSYSARGS;
pub use self::sys_syscall::SYS_syscall;
pub use self::sys_syscall::SYS_exit;
pub use self::sys_syscall::SYS_fork;
pub use self::sys_syscall::SYS_read;
pub use self::sys_syscall::SYS_write;
pub use self::sys_syscall::SYS_open;
pub use self::sys_syscall::SYS_close;
pub use self::sys_syscall::SYS_compat_50_wait4;
pub use self::sys_syscall::SYS_compat_43_ocreat;
pub use self::sys_syscall::SYS_link;
pub use self::sys_syscall::SYS_unlink;
pub use self::sys_syscall::SYS_chdir;
pub use self::sys_syscall::SYS_fchdir;
pub use self::sys_syscall::SYS_compat_50_mknod;
pub use self::sys_syscall::SYS_chmod;
pub use self::sys_syscall::SYS_chown;
pub use self::sys_syscall::SYS_break;
pub use self::sys_syscall::SYS_compat_20_getfsstat;
pub use self::sys_syscall::SYS_compat_43_olseek;
pub use self::sys_syscall::SYS_getpid;
pub use self::sys_syscall::SYS_compat_40_mount;
pub use self::sys_syscall::SYS_unmount;
pub use self::sys_syscall::SYS_setuid;
pub use self::sys_syscall::SYS_getuid;
pub use self::sys_syscall::SYS_geteuid;
pub use self::sys_syscall::SYS_ptrace;
pub use self::sys_syscall::SYS_recvmsg;
pub use self::sys_syscall::SYS_sendmsg;
pub use self::sys_syscall::SYS_recvfrom;
pub use self::sys_syscall::SYS_accept;
pub use self::sys_syscall::SYS_getpeername;
pub use self::sys_syscall::SYS_getsockname;
pub use self::sys_syscall::SYS_access;
pub use self::sys_syscall::SYS_chflags;
pub use self::sys_syscall::SYS_fchflags;
pub use self::sys_syscall::SYS_sync;
pub use self::sys_syscall::SYS_kill;
pub use self::sys_syscall::SYS_compat_43_stat43;
pub use self::sys_syscall::SYS_getppid;
pub use self::sys_syscall::SYS_compat_43_lstat43;
pub use self::sys_syscall::SYS_dup;
pub use self::sys_syscall::SYS_pipe;
pub use self::sys_syscall::SYS_getegid;
pub use self::sys_syscall::SYS_profil;
pub use self::sys_syscall::SYS_ktrace;
pub use self::sys_syscall::SYS_compat_13_sigaction13;
pub use self::sys_syscall::SYS_getgid;
pub use self::sys_syscall::SYS_compat_13_sigprocmask13;
pub use self::sys_syscall::SYS___getlogin;
pub use self::sys_syscall::SYS___setlogin;
pub use self::sys_syscall::SYS_acct;
pub use self::sys_syscall::SYS_compat_13_sigpending13;
pub use self::sys_syscall::SYS_compat_13_sigaltstack13;
pub use self::sys_syscall::SYS_ioctl;
pub use self::sys_syscall::SYS_compat_12_oreboot;
pub use self::sys_syscall::SYS_revoke;
pub use self::sys_syscall::SYS_symlink;
pub use self::sys_syscall::SYS_readlink;
pub use self::sys_syscall::SYS_execve;
pub use self::sys_syscall::SYS_umask;
pub use self::sys_syscall::SYS_chroot;
pub use self::sys_syscall::SYS_compat_43_fstat43;
pub use self::sys_syscall::SYS_compat_43_ogetkerninfo;
pub use self::sys_syscall::SYS_compat_43_ogetpagesize;
pub use self::sys_syscall::SYS_compat_12_msync;
pub use self::sys_syscall::SYS_vfork;
pub use self::sys_syscall::SYS_compat_43_ommap;
pub use self::sys_syscall::SYS_vadvise;
pub use self::sys_syscall::SYS_munmap;
pub use self::sys_syscall::SYS_mprotect;
pub use self::sys_syscall::SYS_madvise;
pub use self::sys_syscall::SYS_mincore;
pub use self::sys_syscall::SYS_getgroups;
pub use self::sys_syscall::SYS_setgroups;
pub use self::sys_syscall::SYS_getpgrp;
pub use self::sys_syscall::SYS_setpgid;
pub use self::sys_syscall::SYS_compat_50_setitimer;
pub use self::sys_syscall::SYS_compat_43_owait;
pub use self::sys_syscall::SYS_compat_12_oswapon;
pub use self::sys_syscall::SYS_compat_50_getitimer;
pub use self::sys_syscall::SYS_compat_43_ogethostname;
pub use self::sys_syscall::SYS_compat_43_osethostname;
pub use self::sys_syscall::SYS_compat_43_ogetdtablesize;
pub use self::sys_syscall::SYS_dup2;
pub use self::sys_syscall::SYS_getrandom;
pub use self::sys_syscall::SYS_fcntl;
pub use self::sys_syscall::SYS_compat_50_select;
pub use self::sys_syscall::SYS_fsync;
pub use self::sys_syscall::SYS_setpriority;
pub use self::sys_syscall::SYS_compat_30_socket;
pub use self::sys_syscall::SYS_connect;
pub use self::sys_syscall::SYS_compat_43_oaccept;
pub use self::sys_syscall::SYS_getpriority;
pub use self::sys_syscall::SYS_compat_43_osend;
pub use self::sys_syscall::SYS_compat_43_orecv;
pub use self::sys_syscall::SYS_compat_13_sigreturn13;
pub use self::sys_syscall::SYS_bind;
pub use self::sys_syscall::SYS_setsockopt;
pub use self::sys_syscall::SYS_listen;
pub use self::sys_syscall::SYS_compat_43_osigvec;
pub use self::sys_syscall::SYS_compat_43_osigblock;
pub use self::sys_syscall::SYS_compat_43_osigsetmask;
pub use self::sys_syscall::SYS_compat_13_sigsuspend13;
pub use self::sys_syscall::SYS_compat_43_osigstack;
pub use self::sys_syscall::SYS_compat_43_orecvmsg;
pub use self::sys_syscall::SYS_compat_43_osendmsg;
pub use self::sys_syscall::SYS_compat_50_gettimeofday;
pub use self::sys_syscall::SYS_compat_50_getrusage;
pub use self::sys_syscall::SYS_getsockopt;
pub use self::sys_syscall::SYS_readv;
pub use self::sys_syscall::SYS_writev;
pub use self::sys_syscall::SYS_compat_50_settimeofday;
pub use self::sys_syscall::SYS_fchown;
pub use self::sys_syscall::SYS_fchmod;
pub use self::sys_syscall::SYS_compat_43_orecvfrom;
pub use self::sys_syscall::SYS_setreuid;
pub use self::sys_syscall::SYS_setregid;
pub use self::sys_syscall::SYS_rename;
pub use self::sys_syscall::SYS_compat_43_otruncate;
pub use self::sys_syscall::SYS_compat_43_oftruncate;
pub use self::sys_syscall::SYS_flock;
pub use self::sys_syscall::SYS_mkfifo;
pub use self::sys_syscall::SYS_sendto;
pub use self::sys_syscall::SYS_shutdown;
pub use self::sys_syscall::SYS_socketpair;
pub use self::sys_syscall::SYS_mkdir;
pub use self::sys_syscall::SYS_rmdir;
pub use self::sys_syscall::SYS_compat_50_utimes;
pub use self::sys_syscall::SYS_compat_50_adjtime;
pub use self::sys_syscall::SYS_compat_43_ogetpeername;
pub use self::sys_syscall::SYS_compat_43_ogethostid;
pub use self::sys_syscall::SYS_compat_43_osethostid;
pub use self::sys_syscall::SYS_compat_43_ogetrlimit;
pub use self::sys_syscall::SYS_compat_43_osetrlimit;
pub use self::sys_syscall::SYS_compat_43_okillpg;
pub use self::sys_syscall::SYS_setsid;
pub use self::sys_syscall::SYS_compat_50_quotactl;
pub use self::sys_syscall::SYS_compat_43_oquota;
pub use self::sys_syscall::SYS_compat_43_ogetsockname;
pub use self::sys_syscall::SYS_nfssvc;
pub use self::sys_syscall::SYS_compat_43_ogetdirentries;
pub use self::sys_syscall::SYS_compat_20_statfs;
pub use self::sys_syscall::SYS_compat_20_fstatfs;
pub use self::sys_syscall::SYS_compat_30_getfh;
pub use self::sys_syscall::SYS_compat_09_ogetdomainname;
pub use self::sys_syscall::SYS_compat_09_osetdomainname;
pub use self::sys_syscall::SYS_compat_09_ouname;
pub use self::sys_syscall::SYS_sysarch;
pub use self::sys_syscall::SYS___futex;
pub use self::sys_syscall::SYS___futex_set_robust_list;
pub use self::sys_syscall::SYS___futex_get_robust_list;
pub use self::sys_syscall::SYS_compat_10_osemsys;
pub use self::sys_syscall::SYS_compat_10_omsgsys;
pub use self::sys_syscall::SYS_compat_10_oshmsys;
pub use self::sys_syscall::SYS_pread;
pub use self::sys_syscall::SYS_pwrite;
pub use self::sys_syscall::SYS_compat_30_ntp_gettime;
pub use self::sys_syscall::SYS_ntp_adjtime;
pub use self::sys_syscall::SYS_timerfd_create;
pub use self::sys_syscall::SYS_timerfd_settime;
pub use self::sys_syscall::SYS_timerfd_gettime;
pub use self::sys_syscall::SYS_setgid;
pub use self::sys_syscall::SYS_setegid;
pub use self::sys_syscall::SYS_seteuid;
pub use self::sys_syscall::SYS_lfs_bmapv;
pub use self::sys_syscall::SYS_lfs_markv;
pub use self::sys_syscall::SYS_lfs_segclean;
pub use self::sys_syscall::SYS_compat_50_lfs_segwait;
pub use self::sys_syscall::SYS_compat_12_stat12;
pub use self::sys_syscall::SYS_compat_12_fstat12;
pub use self::sys_syscall::SYS_compat_12_lstat12;
pub use self::sys_syscall::SYS_pathconf;
pub use self::sys_syscall::SYS_fpathconf;
pub use self::sys_syscall::SYS_getsockopt2;
pub use self::sys_syscall::SYS_getrlimit;
pub use self::sys_syscall::SYS_setrlimit;
pub use self::sys_syscall::SYS_compat_12_getdirentries;
pub use self::sys_syscall::SYS_mmap;
pub use self::sys_syscall::SYS___syscall;
pub use self::sys_syscall::SYS_lseek;
pub use self::sys_syscall::SYS_truncate;
pub use self::sys_syscall::SYS_ftruncate;
pub use self::sys_syscall::SYS___sysctl;
pub use self::sys_syscall::SYS_mlock;
pub use self::sys_syscall::SYS_munlock;
pub use self::sys_syscall::SYS_undelete;
pub use self::sys_syscall::SYS_compat_50_futimes;
pub use self::sys_syscall::SYS_getpgid;
pub use self::sys_syscall::SYS_reboot;
pub use self::sys_syscall::SYS_poll;
pub use self::sys_syscall::SYS_afssys;
pub use self::sys_syscall::SYS_compat_14___semctl;
pub use self::sys_syscall::SYS_semget;
pub use self::sys_syscall::SYS_semop;
pub use self::sys_syscall::SYS_semconfig;
pub use self::sys_syscall::SYS_compat_14_msgctl;
pub use self::sys_syscall::SYS_msgget;
pub use self::sys_syscall::SYS_msgsnd;
pub use self::sys_syscall::SYS_msgrcv;
pub use self::sys_syscall::SYS_shmat;
pub use self::sys_syscall::SYS_compat_14_shmctl;
pub use self::sys_syscall::SYS_shmdt;
pub use self::sys_syscall::SYS_shmget;
pub use self::sys_syscall::SYS_compat_50_clock_gettime;
pub use self::sys_syscall::SYS_compat_50_clock_settime;
pub use self::sys_syscall::SYS_compat_50_clock_getres;
pub use self::sys_syscall::SYS_timer_create;
pub use self::sys_syscall::SYS_timer_delete;
pub use self::sys_syscall::SYS_compat_50_timer_settime;
pub use self::sys_syscall::SYS_compat_50_timer_gettime;
pub use self::sys_syscall::SYS_timer_getoverrun;
pub use self::sys_syscall::SYS_compat_50_nanosleep;
pub use self::sys_syscall::SYS_fdatasync;
pub use self::sys_syscall::SYS_mlockall;
pub use self::sys_syscall::SYS_munlockall;
pub use self::sys_syscall::SYS_compat_50___sigtimedwait;
pub use self::sys_syscall::SYS_sigqueueinfo;
pub use self::sys_syscall::SYS_modctl;
pub use self::sys_syscall::SYS__ksem_init;
pub use self::sys_syscall::SYS__ksem_open;
pub use self::sys_syscall::SYS__ksem_unlink;
pub use self::sys_syscall::SYS__ksem_close;
pub use self::sys_syscall::SYS__ksem_post;
pub use self::sys_syscall::SYS__ksem_wait;
pub use self::sys_syscall::SYS__ksem_trywait;
pub use self::sys_syscall::SYS__ksem_getvalue;
pub use self::sys_syscall::SYS__ksem_destroy;
pub use self::sys_syscall::SYS__ksem_timedwait;
pub use self::sys_syscall::SYS_mq_open;
pub use self::sys_syscall::SYS_mq_close;
pub use self::sys_syscall::SYS_mq_unlink;
pub use self::sys_syscall::SYS_mq_getattr;
pub use self::sys_syscall::SYS_mq_setattr;
pub use self::sys_syscall::SYS_mq_notify;
pub use self::sys_syscall::SYS_mq_send;
pub use self::sys_syscall::SYS_mq_receive;
pub use self::sys_syscall::SYS_compat_50_mq_timedsend;
pub use self::sys_syscall::SYS_compat_50_mq_timedreceive;
pub use self::sys_syscall::SYS_eventfd;
pub use self::sys_syscall::SYS___posix_rename;
pub use self::sys_syscall::SYS_swapctl;
pub use self::sys_syscall::SYS_compat_30_getdents;
pub use self::sys_syscall::SYS_minherit;
pub use self::sys_syscall::SYS_lchmod;
pub use self::sys_syscall::SYS_lchown;
pub use self::sys_syscall::SYS_compat_50_lutimes;
pub use self::sys_syscall::SYS___msync13;
pub use self::sys_syscall::SYS_compat_30___stat13;
pub use self::sys_syscall::SYS_compat_30___fstat13;
pub use self::sys_syscall::SYS_compat_30___lstat13;
pub use self::sys_syscall::SYS___sigaltstack14;
pub use self::sys_syscall::SYS___vfork14;
pub use self::sys_syscall::SYS___posix_chown;
pub use self::sys_syscall::SYS___posix_fchown;
pub use self::sys_syscall::SYS___posix_lchown;
pub use self::sys_syscall::SYS_getsid;
pub use self::sys_syscall::SYS___clone;
pub use self::sys_syscall::SYS_fktrace;
pub use self::sys_syscall::SYS_preadv;
pub use self::sys_syscall::SYS_pwritev;
pub use self::sys_syscall::SYS_compat_16___sigaction14;
pub use self::sys_syscall::SYS___sigpending14;
pub use self::sys_syscall::SYS___sigprocmask14;
pub use self::sys_syscall::SYS___sigsuspend14;
pub use self::sys_syscall::SYS_compat_16___sigreturn14;
pub use self::sys_syscall::SYS___getcwd;
pub use self::sys_syscall::SYS_fchroot;
pub use self::sys_syscall::SYS_compat_30_fhopen;
pub use self::sys_syscall::SYS_compat_30_fhstat;
pub use self::sys_syscall::SYS_compat_20_fhstatfs;
pub use self::sys_syscall::SYS_compat_50_____semctl13;
pub use self::sys_syscall::SYS_compat_50___msgctl13;
pub use self::sys_syscall::SYS_compat_50___shmctl13;
pub use self::sys_syscall::SYS_lchflags;
pub use self::sys_syscall::SYS_issetugid;
pub use self::sys_syscall::SYS_utrace;
pub use self::sys_syscall::SYS_getcontext;
pub use self::sys_syscall::SYS_setcontext;
pub use self::sys_syscall::SYS__lwp_create;
pub use self::sys_syscall::SYS__lwp_exit;
pub use self::sys_syscall::SYS__lwp_self;
pub use self::sys_syscall::SYS__lwp_wait;
pub use self::sys_syscall::SYS__lwp_suspend;
pub use self::sys_syscall::SYS__lwp_continue;
pub use self::sys_syscall::SYS__lwp_wakeup;
pub use self::sys_syscall::SYS__lwp_getprivate;
pub use self::sys_syscall::SYS__lwp_setprivate;
pub use self::sys_syscall::SYS__lwp_kill;
pub use self::sys_syscall::SYS__lwp_detach;
pub use self::sys_syscall::SYS_compat_50__lwp_park;
pub use self::sys_syscall::SYS__lwp_unpark;
pub use self::sys_syscall::SYS__lwp_unpark_all;
pub use self::sys_syscall::SYS__lwp_setname;
pub use self::sys_syscall::SYS__lwp_getname;
pub use self::sys_syscall::SYS__lwp_ctl;
pub use self::sys_syscall::SYS_compat_60_sa_register;
pub use self::sys_syscall::SYS_compat_60_sa_stacks;
pub use self::sys_syscall::SYS_compat_60_sa_enable;
pub use self::sys_syscall::SYS_compat_60_sa_setconcurrency;
pub use self::sys_syscall::SYS_compat_60_sa_yield;
pub use self::sys_syscall::SYS_compat_60_sa_preempt;
pub use self::sys_syscall::SYS___sigaction_sigtramp;
pub use self::sys_syscall::SYS_rasctl;
pub use self::sys_syscall::SYS_kqueue;
pub use self::sys_syscall::SYS_compat_50_kevent;
pub use self::sys_syscall::SYS__sched_setparam;
pub use self::sys_syscall::SYS__sched_getparam;
pub use self::sys_syscall::SYS__sched_setaffinity;
pub use self::sys_syscall::SYS__sched_getaffinity;
pub use self::sys_syscall::SYS_sched_yield;
pub use self::sys_syscall::SYS__sched_protect;
pub use self::sys_syscall::SYS_fsync_range;
pub use self::sys_syscall::SYS_uuidgen;
pub use self::sys_syscall::SYS_compat_90_getvfsstat;
pub use self::sys_syscall::SYS_compat_90_statvfs1;
pub use self::sys_syscall::SYS_compat_90_fstatvfs1;
pub use self::sys_syscall::SYS_compat_30_fhstatvfs1;
pub use self::sys_syscall::SYS_extattrctl;
pub use self::sys_syscall::SYS_extattr_set_file;
pub use self::sys_syscall::SYS_extattr_get_file;
pub use self::sys_syscall::SYS_extattr_delete_file;
pub use self::sys_syscall::SYS_extattr_set_fd;
pub use self::sys_syscall::SYS_extattr_get_fd;
pub use self::sys_syscall::SYS_extattr_delete_fd;
pub use self::sys_syscall::SYS_extattr_set_link;
pub use self::sys_syscall::SYS_extattr_get_link;
pub use self::sys_syscall::SYS_extattr_delete_link;
pub use self::sys_syscall::SYS_extattr_list_fd;
pub use self::sys_syscall::SYS_extattr_list_file;
pub use self::sys_syscall::SYS_extattr_list_link;
pub use self::sys_syscall::SYS_compat_50_pselect;
pub use self::sys_syscall::SYS_compat_50_pollts;
pub use self::sys_syscall::SYS_setxattr;
pub use self::sys_syscall::SYS_lsetxattr;
pub use self::sys_syscall::SYS_fsetxattr;
pub use self::sys_syscall::SYS_getxattr;
pub use self::sys_syscall::SYS_lgetxattr;
pub use self::sys_syscall::SYS_fgetxattr;
pub use self::sys_syscall::SYS_listxattr;
pub use self::sys_syscall::SYS_llistxattr;
pub use self::sys_syscall::SYS_flistxattr;
pub use self::sys_syscall::SYS_removexattr;
pub use self::sys_syscall::SYS_lremovexattr;
pub use self::sys_syscall::SYS_fremovexattr;
pub use self::sys_syscall::SYS_compat_50___stat30;
pub use self::sys_syscall::SYS_compat_50___fstat30;
pub use self::sys_syscall::SYS_compat_50___lstat30;
pub use self::sys_syscall::SYS___getdents30;
pub use self::sys_syscall::SYS_compat_30___fhstat30;
pub use self::sys_syscall::SYS_compat_50___ntp_gettime30;
pub use self::sys_syscall::SYS___socket30;
pub use self::sys_syscall::SYS___getfh30;
pub use self::sys_syscall::SYS___fhopen40;
pub use self::sys_syscall::SYS_compat_90_fhstatvfs1;
pub use self::sys_syscall::SYS_compat_50___fhstat40;
pub use self::sys_syscall::SYS_aio_cancel;
pub use self::sys_syscall::SYS_aio_error;
pub use self::sys_syscall::SYS_aio_fsync;
pub use self::sys_syscall::SYS_aio_read;
pub use self::sys_syscall::SYS_aio_return;
pub use self::sys_syscall::SYS_compat_50_aio_suspend;
pub use self::sys_syscall::SYS_aio_write;
pub use self::sys_syscall::SYS_lio_listio;
pub use self::sys_syscall::SYS___mount50;
pub use self::sys_syscall::SYS_mremap;
pub use self::sys_syscall::SYS_pset_create;
pub use self::sys_syscall::SYS_pset_destroy;
pub use self::sys_syscall::SYS_pset_assign;
pub use self::sys_syscall::SYS__pset_bind;
pub use self::sys_syscall::SYS___posix_fadvise50;
pub use self::sys_syscall::SYS___select50;
pub use self::sys_syscall::SYS___gettimeofday50;
pub use self::sys_syscall::SYS___settimeofday50;
pub use self::sys_syscall::SYS___utimes50;
pub use self::sys_syscall::SYS___adjtime50;
pub use self::sys_syscall::SYS___lfs_segwait50;
pub use self::sys_syscall::SYS___futimes50;
pub use self::sys_syscall::SYS___lutimes50;
pub use self::sys_syscall::SYS___setitimer50;
pub use self::sys_syscall::SYS___getitimer50;
pub use self::sys_syscall::SYS___clock_gettime50;
pub use self::sys_syscall::SYS___clock_settime50;
pub use self::sys_syscall::SYS___clock_getres50;
pub use self::sys_syscall::SYS___nanosleep50;
pub use self::sys_syscall::SYS_____sigtimedwait50;
pub use self::sys_syscall::SYS___mq_timedsend50;
pub use self::sys_syscall::SYS___mq_timedreceive50;
pub use self::sys_syscall::SYS_compat_60__lwp_park;
pub use self::sys_syscall::SYS_compat_100___kevent50;
pub use self::sys_syscall::SYS___pselect50;
pub use self::sys_syscall::SYS___pollts50;
pub use self::sys_syscall::SYS___aio_suspend50;
pub use self::sys_syscall::SYS___stat50;
pub use self::sys_syscall::SYS___fstat50;
pub use self::sys_syscall::SYS___lstat50;
pub use self::sys_syscall::SYS_____semctl50;
pub use self::sys_syscall::SYS___shmctl50;
pub use self::sys_syscall::SYS___msgctl50;
pub use self::sys_syscall::SYS___getrusage50;
pub use self::sys_syscall::SYS___timer_settime50;
pub use self::sys_syscall::SYS___timer_gettime50;
pub use self::sys_syscall::SYS___ntp_gettime50;
pub use self::sys_syscall::SYS___wait450;
pub use self::sys_syscall::SYS___mknod50;
pub use self::sys_syscall::SYS___fhstat50;
pub use self::sys_syscall::SYS_pipe2;
pub use self::sys_syscall::SYS_compat_100_dup3;
pub use self::sys_syscall::SYS_kqueue1;
pub use self::sys_syscall::SYS_paccept;
pub use self::sys_syscall::SYS_linkat;
pub use self::sys_syscall::SYS_renameat;
pub use self::sys_syscall::SYS_mkfifoat;
pub use self::sys_syscall::SYS_mknodat;
pub use self::sys_syscall::SYS_mkdirat;
pub use self::sys_syscall::SYS_faccessat;
pub use self::sys_syscall::SYS_fchmodat;
pub use self::sys_syscall::SYS_fchownat;
pub use self::sys_syscall::SYS_fexecve;
pub use self::sys_syscall::SYS_fstatat;
pub use self::sys_syscall::SYS_utimensat;
pub use self::sys_syscall::SYS_openat;
pub use self::sys_syscall::SYS_readlinkat;
pub use self::sys_syscall::SYS_symlinkat;
pub use self::sys_syscall::SYS_unlinkat;
pub use self::sys_syscall::SYS_futimens;
pub use self::sys_syscall::SYS___quotactl;
pub use self::sys_syscall::SYS_posix_spawn;
pub use self::sys_syscall::SYS_recvmmsg;
pub use self::sys_syscall::SYS_sendmmsg;
pub use self::sys_syscall::SYS_clock_nanosleep;
pub use self::sys_syscall::SYS____lwp_park60;
pub use self::sys_syscall::SYS_posix_fallocate;
pub use self::sys_syscall::SYS_fdiscard;
pub use self::sys_syscall::SYS_wait6;
pub use self::sys_syscall::SYS_clock_getcpuclockid2;
pub use self::sys_syscall::SYS___getvfsstat90;
pub use self::sys_syscall::SYS___statvfs190;
pub use self::sys_syscall::SYS___fstatvfs190;
pub use self::sys_syscall::SYS___fhstatvfs190;
pub use self::sys_syscall::SYS___acl_get_link;
pub use self::sys_syscall::SYS___acl_set_link;
pub use self::sys_syscall::SYS___acl_delete_link;
pub use self::sys_syscall::SYS___acl_aclcheck_link;
pub use self::sys_syscall::SYS___acl_get_file;
pub use self::sys_syscall::SYS___acl_set_file;
pub use self::sys_syscall::SYS___acl_get_fd;
pub use self::sys_syscall::SYS___acl_set_fd;
pub use self::sys_syscall::SYS___acl_delete_file;
pub use self::sys_syscall::SYS___acl_delete_fd;
pub use self::sys_syscall::SYS___acl_aclcheck_file;
pub use self::sys_syscall::SYS___acl_aclcheck_fd;
pub use self::sys_syscall::SYS_lpathconf;
pub use self::sys_syscall::SYS_memfd_create;
pub use self::sys_syscall::SYS___kevent100;
pub use self::sys_syscall::SYS_epoll_create1;
pub use self::sys_syscall::SYS_epoll_ctl;
pub use self::sys_syscall::SYS_epoll_pwait2;
pub use self::sys_syscall::SYS___dup3100;
pub use self::sys_syscall::SYS_semtimedop;
pub use self::sys_syscall::SYS_MAXSYSCALL;
pub use self::sys_syscall::SYS_NSYSENT;
mod sys_sysctl;
pub use self::sys_sysctl::SYSCTL_VERS_1;
pub use self::sys_sysctl::SYSCTL_VERSION;
pub use self::sys_sysctl::CTL_QUERY;
pub use self::sys_sysctl::CTL_MACHDEP;
pub use self::sys_sysctl::sysctl;
pub use self::sys_sysctl::sysctlbyname;
pub use self::sys_sysctl::sysctlnode;
mod machine_cpu;
pub use self::machine_cpu::CPU_BOOTED_KERNEL;
pub use self::machine_cpu::CPU_BOOTED_DEVICE;
pub use self::machine_cpu::CPU_BOOT_ARGS;
pub use self::machine_cpu::CPU_ARCH;
pub type c_char = i8;
