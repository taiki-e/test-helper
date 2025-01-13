// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod dlfcn;
pub use self::dlfcn::RTLD_DEFAULT;
pub use self::dlfcn::dlsym;
mod sys_auxv;
pub use self::sys_auxv::elf_aux_info;
mod sys_syscall;
pub use self::sys_syscall::SYS_syscall;
pub use self::sys_syscall::SYS_exit;
pub use self::sys_syscall::SYS_fork;
pub use self::sys_syscall::SYS_read;
pub use self::sys_syscall::SYS_write;
pub use self::sys_syscall::SYS_open;
pub use self::sys_syscall::SYS_close;
pub use self::sys_syscall::SYS_wait4;
pub use self::sys_syscall::SYS_link;
pub use self::sys_syscall::SYS_unlink;
pub use self::sys_syscall::SYS_chdir;
pub use self::sys_syscall::SYS_fchdir;
pub use self::sys_syscall::SYS_freebsd11_mknod;
pub use self::sys_syscall::SYS_chmod;
pub use self::sys_syscall::SYS_chown;
pub use self::sys_syscall::SYS_break;
pub use self::sys_syscall::SYS_getpid;
pub use self::sys_syscall::SYS_mount;
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
pub use self::sys_syscall::SYS_getppid;
pub use self::sys_syscall::SYS_dup;
pub use self::sys_syscall::SYS_freebsd10_pipe;
pub use self::sys_syscall::SYS_getegid;
pub use self::sys_syscall::SYS_profil;
pub use self::sys_syscall::SYS_ktrace;
pub use self::sys_syscall::SYS_getgid;
pub use self::sys_syscall::SYS_getlogin;
pub use self::sys_syscall::SYS_setlogin;
pub use self::sys_syscall::SYS_acct;
pub use self::sys_syscall::SYS_sigaltstack;
pub use self::sys_syscall::SYS_ioctl;
pub use self::sys_syscall::SYS_reboot;
pub use self::sys_syscall::SYS_revoke;
pub use self::sys_syscall::SYS_symlink;
pub use self::sys_syscall::SYS_readlink;
pub use self::sys_syscall::SYS_execve;
pub use self::sys_syscall::SYS_umask;
pub use self::sys_syscall::SYS_chroot;
pub use self::sys_syscall::SYS_msync;
pub use self::sys_syscall::SYS_vfork;
pub use self::sys_syscall::SYS_freebsd11_vadvise;
pub use self::sys_syscall::SYS_munmap;
pub use self::sys_syscall::SYS_mprotect;
pub use self::sys_syscall::SYS_madvise;
pub use self::sys_syscall::SYS_mincore;
pub use self::sys_syscall::SYS_getgroups;
pub use self::sys_syscall::SYS_setgroups;
pub use self::sys_syscall::SYS_getpgrp;
pub use self::sys_syscall::SYS_setpgid;
pub use self::sys_syscall::SYS_setitimer;
pub use self::sys_syscall::SYS_swapon;
pub use self::sys_syscall::SYS_getitimer;
pub use self::sys_syscall::SYS_getdtablesize;
pub use self::sys_syscall::SYS_dup2;
pub use self::sys_syscall::SYS_fcntl;
pub use self::sys_syscall::SYS_select;
pub use self::sys_syscall::SYS_fsync;
pub use self::sys_syscall::SYS_setpriority;
pub use self::sys_syscall::SYS_socket;
pub use self::sys_syscall::SYS_connect;
pub use self::sys_syscall::SYS_getpriority;
pub use self::sys_syscall::SYS_bind;
pub use self::sys_syscall::SYS_setsockopt;
pub use self::sys_syscall::SYS_listen;
pub use self::sys_syscall::SYS_gettimeofday;
pub use self::sys_syscall::SYS_getrusage;
pub use self::sys_syscall::SYS_getsockopt;
pub use self::sys_syscall::SYS_readv;
pub use self::sys_syscall::SYS_writev;
pub use self::sys_syscall::SYS_settimeofday;
pub use self::sys_syscall::SYS_fchown;
pub use self::sys_syscall::SYS_fchmod;
pub use self::sys_syscall::SYS_setreuid;
pub use self::sys_syscall::SYS_setregid;
pub use self::sys_syscall::SYS_rename;
pub use self::sys_syscall::SYS_flock;
pub use self::sys_syscall::SYS_mkfifo;
pub use self::sys_syscall::SYS_sendto;
pub use self::sys_syscall::SYS_shutdown;
pub use self::sys_syscall::SYS_socketpair;
pub use self::sys_syscall::SYS_mkdir;
pub use self::sys_syscall::SYS_rmdir;
pub use self::sys_syscall::SYS_utimes;
pub use self::sys_syscall::SYS_adjtime;
pub use self::sys_syscall::SYS_setsid;
pub use self::sys_syscall::SYS_quotactl;
pub use self::sys_syscall::SYS_nlm_syscall;
pub use self::sys_syscall::SYS_nfssvc;
pub use self::sys_syscall::SYS_lgetfh;
pub use self::sys_syscall::SYS_getfh;
pub use self::sys_syscall::SYS_sysarch;
pub use self::sys_syscall::SYS_rtprio;
pub use self::sys_syscall::SYS_semsys;
pub use self::sys_syscall::SYS_msgsys;
pub use self::sys_syscall::SYS_shmsys;
pub use self::sys_syscall::SYS_setfib;
pub use self::sys_syscall::SYS_ntp_adjtime;
pub use self::sys_syscall::SYS_setgid;
pub use self::sys_syscall::SYS_setegid;
pub use self::sys_syscall::SYS_seteuid;
pub use self::sys_syscall::SYS_freebsd11_stat;
pub use self::sys_syscall::SYS_freebsd11_fstat;
pub use self::sys_syscall::SYS_freebsd11_lstat;
pub use self::sys_syscall::SYS_pathconf;
pub use self::sys_syscall::SYS_fpathconf;
pub use self::sys_syscall::SYS_getrlimit;
pub use self::sys_syscall::SYS_setrlimit;
pub use self::sys_syscall::SYS_freebsd11_getdirentries;
pub use self::sys_syscall::SYS___syscall;
pub use self::sys_syscall::SYS___sysctl;
pub use self::sys_syscall::SYS_mlock;
pub use self::sys_syscall::SYS_munlock;
pub use self::sys_syscall::SYS_undelete;
pub use self::sys_syscall::SYS_futimes;
pub use self::sys_syscall::SYS_getpgid;
pub use self::sys_syscall::SYS_poll;
pub use self::sys_syscall::SYS_freebsd7___semctl;
pub use self::sys_syscall::SYS_semget;
pub use self::sys_syscall::SYS_semop;
pub use self::sys_syscall::SYS_freebsd7_msgctl;
pub use self::sys_syscall::SYS_msgget;
pub use self::sys_syscall::SYS_msgsnd;
pub use self::sys_syscall::SYS_msgrcv;
pub use self::sys_syscall::SYS_shmat;
pub use self::sys_syscall::SYS_freebsd7_shmctl;
pub use self::sys_syscall::SYS_shmdt;
pub use self::sys_syscall::SYS_shmget;
pub use self::sys_syscall::SYS_clock_gettime;
pub use self::sys_syscall::SYS_clock_settime;
pub use self::sys_syscall::SYS_clock_getres;
pub use self::sys_syscall::SYS_ktimer_create;
pub use self::sys_syscall::SYS_ktimer_delete;
pub use self::sys_syscall::SYS_ktimer_settime;
pub use self::sys_syscall::SYS_ktimer_gettime;
pub use self::sys_syscall::SYS_ktimer_getoverrun;
pub use self::sys_syscall::SYS_nanosleep;
pub use self::sys_syscall::SYS_ffclock_getcounter;
pub use self::sys_syscall::SYS_ffclock_setestimate;
pub use self::sys_syscall::SYS_ffclock_getestimate;
pub use self::sys_syscall::SYS_clock_nanosleep;
pub use self::sys_syscall::SYS_clock_getcpuclockid2;
pub use self::sys_syscall::SYS_ntp_gettime;
pub use self::sys_syscall::SYS_minherit;
pub use self::sys_syscall::SYS_rfork;
pub use self::sys_syscall::SYS_issetugid;
pub use self::sys_syscall::SYS_lchown;
pub use self::sys_syscall::SYS_aio_read;
pub use self::sys_syscall::SYS_aio_write;
pub use self::sys_syscall::SYS_lio_listio;
pub use self::sys_syscall::SYS_freebsd11_getdents;
pub use self::sys_syscall::SYS_lchmod;
pub use self::sys_syscall::SYS_lutimes;
pub use self::sys_syscall::SYS_freebsd11_nstat;
pub use self::sys_syscall::SYS_freebsd11_nfstat;
pub use self::sys_syscall::SYS_freebsd11_nlstat;
pub use self::sys_syscall::SYS_preadv;
pub use self::sys_syscall::SYS_pwritev;
pub use self::sys_syscall::SYS_fhopen;
pub use self::sys_syscall::SYS_freebsd11_fhstat;
pub use self::sys_syscall::SYS_modnext;
pub use self::sys_syscall::SYS_modstat;
pub use self::sys_syscall::SYS_modfnext;
pub use self::sys_syscall::SYS_modfind;
pub use self::sys_syscall::SYS_kldload;
pub use self::sys_syscall::SYS_kldunload;
pub use self::sys_syscall::SYS_kldfind;
pub use self::sys_syscall::SYS_kldnext;
pub use self::sys_syscall::SYS_kldstat;
pub use self::sys_syscall::SYS_kldfirstmod;
pub use self::sys_syscall::SYS_getsid;
pub use self::sys_syscall::SYS_setresuid;
pub use self::sys_syscall::SYS_setresgid;
pub use self::sys_syscall::SYS_aio_return;
pub use self::sys_syscall::SYS_aio_suspend;
pub use self::sys_syscall::SYS_aio_cancel;
pub use self::sys_syscall::SYS_aio_error;
pub use self::sys_syscall::SYS_yield;
pub use self::sys_syscall::SYS_mlockall;
pub use self::sys_syscall::SYS_munlockall;
pub use self::sys_syscall::SYS___getcwd;
pub use self::sys_syscall::SYS_sched_setparam;
pub use self::sys_syscall::SYS_sched_getparam;
pub use self::sys_syscall::SYS_sched_setscheduler;
pub use self::sys_syscall::SYS_sched_getscheduler;
pub use self::sys_syscall::SYS_sched_yield;
pub use self::sys_syscall::SYS_sched_get_priority_max;
pub use self::sys_syscall::SYS_sched_get_priority_min;
pub use self::sys_syscall::SYS_sched_rr_get_interval;
pub use self::sys_syscall::SYS_utrace;
pub use self::sys_syscall::SYS_kldsym;
pub use self::sys_syscall::SYS_jail;
pub use self::sys_syscall::SYS_nnpfs_syscall;
pub use self::sys_syscall::SYS_sigprocmask;
pub use self::sys_syscall::SYS_sigsuspend;
pub use self::sys_syscall::SYS_sigpending;
pub use self::sys_syscall::SYS_sigtimedwait;
pub use self::sys_syscall::SYS_sigwaitinfo;
pub use self::sys_syscall::SYS___acl_get_file;
pub use self::sys_syscall::SYS___acl_set_file;
pub use self::sys_syscall::SYS___acl_get_fd;
pub use self::sys_syscall::SYS___acl_set_fd;
pub use self::sys_syscall::SYS___acl_delete_file;
pub use self::sys_syscall::SYS___acl_delete_fd;
pub use self::sys_syscall::SYS___acl_aclcheck_file;
pub use self::sys_syscall::SYS___acl_aclcheck_fd;
pub use self::sys_syscall::SYS_extattrctl;
pub use self::sys_syscall::SYS_extattr_set_file;
pub use self::sys_syscall::SYS_extattr_get_file;
pub use self::sys_syscall::SYS_extattr_delete_file;
pub use self::sys_syscall::SYS_aio_waitcomplete;
pub use self::sys_syscall::SYS_getresuid;
pub use self::sys_syscall::SYS_getresgid;
pub use self::sys_syscall::SYS_kqueue;
pub use self::sys_syscall::SYS_freebsd11_kevent;
pub use self::sys_syscall::SYS_extattr_set_fd;
pub use self::sys_syscall::SYS_extattr_get_fd;
pub use self::sys_syscall::SYS_extattr_delete_fd;
pub use self::sys_syscall::SYS___setugid;
pub use self::sys_syscall::SYS_eaccess;
pub use self::sys_syscall::SYS_afs3_syscall;
pub use self::sys_syscall::SYS_nmount;
pub use self::sys_syscall::SYS___mac_get_proc;
pub use self::sys_syscall::SYS___mac_set_proc;
pub use self::sys_syscall::SYS___mac_get_fd;
pub use self::sys_syscall::SYS___mac_get_file;
pub use self::sys_syscall::SYS___mac_set_fd;
pub use self::sys_syscall::SYS___mac_set_file;
pub use self::sys_syscall::SYS_kenv;
pub use self::sys_syscall::SYS_lchflags;
pub use self::sys_syscall::SYS_uuidgen;
pub use self::sys_syscall::SYS_sendfile;
pub use self::sys_syscall::SYS_mac_syscall;
pub use self::sys_syscall::SYS_freebsd11_getfsstat;
pub use self::sys_syscall::SYS_freebsd11_statfs;
pub use self::sys_syscall::SYS_freebsd11_fstatfs;
pub use self::sys_syscall::SYS_freebsd11_fhstatfs;
pub use self::sys_syscall::SYS_ksem_close;
pub use self::sys_syscall::SYS_ksem_post;
pub use self::sys_syscall::SYS_ksem_wait;
pub use self::sys_syscall::SYS_ksem_trywait;
pub use self::sys_syscall::SYS_ksem_init;
pub use self::sys_syscall::SYS_ksem_open;
pub use self::sys_syscall::SYS_ksem_unlink;
pub use self::sys_syscall::SYS_ksem_getvalue;
pub use self::sys_syscall::SYS_ksem_destroy;
pub use self::sys_syscall::SYS___mac_get_pid;
pub use self::sys_syscall::SYS___mac_get_link;
pub use self::sys_syscall::SYS___mac_set_link;
pub use self::sys_syscall::SYS_extattr_set_link;
pub use self::sys_syscall::SYS_extattr_get_link;
pub use self::sys_syscall::SYS_extattr_delete_link;
pub use self::sys_syscall::SYS___mac_execve;
pub use self::sys_syscall::SYS_sigaction;
pub use self::sys_syscall::SYS_sigreturn;
pub use self::sys_syscall::SYS_getcontext;
pub use self::sys_syscall::SYS_setcontext;
pub use self::sys_syscall::SYS_swapcontext;
pub use self::sys_syscall::SYS_freebsd13_swapoff;
pub use self::sys_syscall::SYS___acl_get_link;
pub use self::sys_syscall::SYS___acl_set_link;
pub use self::sys_syscall::SYS___acl_delete_link;
pub use self::sys_syscall::SYS___acl_aclcheck_link;
pub use self::sys_syscall::SYS_sigwait;
pub use self::sys_syscall::SYS_thr_create;
pub use self::sys_syscall::SYS_thr_exit;
pub use self::sys_syscall::SYS_thr_self;
pub use self::sys_syscall::SYS_thr_kill;
pub use self::sys_syscall::SYS_freebsd10__umtx_lock;
pub use self::sys_syscall::SYS_freebsd10__umtx_unlock;
pub use self::sys_syscall::SYS_jail_attach;
pub use self::sys_syscall::SYS_extattr_list_fd;
pub use self::sys_syscall::SYS_extattr_list_file;
pub use self::sys_syscall::SYS_extattr_list_link;
pub use self::sys_syscall::SYS_ksem_timedwait;
pub use self::sys_syscall::SYS_thr_suspend;
pub use self::sys_syscall::SYS_thr_wake;
pub use self::sys_syscall::SYS_kldunloadf;
pub use self::sys_syscall::SYS_audit;
pub use self::sys_syscall::SYS_auditon;
pub use self::sys_syscall::SYS_getauid;
pub use self::sys_syscall::SYS_setauid;
pub use self::sys_syscall::SYS_getaudit;
pub use self::sys_syscall::SYS_setaudit;
pub use self::sys_syscall::SYS_getaudit_addr;
pub use self::sys_syscall::SYS_setaudit_addr;
pub use self::sys_syscall::SYS_auditctl;
pub use self::sys_syscall::SYS__umtx_op;
pub use self::sys_syscall::SYS_thr_new;
pub use self::sys_syscall::SYS_sigqueue;
pub use self::sys_syscall::SYS_kmq_open;
pub use self::sys_syscall::SYS_kmq_setattr;
pub use self::sys_syscall::SYS_kmq_timedreceive;
pub use self::sys_syscall::SYS_kmq_timedsend;
pub use self::sys_syscall::SYS_kmq_notify;
pub use self::sys_syscall::SYS_kmq_unlink;
pub use self::sys_syscall::SYS_abort2;
pub use self::sys_syscall::SYS_thr_set_name;
pub use self::sys_syscall::SYS_aio_fsync;
pub use self::sys_syscall::SYS_rtprio_thread;
pub use self::sys_syscall::SYS_sctp_peeloff;
pub use self::sys_syscall::SYS_sctp_generic_sendmsg;
pub use self::sys_syscall::SYS_sctp_generic_sendmsg_iov;
pub use self::sys_syscall::SYS_sctp_generic_recvmsg;
pub use self::sys_syscall::SYS_pread;
pub use self::sys_syscall::SYS_pwrite;
pub use self::sys_syscall::SYS_mmap;
pub use self::sys_syscall::SYS_lseek;
pub use self::sys_syscall::SYS_truncate;
pub use self::sys_syscall::SYS_ftruncate;
pub use self::sys_syscall::SYS_thr_kill2;
pub use self::sys_syscall::SYS_freebsd12_shm_open;
pub use self::sys_syscall::SYS_shm_unlink;
pub use self::sys_syscall::SYS_cpuset;
pub use self::sys_syscall::SYS_cpuset_setid;
pub use self::sys_syscall::SYS_cpuset_getid;
pub use self::sys_syscall::SYS_cpuset_getaffinity;
pub use self::sys_syscall::SYS_cpuset_setaffinity;
pub use self::sys_syscall::SYS_faccessat;
pub use self::sys_syscall::SYS_fchmodat;
pub use self::sys_syscall::SYS_fchownat;
pub use self::sys_syscall::SYS_fexecve;
pub use self::sys_syscall::SYS_freebsd11_fstatat;
pub use self::sys_syscall::SYS_futimesat;
pub use self::sys_syscall::SYS_linkat;
pub use self::sys_syscall::SYS_mkdirat;
pub use self::sys_syscall::SYS_mkfifoat;
pub use self::sys_syscall::SYS_freebsd11_mknodat;
pub use self::sys_syscall::SYS_openat;
pub use self::sys_syscall::SYS_readlinkat;
pub use self::sys_syscall::SYS_renameat;
pub use self::sys_syscall::SYS_symlinkat;
pub use self::sys_syscall::SYS_unlinkat;
pub use self::sys_syscall::SYS_posix_openpt;
pub use self::sys_syscall::SYS_gssd_syscall;
pub use self::sys_syscall::SYS_jail_get;
pub use self::sys_syscall::SYS_jail_set;
pub use self::sys_syscall::SYS_jail_remove;
pub use self::sys_syscall::SYS_freebsd12_closefrom;
pub use self::sys_syscall::SYS___semctl;
pub use self::sys_syscall::SYS_msgctl;
pub use self::sys_syscall::SYS_shmctl;
pub use self::sys_syscall::SYS_lpathconf;
pub use self::sys_syscall::SYS___cap_rights_get;
pub use self::sys_syscall::SYS_cap_enter;
pub use self::sys_syscall::SYS_cap_getmode;
pub use self::sys_syscall::SYS_pdfork;
pub use self::sys_syscall::SYS_pdkill;
pub use self::sys_syscall::SYS_pdgetpid;
pub use self::sys_syscall::SYS_pselect;
pub use self::sys_syscall::SYS_getloginclass;
pub use self::sys_syscall::SYS_setloginclass;
pub use self::sys_syscall::SYS_rctl_get_racct;
pub use self::sys_syscall::SYS_rctl_get_rules;
pub use self::sys_syscall::SYS_rctl_get_limits;
pub use self::sys_syscall::SYS_rctl_add_rule;
pub use self::sys_syscall::SYS_rctl_remove_rule;
pub use self::sys_syscall::SYS_posix_fallocate;
pub use self::sys_syscall::SYS_posix_fadvise;
pub use self::sys_syscall::SYS_wait6;
pub use self::sys_syscall::SYS_cap_rights_limit;
pub use self::sys_syscall::SYS_cap_ioctls_limit;
pub use self::sys_syscall::SYS_cap_ioctls_get;
pub use self::sys_syscall::SYS_cap_fcntls_limit;
pub use self::sys_syscall::SYS_cap_fcntls_get;
pub use self::sys_syscall::SYS_bindat;
pub use self::sys_syscall::SYS_connectat;
pub use self::sys_syscall::SYS_chflagsat;
pub use self::sys_syscall::SYS_accept4;
pub use self::sys_syscall::SYS_pipe2;
pub use self::sys_syscall::SYS_aio_mlock;
pub use self::sys_syscall::SYS_procctl;
pub use self::sys_syscall::SYS_ppoll;
pub use self::sys_syscall::SYS_futimens;
pub use self::sys_syscall::SYS_utimensat;
pub use self::sys_syscall::SYS_fdatasync;
pub use self::sys_syscall::SYS_fstat;
pub use self::sys_syscall::SYS_fstatat;
pub use self::sys_syscall::SYS_fhstat;
pub use self::sys_syscall::SYS_getdirentries;
pub use self::sys_syscall::SYS_statfs;
pub use self::sys_syscall::SYS_fstatfs;
pub use self::sys_syscall::SYS_getfsstat;
pub use self::sys_syscall::SYS_fhstatfs;
pub use self::sys_syscall::SYS_mknodat;
pub use self::sys_syscall::SYS_kevent;
pub use self::sys_syscall::SYS_cpuset_getdomain;
pub use self::sys_syscall::SYS_cpuset_setdomain;
pub use self::sys_syscall::SYS_getrandom;
pub use self::sys_syscall::SYS_getfhat;
pub use self::sys_syscall::SYS_fhlink;
pub use self::sys_syscall::SYS_fhlinkat;
pub use self::sys_syscall::SYS_fhreadlink;
pub use self::sys_syscall::SYS_funlinkat;
pub use self::sys_syscall::SYS_copy_file_range;
pub use self::sys_syscall::SYS___sysctlbyname;
pub use self::sys_syscall::SYS_shm_open2;
pub use self::sys_syscall::SYS_shm_rename;
pub use self::sys_syscall::SYS_sigfastblock;
pub use self::sys_syscall::SYS___realpathat;
pub use self::sys_syscall::SYS_close_range;
pub use self::sys_syscall::SYS_rpctls_syscall;
pub use self::sys_syscall::SYS___specialfd;
pub use self::sys_syscall::SYS_aio_writev;
pub use self::sys_syscall::SYS_aio_readv;
pub use self::sys_syscall::SYS_fspacectl;
pub use self::sys_syscall::SYS_sched_getcpu;
pub use self::sys_syscall::SYS_swapoff;
pub use self::sys_syscall::SYS_kqueuex;
pub use self::sys_syscall::SYS_membarrier;
pub use self::sys_syscall::SYS_timerfd_create;
pub use self::sys_syscall::SYS_timerfd_gettime;
pub use self::sys_syscall::SYS_timerfd_settime;
pub use self::sys_syscall::SYS_kcmp;
pub use self::sys_syscall::SYS_getrlimitusage;
pub use self::sys_syscall::SYS_fchroot;
pub use self::sys_syscall::SYS_setcred;
pub use self::sys_syscall::SYS_MAXSYSCALL;
mod sys_sysctl;
pub use self::sys_sysctl::CTL_KERN;
pub use self::sys_sysctl::KERN_PROC;
pub use self::sys_sysctl::KERN_PROC_AUXV;
mod sys_elf_common;
pub use self::sys_elf_common::AT_NULL;
pub use self::sys_elf_common::AT_IGNORE;
pub use self::sys_elf_common::AT_EXECFD;
pub use self::sys_elf_common::AT_PHDR;
pub use self::sys_elf_common::AT_PHENT;
pub use self::sys_elf_common::AT_PHNUM;
pub use self::sys_elf_common::AT_PAGESZ;
pub use self::sys_elf_common::AT_BASE;
pub use self::sys_elf_common::AT_FLAGS;
pub use self::sys_elf_common::AT_ENTRY;
pub use self::sys_elf_common::AT_NOTELF;
pub use self::sys_elf_common::AT_UID;
pub use self::sys_elf_common::AT_EUID;
pub use self::sys_elf_common::AT_GID;
pub use self::sys_elf_common::AT_EGID;
pub use self::sys_elf_common::AT_EXECPATH;
pub use self::sys_elf_common::AT_CANARY;
pub use self::sys_elf_common::AT_CANARYLEN;
pub use self::sys_elf_common::AT_OSRELDATE;
pub use self::sys_elf_common::AT_NCPUS;
pub use self::sys_elf_common::AT_PAGESIZES;
pub use self::sys_elf_common::AT_PAGESIZESLEN;
pub use self::sys_elf_common::AT_TIMEKEEP;
pub use self::sys_elf_common::AT_STACKPROT;
pub use self::sys_elf_common::AT_EHDRFLAGS;
pub use self::sys_elf_common::AT_HWCAP;
pub use self::sys_elf_common::AT_HWCAP2;
pub use self::sys_elf_common::AT_BSDFLAGS;
pub use self::sys_elf_common::AT_ARGC;
pub use self::sys_elf_common::AT_ARGV;
pub use self::sys_elf_common::AT_ENVC;
pub use self::sys_elf_common::AT_ENVV;
pub use self::sys_elf_common::AT_PS_STRINGS;
pub use self::sys_elf_common::AT_FXRNG;
pub use self::sys_elf_common::AT_KPRELOAD;
pub use self::sys_elf_common::AT_USRSTACKBASE;
pub use self::sys_elf_common::AT_USRSTACKLIM;
pub use self::sys_elf_common::AT_CHERI_STATS;
pub use self::sys_elf_common::AT_COUNT;
pub type c_char = u8;
