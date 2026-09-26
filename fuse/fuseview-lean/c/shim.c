/* The system calls the view makes that Lean's IO library does not: the *at family, O_PATH, raw
 * descriptors, the whole of stat(2), the kernel's account of where an object is. A call that can
 * fail returns `Except UInt32 α` inside IO -- the errno, or the value -- so the IO action itself
 * never fails; the few that cannot fail return their value directly. Each export carries its Lean
 * declaration (Sys.lean) above it: the two must agree, argument for argument, or a boxed scalar is
 * read as a pointer. A descriptor is a UInt32, a byte string a borrowed (`@&`) ByteArray. Every
 * descriptor opened here is close-on-exec.
 *
 * Also here, since nothing about them is the view's: the request counters and the thread that
 * reports them for each line on stdin (the probe's protocol). */
#define _GNU_SOURCE
#include <lean/lean.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>

/* what the code below and Sys.lean assume of the platform: x86_64 Linux */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "the u64 records are little-endian");
_Static_assert(sizeof(long) == 8 && sizeof(off_t) == 8 && sizeof(time_t) == 8, "64-bit longs, offsets, times");
_Static_assert(O_RDONLY == 0 && O_WRONLY == 01 && O_RDWR == 02 && O_CREAT == 0100 && O_EXCL == 0200, "open flags");
_Static_assert(O_TRUNC == 01000 && O_APPEND == 02000 && O_DIRECTORY == 0200000, "open flags");
_Static_assert(O_NOFOLLOW == 0400000 && O_PATH == 010000000, "open flags");
_Static_assert(AT_REMOVEDIR == 0x200, "unlinkat flags");

/* -- results ------------------------------------------------------------------------------- */

static lean_obj_res ok(lean_obj_arg v) {
    lean_object *r = lean_alloc_ctor(1, 1, 0); /* Except.ok */
    lean_ctor_set(r, 0, v);
    return lean_io_result_mk_ok(r);
}

static lean_obj_res fail(int e) {
    lean_object *r = lean_alloc_ctor(0, 1, 0); /* Except.error */
    lean_ctor_set(r, 0, lean_box_uint32((uint32_t)e));
    return lean_io_result_mk_ok(r);
}

static lean_obj_res ok_unit(void) { return ok(lean_box(0)); }

static lean_obj_res ok_u32(uint32_t v) { return ok(lean_box_uint32(v)); }

static lean_obj_res done_or_errno(int ret) { return ret < 0 ? fail(errno) : ok_unit(); }

static lean_object *bytes(const void *p, size_t n) {
    lean_object *a = lean_alloc_sarray(1, n, n);
    memcpy(lean_sarray_cptr(a), p, n);
    return a;
}

/* A NUL-terminated copy of *name* in *buf*: 0, or the errno a real filesystem would give -- EINVAL
 * for a NUL inside it, ENAMETOOLONG for one that does not fit. */
static int c_string(b_lean_obj_arg name, char *buf, size_t cap) {
    size_t n = lean_sarray_size(name);
    if (memchr(lean_sarray_cptr(name), 0, n) != NULL) return EINVAL;
    if (n >= cap) return ENAMETOOLONG;
    memcpy(buf, lean_sarray_cptr(name), n);
    buf[n] = 0;
    return 0;
}

#define C_STRING(var, obj)                        \
    char var[PATH_MAX + 1];                       \
    do {                                          \
        int e_ = c_string(obj, var, sizeof var);  \
        if (e_ != 0) return fail(e_);             \
    } while (0)

static void proc_path(char *buf, size_t cap, uint32_t fd) { snprintf(buf, cap, "/proc/self/fd/%u", fd); }

/* Flags no open here may carry: O_CREAT or O_TMPFILE would want a mode argument (creation belongs
 * to fv_openat). O_TMPFILE includes O_DIRECTORY's bit, so it is tested whole. */
static int creates(uint32_t flags) {
    return (flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE;
}

/* -- the FUSE device ----------------------------------------------------------------------- */

/* Lean: fuseRead (fd : Fd) (buf : ByteArray) (capacity : UInt32) : IO (Except Errno ByteArray)
 * One request, read into *buf* when nothing else holds it and it has room -- the loop hands the
 * last request's buffer back, so the daemon allocates one for its life -- else into a fresh one of
 * *capacity* bytes, which must hold the largest request (max_write and its headers). */
LEAN_EXPORT lean_obj_res fv_fuse_read(uint32_t fd, lean_obj_arg buf, uint32_t capacity, lean_obj_arg w) {
    if (!lean_is_exclusive(buf) || lean_sarray_capacity(buf) < capacity) {
        lean_dec(buf);
        buf = lean_alloc_sarray(1, 0, capacity);
    }
    ssize_t n;
    do n = read((int)fd, lean_sarray_cptr(buf), capacity);
    while (n < 0 && errno == EINTR);
    if (n < 0) {
        int e = errno;
        lean_dec(buf);
        return fail(e);
    }
    lean_sarray_set_size(buf, (size_t)n);
    return ok(buf);
}

/* Lean: writev (fd : Fd) (head : @& ByteArray) (body : @& ByteArray) : IO (Except Errno UInt32)
 * One reply, in one write: *head* then *body*. */
LEAN_EXPORT lean_obj_res fv_writev(uint32_t fd, b_lean_obj_arg head, b_lean_obj_arg body, lean_obj_arg w) {
    struct iovec iov[2] = {
        {lean_sarray_cptr(head), lean_sarray_size(head)},
        {lean_sarray_cptr(body), lean_sarray_size(body)},
    };
    ssize_t n;
    do n = writev((int)fd, iov, 2);
    while (n < 0 && errno == EINTR);
    if (n < 0) return fail(errno);
    return ok_u32((uint32_t)n);
}

/* -- descriptors --------------------------------------------------------------------------- */

/* Lean: openPath (path : @& ByteArray) (flags : UInt32) : IO (Except Errno Fd) */
LEAN_EXPORT lean_obj_res fv_open(b_lean_obj_arg path, uint32_t flags, lean_obj_arg w) {
    if (creates(flags)) return fail(EINVAL);
    C_STRING(p, path);
    int fd = open(p, (int)flags | O_CLOEXEC);
    return fd < 0 ? fail(errno) : ok_u32((uint32_t)fd);
}

/* Lean: openat (dir : Fd) (name : @& ByteArray) (flags mode : UInt32) : IO (Except Errno Fd) */
LEAN_EXPORT lean_obj_res fv_openat(uint32_t dir, b_lean_obj_arg name, uint32_t flags, uint32_t mode, lean_obj_arg w) {
    C_STRING(n, name);
    int fd = openat((int)dir, n, (int)flags | O_CLOEXEC, (mode_t)mode);
    return fd < 0 ? fail(errno) : ok_u32((uint32_t)fd);
}

/* Lean: reopen (fd : Fd) (flags : UInt32) : IO (Except Errno Fd)
 * Reopen the object *fd* refers to, through its /proc link. Never with O_NOFOLLOW: the link is
 * itself a symbolic link, so that would give ELOOP -- or, with O_PATH, a descriptor for the link
 * rather than the object. */
LEAN_EXPORT lean_obj_res fv_reopen(uint32_t fd, uint32_t flags, lean_obj_arg w) {
    if (creates(flags) || (flags & O_NOFOLLOW) != 0) return fail(EINVAL);
    char p[64];
    proc_path(p, sizeof p, fd);
    int out = open(p, (int)flags | O_CLOEXEC);
    return out < 0 ? fail(errno) : ok_u32((uint32_t)out);
}

/* Lean: close (fd : Fd) : IO Unit */
LEAN_EXPORT lean_obj_res fv_close(uint32_t fd, lean_obj_arg w) {
    close((int)fd);
    return lean_io_result_mk_ok(lean_box(0));
}

/* Lean: fdOpen (fd : Fd) : IO Bool */
LEAN_EXPORT lean_obj_res fv_fd_open(uint32_t fd, lean_obj_arg w) {
    return lean_io_result_mk_ok(lean_box(fcntl((int)fd, F_GETFD) >= 0));
}

/* -- stat ---------------------------------------------------------------------------------- */

/* sixteen little-endian u64s: dev ino mode nlink uid gid rdev size blksize blocks, then
 * atime mtime ctime as (seconds, nanoseconds) -- Stat.decode reads them back */
static lean_obj_res stat_result(const struct stat *st) {
    uint64_t f[16] = {
        (uint64_t)st->st_dev,         (uint64_t)st->st_ino,          (uint64_t)st->st_mode,
        (uint64_t)st->st_nlink,       (uint64_t)st->st_uid,          (uint64_t)st->st_gid,
        (uint64_t)st->st_rdev,        (uint64_t)st->st_size,         (uint64_t)st->st_blksize,
        (uint64_t)st->st_blocks,      (uint64_t)st->st_atim.tv_sec,  (uint64_t)st->st_atim.tv_nsec,
        (uint64_t)st->st_mtim.tv_sec, (uint64_t)st->st_mtim.tv_nsec, (uint64_t)st->st_ctim.tv_sec,
        (uint64_t)st->st_ctim.tv_nsec,
    };
    return ok(bytes(f, sizeof f));
}

/* Lean: fstatRaw (fd : Fd) : IO (Except Errno ByteArray) */
LEAN_EXPORT lean_obj_res fv_fstat(uint32_t fd, lean_obj_arg w) {
    struct stat st;
    if (fstat((int)fd, &st) != 0) return fail(errno);
    return stat_result(&st);
}

/* Lean: fstatatRaw (dir : Fd) (name : @& ByteArray) : IO (Except Errno ByteArray)
 * The entry *name* under *dir*, not following a link. */
LEAN_EXPORT lean_obj_res fv_fstatat(uint32_t dir, b_lean_obj_arg name, lean_obj_arg w) {
    C_STRING(n, name);
    struct stat st;
    if (fstatat((int)dir, n, &st, AT_SYMLINK_NOFOLLOW) != 0) return fail(errno);
    return stat_result(&st);
}

/* -- where an object is -------------------------------------------------------------------- */

/* Lean: readlinkFd (fd : Fd) : IO (Except Errno ByteArray)
 * The path the kernel reports for the object *fd* refers to (its d_path). Two markers can appear
 * in it: " (deleted)" appended for a removed object, "(unreachable)" prefixed for one outside this
 * process's root. View.isAt compares the whole string with a recorded absolute path, so the second
 * never matches, and it settles the first by the link count. */
LEAN_EXPORT lean_obj_res fv_readlink_fd(uint32_t fd, lean_obj_arg w) {
    char p[64], buf[PATH_MAX + 64];
    proc_path(p, sizeof p, fd);
    ssize_t n = readlink(p, buf, sizeof buf);
    if (n < 0) return fail(errno);
    if ((size_t)n >= sizeof buf) return fail(ENAMETOOLONG);
    return ok(bytes(buf, (size_t)n));
}

/* Lean: readlinkat (dir : Fd) (name : @& ByteArray) : IO (Except Errno ByteArray) */
LEAN_EXPORT lean_obj_res fv_readlinkat(uint32_t dir, b_lean_obj_arg name, lean_obj_arg w) {
    C_STRING(n, name);
    char buf[PATH_MAX + 1];
    ssize_t len = readlinkat((int)dir, n, buf, sizeof buf);
    if (len < 0) return fail(errno);
    if ((size_t)len >= sizeof buf) return fail(ENAMETOOLONG);
    return ok(bytes(buf, (size_t)len));
}

/* Lean: listdir (fd : Fd) : IO (Except Errno (Array ByteArray))
 * The names in the directory *fd* refers to, read afresh through its /proc link, less . and .. */
LEAN_EXPORT lean_obj_res fv_listdir(uint32_t fd, lean_obj_arg w) {
    char p[64];
    proc_path(p, sizeof p, fd);
    int dfd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return fail(errno);
    DIR *d = fdopendir(dfd);
    if (d == NULL) {
        int e = errno;
        close(dfd);
        return fail(e);
    }
    lean_object *names = lean_mk_empty_array();
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (e == NULL) {
            if (errno != 0) {
                int x = errno;
                closedir(d);
                lean_dec(names);
                return fail(x);
            }
            break;
        }
        const char *n = e->d_name;
        if (n[0] == '.' && (n[1] == 0 || (n[1] == '.' && n[2] == 0))) continue;
        names = lean_array_push(names, bytes(n, strlen(n)));
    }
    closedir(d);
    return ok(names);
}

/* -- names --------------------------------------------------------------------------------- */

/* Lean: mkdirat (dir : Fd) (name : @& ByteArray) (mode : UInt32) : IO (Except Errno Unit) */
LEAN_EXPORT lean_obj_res fv_mkdirat(uint32_t dir, b_lean_obj_arg name, uint32_t mode, lean_obj_arg w) {
    C_STRING(n, name);
    return done_or_errno(mkdirat((int)dir, n, (mode_t)mode));
}

/* Lean: symlinkat (target : @& ByteArray) (dir : Fd) (name : @& ByteArray) : IO (Except Errno Unit) */
LEAN_EXPORT lean_obj_res fv_symlinkat(b_lean_obj_arg target, uint32_t dir, b_lean_obj_arg name, lean_obj_arg w) {
    C_STRING(t, target);
    C_STRING(n, name);
    return done_or_errno(symlinkat(t, (int)dir, n));
}

/* Lean: linkFd (fd dir : Fd) (name : @& ByteArray) : IO (Except Errno Unit)
 * A new name, *name* under *dir*, for the object *fd* refers to: through its /proc link, which
 * links an O_PATH descriptor without CAP_DAC_READ_SEARCH (and a symbolic link itself, not its
 * target). */
LEAN_EXPORT lean_obj_res fv_link_fd(uint32_t fd, uint32_t dir, b_lean_obj_arg name, lean_obj_arg w) {
    C_STRING(n, name);
    char p[64];
    proc_path(p, sizeof p, fd);
    return done_or_errno(linkat(AT_FDCWD, p, (int)dir, n, AT_SYMLINK_FOLLOW));
}

/* Lean: renameat (oldDir : Fd) (old : @& ByteArray) (newDir : Fd) (new : @& ByteArray) : IO (Except Errno Unit) */
LEAN_EXPORT lean_obj_res fv_renameat(uint32_t old_dir, b_lean_obj_arg old_name, uint32_t new_dir, b_lean_obj_arg new_name,
                                     lean_obj_arg w) {
    C_STRING(o, old_name);
    C_STRING(n, new_name);
    return done_or_errno(renameat((int)old_dir, o, (int)new_dir, n));
}

/* Lean: unlinkat (dir : Fd) (name : @& ByteArray) (flags : UInt32) : IO (Except Errno Unit) */
LEAN_EXPORT lean_obj_res fv_unlinkat(uint32_t dir, b_lean_obj_arg name, uint32_t flags, lean_obj_arg w) {
    C_STRING(n, name);
    return done_or_errno(unlinkat((int)dir, n, (int)flags));
}

/* -- contents ------------------------------------------------------------------------------ */

/* Lean: pread (fd : Fd) (size : UInt32) (offset : UInt64) : IO (Except Errno ByteArray) */
LEAN_EXPORT lean_obj_res fv_pread(uint32_t fd, uint32_t size, uint64_t offset, lean_obj_arg w) {
    lean_object *a = lean_alloc_sarray(1, 0, size);
    ssize_t n = pread((int)fd, lean_sarray_cptr(a), size, (off_t)offset);
    if (n < 0) {
        int e = errno;
        lean_dec(a);
        return fail(e);
    }
    lean_sarray_set_size(a, (size_t)n);
    return ok(a);
}

/* Lean: pwrite (fd : Fd) (buf : @& ByteArray) (start len : UInt32) (offset : UInt64) : IO (Except Errno UInt32)
 * Write *len* bytes of *buf* from *start* (a write request's own buffer) at *offset*. */
LEAN_EXPORT lean_obj_res fv_pwrite(uint32_t fd, b_lean_obj_arg buf, uint32_t start, uint32_t len, uint64_t offset,
                                   lean_obj_arg w) {
    if ((size_t)start + len > lean_sarray_size(buf)) return fail(EINVAL);
    ssize_t n = pwrite((int)fd, lean_sarray_cptr(buf) + start, len, (off_t)offset);
    return n < 0 ? fail(errno) : ok_u32((uint32_t)n);
}

/* Lean: ftruncate (fd : Fd) (size : UInt64) : IO (Except Errno Unit) */
LEAN_EXPORT lean_obj_res fv_ftruncate(uint32_t fd, uint64_t size, lean_obj_arg w) {
    return done_or_errno(ftruncate((int)fd, (off_t)size));
}

/* Lean: fsync (fd : Fd) (datasync : UInt8) : IO (Except Errno Unit) */
LEAN_EXPORT lean_obj_res fv_fsync(uint32_t fd, uint8_t datasync, lean_obj_arg w) {
    return done_or_errno(datasync ? fdatasync((int)fd) : fsync((int)fd));
}

/* -- setattr ------------------------------------------------------------------------------- */

/* the FATTR_* bits of fuse_setattr_in.valid this acts on */
#define FATTR_MODE (1 << 0)
#define FATTR_UID (1 << 1)
#define FATTR_GID (1 << 2)
#define FATTR_SIZE (1 << 3)
#define FATTR_ATIME (1 << 4)
#define FATTR_MTIME (1 << 5)
#define FATTR_ATIME_NOW (1 << 7)
#define FATTR_MTIME_NOW (1 << 8)

static struct timespec when(uint32_t valid, uint32_t set, uint32_t now, uint64_t sec, uint32_t nsec) {
    struct timespec ts = {0, UTIME_OMIT}; /* left alone: it keeps its value */
    if (valid & now) {
        ts.tv_nsec = UTIME_NOW;
    } else if (valid & set) {
        ts.tv_sec = (time_t)(int64_t)sec;
        ts.tv_nsec = (long)nsec;
    }
    return ts;
}

/* a time given as a value must be one: UTIME_NOW and UTIME_OMIT are only ever chosen here */
static int bad_time(uint32_t valid, uint32_t set, uint32_t now, uint32_t nsec) {
    return (valid & set) != 0 && (valid & now) == 0 && nsec >= 1000000000u;
}

/* Lean: setattr (fd : Fd) (viaProc : UInt8) (valid mode uid gid : UInt32) (size atime : UInt64)
 *         (atimeNs : UInt32) (mtime : UInt64) (mtimeNs : UInt32) : IO (Except Errno Unit)
 * What a setattr asks, done in the Python view's order -- mode, size, owner, times -- to the
 * descriptor *fd*: one open on the file (*via_proc* 0), or an O_PATH one, acted on through its
 * /proc link, which leads to the file itself. */
LEAN_EXPORT lean_obj_res fv_setattr(uint32_t fd, uint8_t via_proc, uint32_t valid, uint32_t mode, uint32_t uid,
                                    uint32_t gid, uint64_t size, uint64_t atime, uint32_t atimensec, uint64_t mtime,
                                    uint32_t mtimensec, lean_obj_arg w) {
    if (bad_time(valid, FATTR_ATIME, FATTR_ATIME_NOW, atimensec) ||
        bad_time(valid, FATTR_MTIME, FATTR_MTIME_NOW, mtimensec))
        return fail(EINVAL);
    char p[64];
    proc_path(p, sizeof p, fd);
    int f = (int)fd;
    if (valid & FATTR_MODE) {
        mode_t m = (mode_t)(mode & 07777);
        if ((via_proc ? chmod(p, m) : fchmod(f, m)) != 0) return fail(errno);
    }
    if (valid & FATTR_SIZE) {
        if ((via_proc ? truncate(p, (off_t)size) : ftruncate(f, (off_t)size)) != 0) return fail(errno);
    }
    if (valid & (FATTR_UID | FATTR_GID)) {
        uid_t u = (valid & FATTR_UID) ? (uid_t)uid : (uid_t)-1;
        gid_t g = (valid & FATTR_GID) ? (gid_t)gid : (gid_t)-1;
        if ((via_proc ? chown(p, u, g) : fchown(f, u, g)) != 0) return fail(errno);
    }
    if (valid & (FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW)) {
        struct timespec times[2] = {
            when(valid, FATTR_ATIME, FATTR_ATIME_NOW, atime, atimensec),
            when(valid, FATTR_MTIME, FATTR_MTIME_NOW, mtime, mtimensec),
        };
        if ((via_proc ? utimensat(AT_FDCWD, p, times, 0) : futimens(f, times)) != 0) return fail(errno);
    }
    return ok_unit();
}

/* -- the filesystem ------------------------------------------------------------------------ */

/* Lean: statvfsRaw (fd : Fd) : IO (Except Errno ByteArray)
 * eight little-endian u64s: blocks bfree bavail files ffree bsize namemax frsize */
LEAN_EXPORT lean_obj_res fv_statvfs_fd(uint32_t fd, lean_obj_arg w) {
    char p[64];
    proc_path(p, sizeof p, fd);
    struct statvfs st;
    if (statvfs(p, &st) != 0) return fail(errno);
    uint64_t f[8] = {st.f_blocks, st.f_bfree, st.f_bavail, st.f_files,
                     st.f_ffree,  st.f_bsize, st.f_namemax, st.f_frsize};
    return ok(bytes(f, sizeof f));
}

/* certorail/folding.py, as it is: does the directory behind *dir* resolve names byte for byte, as
 * its filesystem declares? False when it folds, and when it cannot say. */
#define FS_EXT 0xEF53u
#define FS_F2FS 0xF2F52010u
#define FS_TMPFS 0x01021994u
#define FS_BTRFS 0x9123683Eu
#define FS_CASEFOLD_FL 0x40000000
#define FS_IOC_GETFLAGS_ ((2UL << 30) | (sizeof(long) << 16) | ((unsigned long)'f' << 8) | 1)

/* Lean: exactLookups (dir : Fd) : IO Bool */
LEAN_EXPORT lean_obj_res fv_exact_lookups(uint32_t dir, lean_obj_arg w) {
    struct statfs sf;
    uint8_t exact = 0;
    if (fstatfs((int)dir, &sf) == 0) {
        uint32_t kind = (uint32_t)((uint64_t)sf.f_type & 0xFFFFFFFFu);
        if (kind == FS_BTRFS) {
            exact = 1;
        } else if (kind == FS_EXT || kind == FS_F2FS || kind == FS_TMPFS) {
            char p[64];
            proc_path(p, sizeof p, dir);
            int fd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd >= 0) {
                unsigned char flags[8] = {0}; /* the ioctl is spelled for a long, and writes an int */
                if (ioctl(fd, FS_IOC_GETFLAGS_, flags) == 0) {
                    int32_t word;
                    memcpy(&word, flags, sizeof word);
                    exact = (word & FS_CASEFOLD_FL) == 0;
                }
                close(fd);
            }
        }
    }
    return lean_io_result_mk_ok(lean_box(exact));
}

/* -- the process --------------------------------------------------------------------------- */

/* Lean: setup : IO Unit
 * A filesystem server holds descriptors for every directory the kernel has cached: the soft
 * limit up to the hard one. And the kernel applied the caller's umask to every mode it sends: the
 * daemon's must not apply again (process-wide, deliberately: the daemon creates nothing of its
 * own). */
LEAN_EXPORT lean_obj_res fv_setup(lean_obj_arg w) {
    struct rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur < r.rlim_max) {
        r.rlim_cur = r.rlim_max;
        setrlimit(RLIMIT_NOFILE, &r);
    }
    umask(0);
    return lean_io_result_mk_ok(lean_box(0));
}

/* lookup, getattr, readdir, open, read: the requests the probe counts */
static _Atomic uint64_t counts[5];

/* Lean: count (which : UInt32) : IO Unit */
LEAN_EXPORT lean_obj_res fv_count(uint32_t which, lean_obj_arg w) {
    if (which < 5) atomic_fetch_add_explicit(&counts[which], 1, memory_order_relaxed);
    return lean_io_result_mk_ok(lean_box(0));
}

static void *reporter(void *arg) {
    for (;;) {
        char c;
        ssize_t n;
        do n = read(0, &c, 1);
        while (n < 0 && errno == EINTR);
        if (n <= 0) return NULL;
        if (c != '\n') continue;
        unsigned long long v[5];
        for (int i = 0; i < 5; i++) v[i] = atomic_exchange(&counts[i], 0);
        char line[256];
        int len = snprintf(line, sizeof line,
                           "{\"lookup\": %llu, \"getattr\": %llu, \"readdir\": %llu, \"open\": %llu, \"read\": %llu}\n",
                           v[0], v[1], v[2], v[3], v[4]);
        if (len < 0 || len >= (int)sizeof line) return NULL;
        for (size_t off = 0; off < (size_t)len;) {
            ssize_t k = write(1, line + off, (size_t)len - off);
            if (k < 0) {
                if (errno == EINTR) continue;
                return NULL;
            }
            off += (size_t)k;
        }
    }
}

static atomic_flag reporting = ATOMIC_FLAG_INIT;

/* Lean: startReporter : IO Unit
 * A JSON line of request counts for each line on stdin, until it ends: a thread of its own,
 * touching no Lean object. Started once; a second call does nothing. */
LEAN_EXPORT lean_obj_res fv_start_reporter(lean_obj_arg w) {
    if (!atomic_flag_test_and_set(&reporting)) {
        pthread_t t;
        int e = pthread_create(&t, NULL, reporter, NULL);
        if (e == 0) {
            pthread_detach(t);
        } else {
            fprintf(stderr, "fuseview-lean: no request counts: pthread_create: %s\n", strerror(e));
        }
    }
    return lean_io_result_mk_ok(lean_box(0));
}
