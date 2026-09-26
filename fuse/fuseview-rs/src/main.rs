//! certorail's FUSE view (`certorail/fuseview.py`), ported to Rust for one question: how much of
//! the view's cost is the interpreter? The algorithm is the Python one, check for check and system
//! call for system call (README.md says where it differs), so what separates the two in
//! `scripts/probe_view_find.py` is native execution.
//!
//! It serves a mount it makes itself (MOUNTPOINT), or one made by whoever hands it the /dev/fuse
//! descriptor (`--fd`): how it serves from inside a jail, where it cannot mount
//! (`scripts/native_view.py`). Either way it prints "ready" once the kernel has connected, prints its
//! request counts as a JSON line (and clears them) for each line it reads on stdin, and exits when
//! the view is unmounted. A mount of its own it unmounts at SIGTERM or SIGINT. A request that fails
//! for a reason other than the backing filesystem's is logged to stderr and answered EIO.

mod filter;
mod spec;
mod sys;
mod view;

use std::ffi::{OsStr, OsString};
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage: fuseview-rs [OPTIONS] VIEW.JSON MOUNTPOINT
       fuseview-rs [OPTIONS] --fd N VIEW.JSON

  VIEW.JSON           a view daemon's specification (viewdaemon.ViewSpec.document(), format 2)
  --fd N              serve the /dev/fuse descriptor N, mounted by whoever handed it over
  --entry-ttl S       how long the kernel caches a name (default 1)
  --attr-ttl-dirs S   a directory's attributes (default 1)
  --attr-ttl-files S  a file's attributes (default 0)
  --threads N         request threads (default 1); read and write run outside the one lock
  --keep-cache        keep a file's cached pages across opens";

enum Serve {
    /// a mount of its own, made through fusermount3
    Mount(PathBuf),
    /// a /dev/fuse descriptor, mounted by whoever handed it over
    Fd(OwnedFd),
}

struct Args {
    spec: PathBuf,
    serve: Serve,
    ttls: view::Ttls,
    threads: usize,
    keep_cache: bool,
}

fn parsed<T: FromStr>(option: &str, value: Option<OsString>) -> Result<T, String> {
    let text = value.ok_or_else(|| format!("{option} wants a value"))?;
    let text = text.to_str().ok_or_else(|| format!("{option} wants a number"))?;
    text.parse::<T>().map_err(|_| format!("{option}: not a number: {text}"))
}

fn seconds(option: &str, value: Option<OsString>) -> Result<Duration, String> {
    Duration::try_from_secs_f64(parsed(option, value)?).map_err(|_| format!("{option}: not a length of time"))
}

fn parse_args() -> Result<Args, String> {
    let mut ttls = view::Ttls { entry: Duration::from_secs(1), dirs: Duration::from_secs(1), files: Duration::ZERO };
    let mut threads: usize = 1;
    let mut keep_cache = false;
    let mut fd: Option<RawFd> = None;
    let mut positional = Vec::new();
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--fd") => fd = Some(parsed("--fd", args.next())?),
            Some("--entry-ttl") => ttls.entry = seconds("--entry-ttl", args.next())?,
            Some("--attr-ttl-dirs") => ttls.dirs = seconds("--attr-ttl-dirs", args.next())?,
            Some("--attr-ttl-files") => ttls.files = seconds("--attr-ttl-files", args.next())?,
            Some("--threads") => threads = parsed::<usize>("--threads", args.next())?.max(1),
            Some("--keep-cache") => keep_cache = true,
            Some("-h" | "--help") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            Some(option) if option.starts_with("--") => return Err(format!("unknown option {option}\n{USAGE}")),
            _ => positional.push(PathBuf::from(arg)),
        }
    }
    let (spec, serve) = match (fd, <[PathBuf; 2]>::try_from(positional)) {
        (None, Ok([spec, mountpoint])) => (spec, Serve::Mount(mountpoint)),
        (Some(fd), Err(positional)) if positional.len() == 1 => {
            (positional.into_iter().next().expect("one"), Serve::Fd(sys::adopt(fd)?))
        }
        _ => return Err(USAGE.to_string()),
    };
    Ok(Args { spec, serve, ttls, threads, keep_cache })
}

/// fusermount3 unmounts what this user mounted; lazily when something still has it open.
fn unmount(mountpoint: &Path) {
    let run = |args: &[&OsStr]| {
        Command::new("fusermount3")
            .args(args)
            .arg(mountpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if !run(&[OsStr::new("-u")]) {
        run(&[OsStr::new("-u"), OsStr::new("-z")]);
    }
}

/// A JSON line of request counts for each line on stdin, until it ends.
fn report(counts: Arc<view::Counts>) {
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            if line.is_err() {
                break;
            }
            println!("{}", counts.take());
        }
    });
}

/// Serve a mount of its own until it is unmounted -- by SIGTERM or SIGINT, which are taken by
/// sigwait here (blocked in every thread, none interrupting a request), or from outside.
fn mounted(view: view::View, mountpoint: PathBuf, config: fuser::Config, counts: Arc<view::Counts>) -> Result<(), String> {
    let signals = sys::Signals::of(&[libc::SIGTERM, libc::SIGINT]);
    signals.block(); // before any thread is spawned: each inherits the mask
    report(counts);
    let ended = Arc::new(AtomicBool::new(false));
    let session = {
        let (ended, mountpoint) = (ended.clone(), mountpoint.clone());
        std::thread::spawn(move || {
            let result = fuser::mount(view, &mountpoint, &config);
            ended.store(true, Ordering::SeqCst);
            sys::signal_self(libc::SIGTERM); // the main thread waits for signals, not for this
            result
        })
    };
    signals.wait();
    if !ended.load(Ordering::SeqCst) {
        unmount(&mountpoint);
    }
    match session.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("{}: {e}", mountpoint.display())),
        Err(_) => Err("the session panicked".to_string()),
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let text = std::fs::read_to_string(&args.spec).map_err(|e| format!("{}: {e}", args.spec.display()))?;
    let spec = spec::parse(&text).map_err(|e| format!("{}: {e}", args.spec.display()))?;
    sys::raise_fd_limit();
    // the kernel applied the jail's umask to every mode it sends; the daemon's must not apply again
    sys::clear_umask();
    let counts = Arc::new(view::Counts::default());
    let view = view::View::new(spec, args.ttls, args.keep_cache, counts.clone()).map_err(|e| format!("cannot serve: {e}"))?;
    let mut config = fuser::Config::default();
    if args.threads > 1 {
        config.n_threads = Some(args.threads);
    }
    match args.serve {
        Serve::Mount(mountpoint) => {
            config.mount_options = vec![
                fuser::MountOption::FSName("certorail-view-rs".to_string()),
                fuser::MountOption::DefaultPermissions,
            ];
            mounted(view, mountpoint, config, counts)
        }
        Serve::Fd(fd) => {
            report(counts);
            let session = fuser::Session::from_fd(view, fd, fuser::SessionACL::Owner, config)
                .map_err(|e| format!("cannot serve the descriptor: {e}"))?;
            session.run().map_err(|e| format!("the session ended: {e}"))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("fuseview-rs: {message}");
            ExitCode::from(2)
        }
    }
}
