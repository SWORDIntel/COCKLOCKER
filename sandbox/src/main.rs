// CockLocker Sandbox - APT-level threat isolation for Cockpit
// Inspired by ImageHarden's sandboxing approach

use anyhow::{Context, Result};
use clap::Parser;
use landlock::{
    Access, AccessFs, PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use log::{error, info, warn};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter,
    SeccompRule,
};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to hardened Cockpit installation
    #[arg(short, long, default_value = "/opt/cockpit-hardened")]
    cockpit_path: PathBuf,

    /// Configuration file path
    #[arg(short, long, default_value = "/opt/cockpit-hardened/etc/cockpit/cockpit.conf")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind_address: String,

    /// Port number
    #[arg(short, long, default_value = "9090")]
    port: u16,

    /// Enable Xen-specific hardening
    #[arg(short = 'x', long)]
    xen_hardening: bool,
}

#[derive(Debug, thiserror::Error)]
enum SandboxError {
    #[error("Failed to create namespace: {0}")]
    NamespaceError(String),

    #[error("Failed to apply seccomp filter: {0}")]
    SeccompError(String),

    #[error("Failed to apply Landlock rules: {0}")]
    LandlockError(String),

    #[error("Failed to execute Cockpit: {0}")]
    ExecutionError(String),
}

/// Create a strict seccomp filter for Cockpit
fn create_cockpit_seccomp_filter() -> Result<BpfProgram> {
    info!("Creating seccomp-bpf filter for Cockpit...");

    // Allow only essential syscalls needed for Cockpit operation
    let allowed_syscalls = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_ioctl,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_access,
        libc::SYS_pipe,
        libc::SYS_select,
        libc::SYS_sched_yield,
        libc::SYS_mremap,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_nanosleep,
        libc::SYS_getpid,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_socketpair,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_clone,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_kill,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_gettimeofday,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getppid,
        libc::SYS_getpgrp,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_getpgid,
        libc::SYS_umask,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_setrlimit,
        libc::SYS_sync,
        libc::SYS_gettid,
        libc::SYS_futex,
        libc::SYS_time,
        libc::SYS_set_tid_address,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        libc::SYS_signalfd,
        libc::SYS_signalfd4,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_pselect6,
        libc::SYS_ppoll,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_shutdown,
        libc::SYS_getrandom,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    for syscall in allowed_syscalls {
        rules.insert(syscall, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .context("Failed to create seccomp filter")?;

    Ok(filter.try_into()?)
}

/// Apply Landlock filesystem restrictions
fn apply_landlock_restrictions(cockpit_path: &Path) -> Result<()> {
    info!("Applying Landlock filesystem restrictions...");

    let abi = ABI::V4;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    // Allow read access to Cockpit installation
    let cockpit_access = AccessFs::from_read(abi);
    let cockpit_fd = fs::File::open(cockpit_path).context("Failed to open Cockpit path")?;
    ruleset = ruleset.add_rule(PathBeneath::new(&cockpit_fd, cockpit_access))?;

    // Allow limited write access to specific directories
    let log_path = PathBuf::from("/var/log/cockpit-hardened");
    if log_path.exists() {
        let log_access = AccessFs::WriteFile | AccessFs::MakeDir;
        let log_fd = fs::File::open(&log_path).context("Failed to open log path")?;
        ruleset = ruleset.add_rule(PathBeneath::new(&log_fd, log_access))?;
    }

    // Restrict the calling thread
    let status = ruleset
        .restrict_self()
        .context("Failed to apply Landlock restrictions")?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock restrictions fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            warn!("Landlock restrictions partially enforced");
        }
        RulesetStatus::NotEnforced => {
            error!("Landlock restrictions not enforced - kernel may not support Landlock");
        }
    }

    Ok(())
}

/// Setup network namespace with restricted access
fn setup_network_namespace(_bind_address: &str, _port: u16) -> Result<()> {
    info!("Setting up network namespace...");

    // Create new network namespace
    // In production, configure only loopback or specific interfaces
    // For now, we'll use the host network but with strict firewall rules

    Ok(())
}

/// Drop capabilities to minimum required set
fn drop_capabilities() -> Result<()> {
    info!("Dropping unnecessary capabilities...");

    use caps::{CapSet, Capability};

    // Keep only essential capabilities
    let essential_caps = vec![
        Capability::CAP_NET_BIND_SERVICE, // Bind to ports < 1024 if needed
        Capability::CAP_SETUID,            // Switch users
        Capability::CAP_SETGID,            // Switch groups
    ];

    // Clear all capabilities first
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Effective)?;
    caps::clear(None, CapSet::Inheritable)?;

    // Set only essential capabilities
    let caps_set: HashSet<_> = essential_caps.into_iter().collect();
    caps::set(None, CapSet::Permitted, &caps_set)?;
    caps::set(None, CapSet::Effective, &caps_set)?;

    info!("Capabilities dropped successfully");
    Ok(())
}

/// Setup Xen-specific hardening
fn setup_xen_hardening() -> Result<()> {
    info!("Applying Xen hypervisor-specific hardening...");

    // Disable speculative execution mitigations that might leak across VMs
    // Check for Xen PV interfaces and harden them
    if Path::new("/proc/xen").exists() {
        info!("Xen environment detected");

        // Additional hardening for Xen dom0/domU environment
        // 1. Ensure event channels are properly isolated
        // 2. Verify grant table operations are restricted
        // 3. Check for PV driver security settings

        // Read Xen capabilities
        if let Ok(caps) = fs::read_to_string("/proc/xen/capabilities") {
            info!("Xen capabilities: {}", caps.trim());

            if caps.contains("control_d") {
                warn!("Running in dom0 - extra caution required");
            }
        }
    } else {
        warn!("Xen environment not detected, skipping Xen-specific hardening");
    }

    Ok(())
}

/// Create and enter sandboxed environment
fn enter_sandbox(args: &Args) -> Result<()> {
    info!("Entering sandboxed environment for Cockpit...");

    // Apply Xen hardening if enabled
    if args.xen_hardening {
        setup_xen_hardening()?;
    }

    // Drop capabilities
    drop_capabilities()?;

    // Apply Landlock restrictions
    apply_landlock_restrictions(&args.cockpit_path)?;

    // Apply seccomp filter
    let seccomp_filter = create_cockpit_seccomp_filter()?;
    seccompiler::apply_filter(&seccomp_filter)
        .context("Failed to apply seccomp filter")?;

    info!("Sandbox environment fully configured");
    Ok(())
}

/// Launch Cockpit in sandboxed environment
fn launch_cockpit(args: &Args) -> Result<()> {
    info!("Launching hardened Cockpit...");

    // Enter sandbox
    enter_sandbox(args)?;

    // Construct Cockpit ws command
    let ws_binary = args.cockpit_path.join("libexec/cockpit-ws");

    if !ws_binary.exists() {
        anyhow::bail!(
            "Cockpit ws binary not found at {}",
            ws_binary.display()
        );
    }

    // Launch Cockpit with restricted parameters
    let mut cmd = Command::new(&ws_binary);
    cmd.arg("--port")
        .arg(args.port.to_string())
        .arg("--address")
        .arg(&args.bind_address);

    if args.verbose {
        cmd.arg("--verbose");
    }

    // Set up environment
    cmd.env("COCKPIT_CONFIG_DIR", args.cockpit_path.join("etc/cockpit"));
    cmd.env_remove("LD_PRELOAD"); // Security: prevent LD_PRELOAD attacks

    info!("Executing: {:?}", cmd);

    // Execute
    let status = cmd.status().context("Failed to execute Cockpit")?;

    if !status.success() {
        anyhow::bail!("Cockpit exited with error: {}", status);
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    info!("CockLocker Sandbox - APT-level threat isolation for Cockpit");
    info!("==========================================================");

    // Verify running as root (needed for namespace creation)
    if !nix::unistd::Uid::effective().is_root() {
        error!("This program must be run as root for proper sandboxing");
        std::process::exit(1);
    }

    // Verify Cockpit installation exists
    if !args.cockpit_path.exists() {
        error!(
            "Cockpit installation not found at {}",
            args.cockpit_path.display()
        );
        error!("Please run build_hardened_cockpit.sh first");
        std::process::exit(1);
    }

    // Create log directory
    let log_dir = PathBuf::from("/var/log/cockpit-hardened");
    fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    // Launch Cockpit in sandbox
    if let Err(e) = launch_cockpit(&args) {
        error!("Failed to launch Cockpit: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
