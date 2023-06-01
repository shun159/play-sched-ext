#[path = "bpf/.output/usched.skel.rs"]
mod usched;
pub use usched::*;
pub mod usched_sys;

use anyhow::{Context, Result};
use clap::Parser;
use log::*;

#[derive(Debug, Parser)]
struct Opts {
    /// Target PID
    #[clap(short, long, default_value = "1")]
    pid: i32,

    /// Scheduling slice duration in microseconds.
    #[clap(short, long, default_value = "20000")]
    slice_us: u64,

    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    partial: bool,
}

fn skel_init(opts: Opts) -> Result<()>{
    let mut skel_builder = UschedSkelBuilder::default();
    skel_builder.obj_builder.debug(opts.verbose > 0);
    let mut skel = skel_builder.open().context("failed to open BPF program")?;

    skel.rodata().slice_ns = opts.slice_us * 1000;
    skel.rodata().switch_partial = opts.partial;
    skel.rodata().usersched_pid = opts.pid;

    println!("oogheoe");
    // Attach.
    let mut skel = skel.load().context("Failed to load BPF program")?;
    skel.attach().context("Failed to attach BPF program")?;
    let struct_ops = Some(
        skel.maps_mut()
            .usched_ops()
            .attach_struct_ops()
            .context("Failed to attach usched struct ops")?,
    );
    return Ok(())
}

fn main() {
    let opts = Opts::parse();
    let _ = skel_init(opts);
}
