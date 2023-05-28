#[path = "bpf/.output/usched.skel.rs"]

mod usched;
pub use usched::*;
pub mod usched_sys;

fn main() {
    println!("Hello, world!");
}
