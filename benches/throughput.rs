//! Placeholder for Criterion benchmarks.
//!
//! **Owner:** Matthew Wang — Testing & Benchmarking
//!
//! This file will measure normal vs. anamorphic throughput as the covert
//! payload size scales, verifying that overhead is linear.

use criterion::{criterion_group, criterion_main, Criterion};

fn placeholder_benchmark(_c: &mut Criterion) {
    // Matthew: implement throughput benchmarks here.
    // See Guru.md Phase 4 and README §8 for expected measurements.
}

criterion_group!(benches, placeholder_benchmark);
criterion_main!(benches);
