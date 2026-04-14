#![allow(dead_code)]
use criterion::{measurement::WallTime, BenchmarkGroup, SamplingMode};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const PARAM_BITS: usize = 2048;
pub const NORMAL_MSG: &[u8] = b"normal benchmark payload";
pub const BENCH_MAC_KEY: &[u8] = b"0123456789abcdef";
pub const BENCH_BLOCK_SIZE: usize = 16;
pub const PRF_COVERT_SIZES: [usize; 7] = [0, 1024, 4096, 16384, 65536, 131072, 262144];
pub const PRF_LARGE_COVERT_SIZES: [usize; 8] = [
    393216,
    524288,
    786432,
    1048576,
    1310720,
    1572864,
    1835008,
    2097152,
];
pub const XOR_COVERT_SIZES: [usize; 8] = [0, 1024, 4096, 16384, 65536, 131072, 262144, 524288];
pub const XOR_LARGE_COVERT_SIZES: [usize; 8] = [
    786432,
    1048576,
    1572864,
    2097152,
    2621440,
    3145728,
    3670016,
    4194304,
];
pub const SEARCH_FAST_SET_SIZES: [usize; 3] = [1, 4, 16];
pub const SEARCH_SLOW_SET_SIZES: [usize; 2] = [64, 256];
pub const STREAM_COVERT_SIZES: [usize; 3] = [1, 4, 16];
pub const STREAM_LARGE_COVERT_SIZES: [usize; 2] = [64, 256];

pub fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

pub fn derive_keystream_for_bench(shared: &BigUint, length: usize, p: &BigUint) -> Vec<u8> {
    let shared_bytes = shared.to_bytes_be();
    let width = ((p.bits() + 7) / 8) as usize;
    let mut padded = vec![0u8; width];
    if shared_bytes.len() <= width {
        padded[width - shared_bytes.len()..].copy_from_slice(&shared_bytes);
    }
    let mut keystream = Vec::with_capacity(length);
    let mut counter = 0u32;

    while keystream.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(&padded);
        hasher.update(counter.to_be_bytes());
        keystream.extend_from_slice(&hasher.finalize());
        counter += 1;
    }

    keystream.truncate(length);
    keystream
}

pub fn search_candidates(correct: &[u8], candidate_count: usize) -> Vec<Vec<u8>> {
    let filler_count = candidate_count.saturating_sub(1);
    let mut candidates = Vec::with_capacity(filler_count + 1);

    for index in 0..filler_count {
        let mut candidate = correct.to_vec();
        if candidate.is_empty() {
            candidate.push((index as u8).wrapping_add(1));
        } else {
            candidate[0] ^= ((index as u8) << 1) | 1;
        }

        if candidate == correct {
            candidate.push(0x01);
        }

        candidates.push(candidate);
    }

    candidates.push(correct.to_vec());
    candidates
}

pub fn apply_crypto_group_config(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(8));
}

pub fn apply_payload_scaling_group_config(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(6));
}

pub fn apply_large_payload_scaling_group_config(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(4));
}

pub fn apply_slow_setup_group_config(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
}

pub fn apply_slow_search_group_config(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
}

pub fn apply_slow_stream_group_config(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_millis(1));
    group.measurement_time(Duration::from_secs(1));
}
