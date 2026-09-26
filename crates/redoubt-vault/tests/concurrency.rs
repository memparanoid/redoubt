// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

use std::num::NonZero;
use std::sync::{Arc, Barrier, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use redoubt_alloc::RedoubtVec;
use redoubt_codec::RedoubtCodec;
use redoubt_secret::RedoubtSecret;
use redoubt_vault::{CipherBoxError, cipherbox};
use redoubt_zero::RedoubtZero;

const ROUNDS: usize = 100;
const WRITES: u64 = 200;
const LEFT: u64 = 7;
const RIGHT: u64 = 9;
const BLOB_LEN: usize = 256 * 1024;
/// What the blob grows by with every write, so the workspace it is read into
/// has to grow between reads.
const GROWTH: usize = 1024;
const DEADLINE: Duration = Duration::from_secs(120);

#[cipherbox(PairBox)]
#[derive(Default, RedoubtZero, RedoubtCodec)]
#[fast_zeroize(drop)]
struct Pair {
    left: RedoubtSecret<u64>,
    right: RedoubtSecret<u64>,
    blob: RedoubtVec<u8>,
}

/// Four per core, so readers are preempted while they hold a workspace and
/// the others pile up behind it.
fn readers() -> usize {
    thread::available_parallelism().map_or(4, NonZero::get) * 4
}

fn blob() -> Vec<u8> {
    (0..BLOB_LEN).map(|index| (index % 251) as u8).collect()
}

fn sealed() -> Result<PairBox, CipherBoxError> {
    let mut pair_box = PairBox::new();

    pair_box.open_mut(|pair| {
        pair.left.replace(&mut { LEFT });
        pair.right.replace(&mut { RIGHT });
        pair.blob.replace_from_mut_slice(&mut blob());

        Ok(())
    })?;

    Ok(pair_box)
}

/// Every field carries the write's counter, so a read can tell whether all of
/// them came from the same write.
fn stamp_every_field(pair: &mut Pair, write_counter: u64) -> Result<(), CipherBoxError> {
    pair.left.replace(&mut { write_counter });
    pair.right.replace(&mut { write_counter });
    pair.blob.replace_from_mut_slice(&mut vec![
        write_counter as u8;
        BLOB_LEN + GROWTH * write_counter as usize
    ]);

    Ok(())
}

fn assert_stamped_by(blob: &[u8], write_counter: u64) {
    assert_eq!(blob.len(), BLOB_LEN + GROWTH * write_counter as usize);
    assert!(
        blob.iter().all(|&byte| byte == write_counter as u8),
        "a read saw a blob from two writes"
    );
}

/// Sends from `drop`, so a reader that panics reaches its join instead of
/// reading as a hang.
struct Finished(mpsc::Sender<()>);

impl Drop for Finished {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

fn read_concurrently<F>(what: &str, read: F)
where
    F: Fn(usize) + Send + Sync + 'static,
{
    let readers = readers();
    let read = Arc::new(read);
    let start = Arc::new(Barrier::new(readers));
    let (finished, finishing) = mpsc::channel();

    let handles: Vec<_> = (0..readers)
        .map(|reader| {
            let read = Arc::clone(&read);
            let start = Arc::clone(&start);
            let finished = Finished(finished.clone());

            thread::spawn(move || {
                let _finished = finished;

                start.wait();

                for round in 0..ROUNDS {
                    read(reader + round);
                }
            })
        })
        .collect();

    let deadline = Instant::now() + DEADLINE;

    for _ in 0..readers {
        let left = deadline.saturating_duration_since(Instant::now());

        if finishing.recv_timeout(left).is_err() {
            panic!("{what}: a reader did not finish within {DEADLINE:?}");
        }
    }

    for handle in handles {
        handle
            .join()
            .unwrap_or_else(|_| panic!("{what}: a reader panicked"));
    }
}

// ============================================================================
// open
// ============================================================================

#[test]
fn test_open_hands_every_reader_the_whole_struct() -> Result<(), CipherBoxError> {
    let pair_box = Arc::new(sealed()?);
    let expected = Arc::new(blob());

    read_concurrently("open", move |_| {
        pair_box
            .open(|pair| {
                assert_eq!(*pair.left.as_ref(), LEFT);
                assert_eq!(*pair.right.as_ref(), RIGHT);
                assert_eq!(pair.blob.as_slice(), expected.as_slice());

                Ok(())
            })
            .expect("a read of a sealed box failed");
    });

    Ok(())
}

// ============================================================================
// open_mut
// ============================================================================

#[test]
fn test_open_mut_between_reads_is_seen_whole_by_every_read() -> Result<(), CipherBoxError> {
    let mut first = PairBox::new();

    first.open_mut(|pair| stamp_every_field(pair, 0))?;

    let pair_box = Arc::new(RwLock::new(first));

    let writing = Arc::clone(&pair_box);
    let writer = thread::spawn(move || {
        for write_counter in 1..=WRITES {
            let mut held = writing.write().expect("a reader panicked holding the box");

            held.open_mut(|pair| stamp_every_field(pair, write_counter))
                .expect("a write to a sealed box failed");
        }
    });

    let reading = Arc::clone(&pair_box);
    read_concurrently("reads between writes", move |_| {
        let held = reading.read().expect("the writer panicked holding the box");

        held.open(|pair| {
            let write_counter = *pair.left.as_ref();

            assert_eq!(
                write_counter,
                *pair.right.as_ref(),
                "a read saw half a write"
            );
            assert_stamped_by(pair.blob.as_slice(), write_counter);

            Ok(())
        })
        .expect("a read of a sealed box failed");

        let blob = held.leak_blob().expect("a read of a sealed box failed");
        let write_counter = (blob.len() - BLOB_LEN) / GROWTH;

        assert_stamped_by(blob.as_slice(), write_counter as u64);
    });

    writer.join().expect("the writer panicked");

    Ok(())
}

// ============================================================================
// leak_<field>
// ============================================================================

#[test]
fn test_leak_hands_every_reader_the_sealed_field() -> Result<(), CipherBoxError> {
    let pair_box = Arc::new(sealed()?);
    let expected = Arc::new(blob());

    read_concurrently("leak", move |_| {
        let blob = pair_box.leak_blob().expect("a read of a sealed box failed");

        assert_eq!(blob.as_slice(), expected.as_slice());
    });

    Ok(())
}

#[test]
fn test_leak_of_different_fields_hands_each_its_own() -> Result<(), CipherBoxError> {
    let pair_box = Arc::new(sealed()?);
    let expected = Arc::new(blob());

    read_concurrently("leak of different fields", move |turn| match turn % 3 {
        0 => {
            let left = pair_box.leak_left().expect("a read of a sealed box failed");

            assert_eq!(*left.as_ref(), LEFT);
        }
        1 => {
            let right = pair_box
                .leak_right()
                .expect("a read of a sealed box failed");

            assert_eq!(*right.as_ref(), RIGHT);
        }
        _ => {
            let blob = pair_box.leak_blob().expect("a read of a sealed box failed");

            assert_eq!(blob.as_slice(), expected.as_slice());
        }
    });

    Ok(())
}
