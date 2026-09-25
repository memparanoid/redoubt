# Forensics in redoubt-rand

## Where the bytes come from

On Linux, x86-64 and AArch64, `fill_with_random_bytes` asks the kernel through
`redoubt_rand_fill` (`src/asm/`): the `getrandom` syscall issued by the routine
itself, the bytes written by the kernel straight into the caller's buffer, and
every caller-saved general register emptied before it returns. No libc, no
vDSO, nothing in user space between the kernel and the buffer but the routine.

Its probe (`src/tests/backend/asm/probes.rs`) is what answers for it: every
register the routine could have written reads as zero afterwards, whatever the
bytes were. That is stronger than a sweep for a needle, and no forensics test
re-measures it.

## Why the `getrandom` crate is not measured

Everywhere else — another operating system, another architecture, and
`Backend::Rust` under test — the bytes come from the `getrandom` crate, and
through it from the platform's libc, which may generate them in user space
rather than asking the kernel.

None of that is code of this crate. A residue found there would have nothing
here to fix, and a clean reading would be a claim about one libc on one
machine, not about the path. So it is not measured, and nothing in this crate
claims it leaves nothing.

Off Linux there is nothing to measure it with either: the sweep reads
`/proc/self`, so `redoubt-forensics` runs on Linux only. And on Windows and
WASI a key made from these bytes has no protected memory to go to — no page
that can be locked and closed — so it sits in ordinary memory for as long as
it is held. A path proven clean into a key anyone can read would be worth
nothing, which is why the fallback is the `getrandom` crate and nothing more.
