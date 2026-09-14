# What the cross tests need

Two ways of running this workspace on an architecture this machine is not,
and they answer different questions.

`scripts/cross-test.sh`, one per crate, runs the tests under **`qemu-aarch64`**
— process emulation. Seconds, and it covers the other C library and the other
architecture.

`scripts/cross-nextest.sh` runs them on an **`aarch64` machine with a kernel of
its own**, under `qemu-system-aarch64`. Minutes, and it reaches the one thing
process emulation cannot: `ptrace`. A host kernel cannot be told that one
emulated process is the tracer of another, so every `cross-test.sh` run takes
the two-process path and the three-process one has never been read on
`aarch64` at all.

---

## For `cross-test.sh`

| | what for |
|---|---|
| `qemu-aarch64` | runs an `aarch64` binary on this machine |
| `aarch64-unknown-linux-musl-gcc` | links the `aarch64` test binaries |
| `x86_64-unknown-linux-musl-gcc` | links the musl ones for this architecture |
| the `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` targets | `rustup target add`, or the toolchain's own way |

Each script takes `CROSS_CC`, `MUSL_CC` and `QEMU` for a machine that calls
them something else.

## For `cross-nextest.sh`

Everything above, and:

| | what for |
|---|---|
| `qemu-system-aarch64` | the machine itself |
| `qemu-img` | its disk |
| `cloud-localds` | the first-boot configuration |
| `socat` | talks to the machine's monitor, which is how it is told to freeze |
| `curl` | fetches the Ubuntu image once |
| `ssh`, `scp`, `ssh-keygen` | everything after the first boot |
| the EDK2 `aarch64` firmware | `aarch64` has no BIOS; it boots UEFI |
| `aarch64-unknown-linux-gnu-gcc` | links the glibc half |
| the `aarch64-unknown-linux-gnu` target | the same |

The firmware is `edk2-aarch64-code.fd`, and it ships with qemu. `build.sh`
looks for it under `/run/current-system/sw/share/qemu`, `/usr/share/qemu` and
`/usr/share/AAVMF`.

### Both C libraries, and why

The C library decides the allocator, and the allocator decides what a freed
chunk keeps: glibc leaves everything past a chunk's first bytes where it was,
and musl's `mallocng` may cover the lot. A sweep reads whatever is left, so the
same leak can show under one and not the other.

A musl build links statically and runs on the machine anyway, so one machine
serves both.

## On NixOS

In `environment.systemPackages`:

```nix
qemu                    # qemu-system-aarch64, qemu-img, the EDK2 firmware
cloud-utils             # cloud-localds
socat
pkgsCross.aarch64-multiplatform.buildPackages.gcc      # the glibc cross compiler
pkgsCross.aarch64-multiplatform-musl.buildPackages.gcc # the musl one
```

The cross compilers come out named for their triple, which is what the scripts
look for.

## Somewhere else

Whatever the package manager calls them, plus the Rust targets:

```sh
rustup target add aarch64-unknown-linux-gnu aarch64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

## What none of this needs

A compiler inside the machine. `cargo nextest archive` writes the test
binaries, already linked, into one file, and only that file goes in. Emulating
a whole system has no KVM to lean on, so building in there would take an
afternoon — and a toolchain in there would be a second one to keep in step
with this one.
