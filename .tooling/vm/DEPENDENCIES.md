# What the cross tests need

`scripts/cross-nextest.sh` runs the tests on a machine with a kernel of its own
for each architecture, under `qemu-system-aarch64` and `qemu-system-x86_64`,
with both C libraries on each. A machine has `ptrace`, which process emulation
refuses: a host kernel cannot be told that one emulated process is the tracer
of another.

---

## For `cross-nextest.sh`

| | what for |
|---|---|
| `qemu-system-aarch64`, `qemu-system-x86_64` | the machines themselves |
| `qemu-img` | their disks |
| `cloud-localds` | the first-boot configuration |
| `socat` | talks to a machine's monitor, which is how it is told to freeze |
| `curl` | fetches the Ubuntu image once |
| `ssh`, `scp`, `ssh-keygen` | everything after the first boot |
| the EDK2 `aarch64` firmware | `aarch64` has no BIOS; it boots UEFI |
| `<arch>-unknown-linux-gnu-gcc` | links the glibc half, per architecture |
| `<arch>-unknown-linux-musl-gcc` | links the musl half, per architecture |
| the `<arch>-unknown-linux-gnu` and `<arch>-unknown-linux-musl` targets | `rustup target add`, or the toolchain's own way |

`GNU_CC` and `MUSL_CC` name the compilers where they go by other names.

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
