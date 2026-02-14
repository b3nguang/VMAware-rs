# VMAware-rs

A cross-platform Rust library for virtual machine detection — port of [VMAware](https://github.com/kernelwernel/VMAware) (C++).

## Features

- **Cross-platform**: Windows, Linux, and macOS support
- **~90 detection techniques** covering CPUID, firmware, registry, DMI, PCI, processes, and more
- **~70 VM brands** detected including VMware, VirtualBox, QEMU, Hyper-V, KVM, Parallels, and many others
- **Scoring system** with configurable thresholds
- **Memoized results** — techniques are cached for performance
- **CLI tool** included
- **MIT licensed**

## Quick Start

Add to your `Cargo.toml`:
```toml
[dependencies]
vmaware = { path = "." }
```

### Library Usage

```rust
use vmaware::VM;

fn main() {
    if VM::detect(None) {
        println!("Virtual machine detected!");
    } else {
        println!("Running on baremetal");
    }

    println!("VM name: {}", VM::brand(None));
    println!("VM type: {}", VM::vm_type(None));
    println!("VM certainty: {}%", VM::percentage(None));
    println!("VM hardening: {}", if VM::is_hardened() { "likely" } else { "not found" });
}
```

### Custom Flags

```rust
use vmaware::{VM, flags::FlagSet};

fn main() {
    // Use high threshold for stricter detection
    let flags = VM::high_threshold_flags();
    let is_vm = VM::detect(Some(&flags));

    // Disable specific techniques
    let flags = VM::disable(&[VM::TIMER, VM::VMID]);
    let is_vm = VM::detect(Some(&flags));

    // Check a single technique
    let rdtsc_detected = VM::check(VM::TIMER);

    // Get all results at once
    let result = vmaware::VMAwareResult::new(None);
    println!("{:?}", result);
}
```

### Custom Techniques & Score Tuning

```rust
use vmaware::VM;

fn main() {
    // Add a user-defined detection technique
    VM::add_custom(100, "Check for VM marker file", || {
        std::path::Path::new("/tmp/vm_marker").exists()
    });

    // Adjust built-in technique scores
    VM::modify_score(VM::TIMER, -50);  // reduce TIMER contribution

    println!("Detected: {}", VM::detect(None));
}
```

### CLI Tool

```bash
cargo run --bin vmaware-cli

# Specific queries
cargo run --bin vmaware-cli -- --detect
cargo run --bin vmaware-cli -- --brand
cargo run --bin vmaware-cli -- --percent
cargo run --bin vmaware-cli -- --verbose
cargo run --bin vmaware-cli -- --detected-only
```

## Architecture

```
src/
├── lib.rs                  # Public API (VM struct, VMAwareResult)
├── brands.rs               # VM brand string constants (~70 brands)
├── flags.rs                # Technique enum flags and FlagSet
├── cpu.rs                  # CPUID operations
├── memo.rs                 # Memoization / result caching
├── engine.rs               # Scoring engine, technique table, brand scoreboard
├── util.rs                 # Utility functions (file I/O, registry, processes)
├── techniques/
│   ├── mod.rs
│   ├── cross_platform.rs   # Cross-platform techniques (CPUID, timing, etc.)
│   ├── windows.rs          # Windows-specific techniques (registry, DLLs, etc.)
│   ├── linux.rs            # Linux-specific techniques (sysfs, DMI, proc, etc.)
│   └── macos.rs            # macOS-specific techniques (sysctl, ioreg, etc.)
└── bin/
    └── cli.rs              # CLI binary
```

## API Reference

| Method | Description |
|---|---|
| `VM::detect(flags)` | Returns `true` if a VM is detected |
| `VM::brand(flags)` | Returns the most likely VM brand name |
| `VM::percentage(flags)` | Returns detection certainty (0-100) |
| `VM::vm_type(flags)` | Returns the VM type (e.g. "Hypervisor (type 2)") |
| `VM::conclusion(flags)` | Returns a human-readable conclusion |
| `VM::check(flag)` | Check a single technique |
| `VM::detected_count(flags)` | Number of techniques that detected a VM |
| `VM::detected_enums(flags)` | List of detected technique flags |
| `VM::is_hardened()` | Check for anti-VM hardening |
| `VM::add_custom(pts, desc, fn)` | Add a user-defined technique |
| `VM::modify_score(flag, delta)` | Adjust a technique's score contribution |
| `VM::flag_to_string(flag)` | Get a technique's string name |
| `VM::disable(techniques)` | Create a FlagSet with specific techniques disabled |
| `VM::reset()` | Reset all caches and internal state |

## Credits

This is a Rust port of the original [VMAware](https://github.com/kernelwernel/VMAware) C++ library by [kernelwernel](https://github.com/kernelwernel) and [Requiem](https://github.com/NotRequiem).

## License

MIT
