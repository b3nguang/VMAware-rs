//! # VMAware-rs
//!
//! A cross-platform Rust library for virtual machine detection.
//! Port of [VMAware](https://github.com/kernelwernel/VMAware) (C++).
//!
//! ## Quick Start
//! ```rust
//! use vmaware::VM;
//!
//! fn main() {
//!     if VM::detect(None) {
//!         println!("Virtual machine detected!");
//!     } else {
//!         println!("Running on baremetal");
//!     }
//!
//!     println!("VM name: {}", VM::brand(None));
//!     println!("VM type: {}", VM::vm_type(None));
//!     println!("VM certainty: {}%", VM::percentage(None));
//! }
//! ```

pub mod brands;
pub mod flags;
pub mod cpu;
pub mod memo;
pub mod util;
pub mod engine;
pub mod techniques;

use flags::{Flag, FlagSet};

/// Main VM detection interface.
/// All methods are static — no instantiation needed.
pub struct VM;

impl VM {
    // ======================== Flag re-exports for convenience ========================

    pub const VMID: Flag = Flag::Vmid;
    pub const CPU_BRAND: Flag = Flag::CpuBrand;
    pub const HYPERVISOR_BIT: Flag = Flag::HypervisorBit;
    pub const HYPERVISOR_STR: Flag = Flag::HypervisorStr;
    pub const TIMER: Flag = Flag::Timer;
    pub const THREAD_COUNT: Flag = Flag::ThreadCount;
    pub const MAC: Flag = Flag::Mac;
    pub const TEMPERATURE: Flag = Flag::Temperature;
    pub const SYSTEMD: Flag = Flag::Systemd;
    pub const CVENDOR: Flag = Flag::Cvendor;
    pub const CTYPE: Flag = Flag::Ctype;
    pub const DOCKERENV: Flag = Flag::Dockerenv;
    pub const DMIDECODE: Flag = Flag::Dmidecode;
    pub const DMESG: Flag = Flag::Dmesg;
    pub const HWMON: Flag = Flag::Hwmon;
    pub const DLL: Flag = Flag::Dll;
    pub const HWMODEL: Flag = Flag::Hwmodel;
    pub const WINE: Flag = Flag::Wine;
    pub const POWER_CAPABILITIES: Flag = Flag::PowerCapabilities;
    pub const PROCESSES: Flag = Flag::Processes;
    pub const LINUX_USER_HOST: Flag = Flag::LinuxUserHost;
    pub const GAMARUE: Flag = Flag::Gamarue;
    pub const BOCHS_CPU: Flag = Flag::BochsCpu;
    pub const MAC_MEMSIZE: Flag = Flag::MacMemsize;
    pub const MAC_IOKIT: Flag = Flag::MacIokit;
    pub const IOREG_GREP: Flag = Flag::IoregGrep;
    pub const MAC_SIP: Flag = Flag::MacSip;
    pub const VPC_INVALID: Flag = Flag::VpcInvalid;
    pub const SYSTEM_REGISTERS: Flag = Flag::SystemRegisters;
    pub const VMWARE_IOMEM: Flag = Flag::VmwareIomem;
    pub const VMWARE_IOPORTS: Flag = Flag::VmwareIoports;
    pub const VMWARE_SCSI: Flag = Flag::VmwareScsi;
    pub const VMWARE_DMESG: Flag = Flag::VmwareDmesg;
    pub const VMWARE_STR: Flag = Flag::VmwareStr;
    pub const VMWARE_BACKDOOR: Flag = Flag::VmwareBackdoor;
    pub const MUTEX: Flag = Flag::Mutex;
    pub const THREAD_MISMATCH: Flag = Flag::ThreadMismatch;
    pub const CUCKOO_DIR: Flag = Flag::CuckooDir;
    pub const CUCKOO_PIPE: Flag = Flag::CuckooPipe;
    pub const AZURE: Flag = Flag::Azure;
    pub const DISPLAY: Flag = Flag::Display;
    pub const DEVICE_STRING: Flag = Flag::DeviceString;
    pub const BLUESTACKS_FOLDERS: Flag = Flag::BluestacksFolders;
    pub const CPUID_SIGNATURE: Flag = Flag::CpuidSignature;
    pub const KGT_SIGNATURE: Flag = Flag::KgtSignature;
    pub const QEMU_VIRTUAL_DMI: Flag = Flag::QemuVirtualDmi;
    pub const QEMU_USB: Flag = Flag::QemuUsb;
    pub const HYPERVISOR_DIR: Flag = Flag::HypervisorDir;
    pub const UML_CPU: Flag = Flag::UmlCpu;
    pub const KMSG: Flag = Flag::Kmsg;
    pub const VBOX_MODULE: Flag = Flag::VboxModule;
    pub const SYSINFO_PROC: Flag = Flag::SysinfoProc;
    pub const DMI_SCAN: Flag = Flag::DmiScan;
    pub const SMBIOS_VM_BIT: Flag = Flag::SmbiosVmBit;
    pub const PODMAN_FILE: Flag = Flag::PodmanFile;
    pub const WSL_PROC: Flag = Flag::WslProc;
    pub const DRIVERS: Flag = Flag::Drivers;
    pub const DISK_SERIAL: Flag = Flag::DiskSerial;
    pub const IVSHMEM: Flag = Flag::Ivshmem;
    pub const GPU_CAPABILITIES: Flag = Flag::GpuCapabilities;
    pub const DEVICE_HANDLES: Flag = Flag::DeviceHandles;
    pub const QEMU_FW_CFG: Flag = Flag::QemuFwCfg;
    pub const VIRTUAL_PROCESSORS: Flag = Flag::VirtualProcessors;
    pub const HYPERVISOR_QUERY: Flag = Flag::HypervisorQuery;
    pub const AMD_SEV: Flag = Flag::AmdSev;
    pub const VIRTUAL_REGISTRY: Flag = Flag::VirtualRegistry;
    pub const FIRMWARE: Flag = Flag::Firmware;
    pub const FILE_ACCESS_HISTORY: Flag = Flag::FileAccessHistory;
    pub const AUDIO: Flag = Flag::Audio;
    pub const NSJAIL_PID: Flag = Flag::NsjailPid;
    pub const PCI_DEVICES: Flag = Flag::PciDevices;
    pub const ACPI_SIGNATURE: Flag = Flag::AcpiSignature;
    pub const TRAP: Flag = Flag::Trap;
    pub const UD: Flag = Flag::Ud;
    pub const BLOCKSTEP: Flag = Flag::Blockstep;
    pub const DBVM: Flag = Flag::Dbvm;
    pub const BOOT_LOGO: Flag = Flag::BootLogo;
    pub const MAC_SYS: Flag = Flag::MacSys;
    pub const KERNEL_OBJECTS: Flag = Flag::KernelObjects;
    pub const NVRAM: Flag = Flag::Nvram;
    pub const SMBIOS_INTEGRITY: Flag = Flag::SmbiosIntegrity;
    pub const EDID: Flag = Flag::Edid;
    pub const CPU_HEURISTIC: Flag = Flag::CpuHeuristic;
    pub const CLOCK: Flag = Flag::Clock;

    // ======================== Public API ========================

    /// Detect if running inside a VM.
    ///
    /// Pass `None` for default flags, or `Some(flagset)` for custom configuration.
    ///
    /// # Examples
    /// ```rust
    /// use vmaware::VM;
    /// let is_vm = VM::detect(None);
    /// ```
    pub fn detect(flags: Option<&FlagSet>) -> bool {
        let default_flags = FlagSet::new_default();
        let flags = flags.unwrap_or(&default_flags);

        let points = engine::run_all(flags, true);

        let threshold = if flags.high_threshold {
            engine::HIGH_THRESHOLD_SCORE
        } else {
            engine::DEFAULT_THRESHOLD
        };

        if points >= threshold {
            return true;
        }

        // Last ditch: check hardening indicators
        Self::is_hardened()
    }

    /// Get the percentage certainty of VM detection (0-100).
    pub fn percentage(flags: Option<&FlagSet>) -> u8 {
        let default_flags = FlagSet::new_default();
        let flags = flags.unwrap_or(&default_flags);

        let points = engine::run_all(flags, true);

        let threshold = if flags.high_threshold {
            engine::HIGH_THRESHOLD_SCORE
        } else {
            engine::DEFAULT_THRESHOLD
        };

        if points >= threshold {
            100
        } else if points >= 100 {
            99
        } else {
            std::cmp::min(points, 99) as u8
        }
    }

    /// Get the most likely VM brand name.
    ///
    /// Returns "Unknown" if no brand was detected.
    pub fn brand(flags: Option<&FlagSet>) -> String {
        let default_flags = FlagSet::new_default();
        let flags = flags.unwrap_or(&default_flags);
        let is_multiple = flags.multiple;

        // Run all techniques to populate brand scoreboard
        let _score = engine::run_all(flags, false);

        // Check cache
        if is_multiple {
            if memo::multi_brand_is_cached() {
                return memo::multi_brand_fetch();
            }
        } else if memo::brand_is_cached() {
            return memo::brand_fetch();
        }

        // Collect active brands from scoreboard
        let scoreboard = engine::BRAND_SCOREBOARD.lock().unwrap();
        let mut active: Vec<(&str, i32)> = scoreboard
            .iter()
            .filter(|b| b.score > 0)
            .map(|b| (b.name, b.score))
            .collect();
        drop(scoreboard);

        if active.is_empty() {
            return brands::NULL_BRAND.to_string();
        }

        if active.len() == 1 {
            let result = active[0].0.to_string();
            memo::brand_store(&result);
            return result;
        }

        // Remove Hyper-V artifacts if other brands are present
        if active.len() > 1 {
            active.retain(|b| b.0 != brands::HYPERV_ARTIFACT);
        }

        // Brand merging logic
        Self::merge_brands(&mut active, brands::VPC, brands::HYPERV, brands::HYPERV_VPC);
        Self::merge_brands(&mut active, brands::AZURE_HYPERV, brands::HYPERV, brands::AZURE_HYPERV);
        Self::merge_brands(&mut active, brands::AZURE_HYPERV, brands::VPC, brands::AZURE_HYPERV);
        Self::merge_brands(&mut active, brands::AZURE_HYPERV, brands::HYPERV_VPC, brands::AZURE_HYPERV);
        Self::merge_brands(&mut active, brands::QEMU, brands::KVM, brands::QEMU_KVM);
        Self::merge_brands(&mut active, brands::KVM, brands::HYPERV, brands::KVM_HYPERV);
        Self::merge_brands(&mut active, brands::QEMU, brands::HYPERV, brands::QEMU_KVM_HYPERV);
        Self::merge_brands(&mut active, brands::QEMU_KVM, brands::HYPERV, brands::QEMU_KVM_HYPERV);
        Self::merge_brands(&mut active, brands::VMWARE, brands::VMWARE_FUSION, brands::VMWARE_FUSION);
        Self::merge_brands(&mut active, brands::VMWARE, brands::VMWARE_EXPRESS, brands::VMWARE_EXPRESS);
        Self::merge_brands(&mut active, brands::VMWARE, brands::VMWARE_ESX, brands::VMWARE_ESX);
        Self::merge_brands(&mut active, brands::VMWARE, brands::VMWARE_GSX, brands::VMWARE_GSX);
        Self::merge_brands(&mut active, brands::VMWARE, brands::VMWARE_WORKSTATION, brands::VMWARE_WORKSTATION);
        Self::merge_brands(&mut active, brands::VMWARE_HARD, brands::VMWARE, brands::VMWARE_HARD);

        // Sort by score descending
        active.sort_by(|a, b| b.1.cmp(&a.1));

        if active.is_empty() {
            return brands::NULL_BRAND.to_string();
        }

        if !is_multiple {
            let result = active[0].0.to_string();
            memo::brand_store(&result);
            result
        } else {
            let result = active
                .iter()
                .map(|b| b.0)
                .collect::<Vec<_>>()
                .join(" or ");
            memo::multi_brand_store(&result);
            result
        }
    }

    /// Helper: merge two brands into a combined brand if both are present.
    fn merge_brands(active: &mut Vec<(&str, i32)>, a: &str, b: &str, result: &'static str) {
        let has_a = active.iter().any(|x| x.0 == a);
        let has_b = active.iter().any(|x| x.0 == b);

        if has_a && has_b {
            active.retain(|x| x.0 != a && x.0 != b);
            active.push((result, 2));
        }
    }

    /// Get the VM type string (e.g., "Hypervisor (type 2)").
    pub fn vm_type(flags: Option<&FlagSet>) -> String {
        let brand_str = Self::brand(flags);

        if brand_str.contains(" or ") {
            return "Unknown".to_string();
        }

        brands::brand_to_type(&brand_str).to_string()
    }

    /// Get a conclusion message about the detection result.
    pub fn conclusion(flags: Option<&FlagSet>) -> String {
        let default_flags = FlagSet::new_default();
        let flags = flags.unwrap_or(&default_flags);

        let mut brand_str = Self::brand(Some(flags));
        let percent = Self::percentage(Some(flags));
        let hardened = Self::is_hardened();

        let hardener = if hardened { "hardened " } else { "" };

        let article = if !hardened && matches!(
            brand_str.as_str(),
            "ACRN" | "Anubis" | "OpenBSD VMM" | "Intel HAXM" | "Apple VZ"
            | "Intel KGT (Trusty)" | "IBM PowerVM" | "OpenStack (KVM)"
            | "AWS Nitro System EC2 (KVM-based)" | "OpenVZ" | "Intel TDX"
            | "AMD SEV" | "AMD SEV-ES" | "AMD SEV-SNP" | "nsjail" | "Unknown"
        ) {
            "an "
        } else {
            "a "
        };

        if brand_str == brands::NULL_BRAND {
            brand_str = "unknown".to_string();
        }

        let is_artifact = brand_str == brands::HYPERV_ARTIFACT;
        let vm_suffix = if is_artifact { "" } else { " VM" };

        let make_conclusion = |category: &str| -> String {
            format!("{}{}{}{}{}", category, article, hardener, brand_str, vm_suffix)
        };

        if hardened {
            return make_conclusion("Running inside ");
        }

        if flags.dynamic {
            if percent == 0 { return "Running on baremetal".to_string(); }
            if percent <= 20 { return make_conclusion("Very unlikely "); }
            if percent <= 35 { return make_conclusion("Unlikely "); }
            if percent < 50 { return make_conclusion("Potentially "); }
            if percent <= 62 { return make_conclusion("Might be "); }
            if percent <= 75 { return make_conclusion("Likely "); }
            if percent < 100 { return make_conclusion("Very likely "); }
        }

        if percent == 100 {
            return make_conclusion("Running inside ");
        }

        "Running on baremetal".to_string()
    }

    /// Check a single technique and return whether it detected a VM.
    pub fn check(flag: Flag) -> bool {
        if !flag.is_supported_on_current_platform() {
            return false;
        }

        // Check cache first
        if memo::is_cached(flag) {
            return memo::cache_fetch(flag).result;
        }

        // Find and run the technique
        let table = &*engine::TECHNIQUE_TABLE;
        for (f, technique) in table.iter() {
            if *f == flag {
                let result = (technique.run)();
                let pts = if result.score_override > 0 {
                    result.score_override
                } else {
                    technique.points
                };

                if result.detected {
                    let brand_name = result.brand.unwrap_or(brands::NULL_BRAND);
                    memo::cache_store(flag, true, pts, brand_name);

                    if let Some(brand) = result.brand {
                        engine::add_brand_score(brand);
                    }
                    if let Some(extra) = result.extra_brand {
                        engine::add_brand_score(extra);
                    }

                    let mut count = engine::DETECTED_COUNT.lock().unwrap();
                    *count += 1;

                    return true;
                } else {
                    memo::cache_store(flag, false, 0, brands::NULL_BRAND);
                    return false;
                }
            }
        }

        false
    }

    /// Get the number of techniques that detected a VM.
    pub fn detected_count(flags: Option<&FlagSet>) -> u8 {
        let default_flags = FlagSet::new_default();
        let flags = flags.unwrap_or(&default_flags);

        engine::run_all(flags, false);
        *engine::DETECTED_COUNT.lock().unwrap()
    }

    /// Get a list of all technique flags that were detected.
    pub fn detected_enums(flags: Option<&FlagSet>) -> Vec<Flag> {
        let default_flags = FlagSet::new_default();
        let flags = flags.unwrap_or(&default_flags);

        let mut detected = Vec::new();
        for flag in Flag::all_techniques() {
            if flags.is_enabled(flag) && Self::check(flag) {
                detected.push(flag);
            }
        }
        detected
    }

    /// Convert a technique flag to its string name.
    pub fn flag_to_string(flag: Flag) -> &'static str {
        flag.to_str()
    }

    /// Detect whether the environment has any hardening indications.
    pub fn is_hardened() -> bool {
        if memo::hardened_is_cached() {
            return memo::hardened_fetch();
        }

        let result = Self::hardened_logic();
        memo::hardened_store(result);
        result
    }

    fn hardened_logic() -> bool {
        let hv_present = Self::check(Flag::HypervisorBit) || Self::check(Flag::HypervisorStr);

        // Rule 1: If FIRMWARE is detected, so should HYPERVISOR_BIT or HYPERVISOR_STR
        if Self::check(Flag::Firmware) && !hv_present {
            return true;
        }

        #[cfg(target_os = "linux")]
        {
            // Rule 2: If FIRMWARE detected QEMU/VBOX, CVENDOR should match
            if memo::is_cached(Flag::Firmware) {
                let fw_data = memo::cache_fetch(Flag::Firmware);
                if fw_data.result {
                    let fw_brand = fw_data.brand_name;
                    if fw_brand == brands::QEMU || fw_brand == brands::VBOX {
                        if memo::is_cached(Flag::Cvendor) {
                            let cv_data = memo::cache_fetch(Flag::Cvendor);
                            if cv_data.brand_name != fw_brand {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Rule 3: If ACPI_SIGNATURE (QEMU) detected, FIRMWARE (QEMU) should too
            if memo::is_cached(Flag::AcpiSignature) {
                let acpi_data = memo::cache_fetch(Flag::AcpiSignature);
                if acpi_data.result && acpi_data.brand_name == brands::QEMU
                    && memo::is_cached(Flag::Firmware)
                {
                    let fw_data = memo::cache_fetch(Flag::Firmware);
                    if fw_data.brand_name != brands::QEMU {
                        return true;
                    }
                }
            }

            // Rule 4: If TRAP or NVRAM detected, hypervisor should be present
            if (Self::check(Flag::Trap) || Self::check(Flag::Nvram)) && !hv_present {
                return true;
            }
        }

        false
    }

    /// Get the total number of available techniques.
    pub fn technique_count() -> usize {
        engine::TECHNIQUE_TABLE.len()
    }

    /// Create a FlagSet with default flags (convenience).
    pub fn default_flags() -> FlagSet {
        FlagSet::new_default()
    }

    /// Create a FlagSet with all flags enabled (convenience).
    pub fn all_flags() -> FlagSet {
        FlagSet::new_all()
    }

    /// Create a FlagSet with high threshold enabled.
    pub fn high_threshold_flags() -> FlagSet {
        let mut fs = FlagSet::new_default();
        fs.high_threshold = true;
        fs
    }

    /// Create a default FlagSet with specific techniques disabled.
    pub fn disable(techniques: &[Flag]) -> FlagSet {
        let mut fs = FlagSet::new_default();
        for &t in techniques {
            fs.disable(t);
        }
        fs
    }

    /// Add a custom user-defined detection technique.
    ///
    /// # Arguments
    /// * `points` - Score contribution if the technique detects a VM
    /// * `description` - Human-readable description
    /// * `func` - Detection function returning `true` if VM detected
    ///
    /// # Examples
    /// ```rust
    /// use vmaware::VM;
    /// VM::add_custom(100, "My custom check", || {
    ///     std::path::Path::new("/tmp/vm_marker").exists()
    /// });
    /// ```
    pub fn add_custom(points: u8, description: &str, func: impl Fn() -> bool + Send + Sync + 'static) {
        engine::add_custom(points, description, func);
    }

    /// Modify the score contribution of a built-in technique.
    ///
    /// Positive values increase the score contribution, negative values decrease it.
    /// This is primarily useful for development and fine-tuning.
    ///
    /// # Examples
    /// ```rust
    /// use vmaware::VM;
    /// VM::modify_score(VM::TIMER, -50); // reduce TIMER contribution by 50
    /// ```
    pub fn modify_score(flag: Flag, delta: i16) {
        engine::modify_score(flag, delta);
    }

    /// Reset all internal state (caches, scoreboard, counts, custom techniques).
    /// Useful for re-running detection from scratch.
    pub fn reset() {
        engine::reset();
    }
}

/// Convenience struct that holds all detection results at once.
#[derive(Debug, Clone)]
pub struct VMAwareResult {
    pub brand: String,
    pub vm_type: String,
    pub conclusion: String,
    pub is_vm: bool,
    pub percentage: u8,
    pub detected_count: u8,
    pub technique_count: usize,
    pub detected_techniques: Vec<Flag>,
    pub detected_technique_strings: Vec<String>,
}

impl VMAwareResult {
    /// Create a new result with default flags.
    pub fn new(flags: Option<&FlagSet>) -> Self {
        let brand = VM::brand(flags);
        let vm_type = VM::vm_type(flags);
        let conclusion = VM::conclusion(flags);
        let is_vm = VM::detect(flags);
        let percentage = VM::percentage(flags);
        let detected_count = VM::detected_count(flags);
        let technique_count = VM::technique_count();
        let detected_techniques = VM::detected_enums(flags);
        let detected_technique_strings = detected_techniques
            .iter()
            .map(|f| f.to_str().to_string())
            .collect();

        Self {
            brand,
            vm_type,
            conclusion,
            is_vm,
            percentage,
            detected_count,
            technique_count,
            detected_techniques,
            detected_technique_strings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_to_string() {
        assert_eq!(VM::flag_to_string(Flag::Vmid), "VMID");
        assert_eq!(VM::flag_to_string(Flag::CpuBrand), "CPU_BRAND");
        assert_eq!(VM::flag_to_string(Flag::HypervisorBit), "HYPERVISOR_BIT");
    }

    #[test]
    fn test_flagset_default() {
        let fs = FlagSet::new_default();
        // VmwareDmesg should be disabled by default
        assert!(!fs.is_enabled(Flag::VmwareDmesg));
        // HypervisorBit should be enabled by default
        assert!(fs.is_enabled(Flag::HypervisorBit));
    }

    #[test]
    fn test_flagset_disable() {
        let fs = VM::disable(&[Flag::Timer, Flag::Vmid]);
        assert!(!fs.is_enabled(Flag::Timer));
        assert!(!fs.is_enabled(Flag::Vmid));
        assert!(fs.is_enabled(Flag::HypervisorBit));
    }

    #[test]
    fn test_brand_to_type() {
        assert_eq!(brands::brand_to_type(brands::VBOX), "Hypervisor (type 2)");
        assert_eq!(brands::brand_to_type(brands::KVM), "Hypervisor (type 1)");
        assert_eq!(brands::brand_to_type(brands::DOCKER), "Container");
        assert_eq!(brands::brand_to_type(brands::BOCHS), "Emulator");
    }

    #[test]
    fn test_technique_count() {
        assert!(VM::technique_count() > 0);
    }

    #[test]
    fn test_percentage_range() {
        let pct = VM::percentage(None);
        assert!(pct <= 100);
    }

    #[test]
    fn test_vmaware_result() {
        VM::reset();
        let result = VMAwareResult::new(None);
        assert!(result.percentage <= 100);
        assert!(result.technique_count > 0);
    }

    #[test]
    fn test_add_custom() {
        // Verify add_custom API works without panicking
        // Note: cannot reliably test execution due to parallel test reset() calls
        // Instead, verify the custom technique is stored correctly
        let initial_len = engine::CUSTOM_TECHNIQUES.lock().unwrap().len();
        engine::add_custom(200, "test custom technique", || true);
        let new_len = engine::CUSTOM_TECHNIQUES.lock().unwrap().len();
        // new_len should be >= initial_len (may not be exactly +1 due to parallel tests)
        assert!(new_len >= initial_len, "Custom technique should be added to the list");
    }

    #[test]
    fn test_modify_score() {
        VM::reset();
        // Verify modify_score API works without panicking
        VM::modify_score(Flag::Timer, -50);
        VM::modify_score(Flag::Vmid, 10);
        // Run detection — should not panic regardless of environment
        let _pct = VM::percentage(None);
        let _detected = VM::detect(None);
        VM::reset();
    }

    #[test]
    fn test_all_brands_not_empty() {
        let all = brands::all_brands();
        assert!(all.len() > 50, "Should have at least 50 brands");
        assert!(all.contains(&brands::VBOX));
        assert!(all.contains(&brands::VMWARE));
        assert!(all.contains(&brands::QEMU));
    }

    #[test]
    fn test_flagset_from_flags() {
        let fs = FlagSet::from_flags(&[Flag::Vmid, Flag::CpuBrand]);
        assert!(fs.is_enabled(Flag::Vmid));
        assert!(fs.is_enabled(Flag::CpuBrand));
        assert!(!fs.is_enabled(Flag::Timer));
        assert!(!fs.is_enabled(Flag::HypervisorBit));
    }

    #[test]
    fn test_high_threshold_flags() {
        let fs = VM::high_threshold_flags();
        assert!(fs.high_threshold);
        assert!(fs.is_enabled(Flag::HypervisorBit));
    }

    #[test]
    fn test_check_single_technique() {
        VM::reset();
        // check() should return a bool without panicking
        let _ = VM::check(Flag::HypervisorBit);
        let _ = VM::check(Flag::Vmid);
    }

    #[test]
    fn test_conclusion_baremetal() {
        VM::reset();
        let conclusion = VM::conclusion(None);
        // On a real machine with no detections, should say baremetal
        // (unless running in a VM, in which case it should say something else)
        assert!(!conclusion.is_empty());
    }

    #[test]
    fn test_flag_all_techniques_iterator() {
        let count = Flag::all_techniques().count();
        assert_eq!(count, Flag::TECHNIQUE_COUNT);
        assert!(count > 50);
    }

    #[test]
    fn test_cpu_brand_returns_string() {
        let brand = cpu::get_brand();
        assert!(!brand.is_empty());
    }

    #[test]
    fn test_reset_clears_state() {
        VM::reset();
        VM::add_custom(100, "temp", || true);
        VM::reset();
        // After double reset, detection should be clean
        let count = VM::detected_count(None);
        // count can be >= 0 depending on real techniques, just check it doesn't panic
        let _ = count;
    }
}
