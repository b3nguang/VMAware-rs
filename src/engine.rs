//! Core scoring engine module.
//! Manages the technique table, brand scoreboard, and orchestrates running all detections.

use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::brands;
use crate::flags::{Flag, FlagSet};
use crate::memo;
use crate::techniques;

/// A technique entry: certainty points + detection function.
pub struct Technique {
    pub points: u8,
    pub run: fn() -> TechniqueResult,
}

/// Result returned by a technique function.
#[derive(Debug, Clone)]
pub struct TechniqueResult {
    pub detected: bool,
    /// Brand(s) detected — if any.
    pub brand: Option<&'static str>,
    /// Optional secondary brand.
    pub extra_brand: Option<&'static str>,
    /// Override score (0 = use default from table).
    pub score_override: u8,
}

impl TechniqueResult {
    pub fn not_detected() -> Self {
        Self {
            detected: false,
            brand: None,
            extra_brand: None,
            score_override: 0,
        }
    }

    pub fn detected() -> Self {
        Self {
            detected: true,
            brand: None,
            extra_brand: None,
            score_override: 0,
        }
    }

    pub fn detected_with_brand(brand: &'static str) -> Self {
        Self {
            detected: true,
            brand: Some(brand),
            extra_brand: None,
            score_override: 0,
        }
    }

    pub fn detected_with_brands(brand: &'static str, extra: &'static str) -> Self {
        Self {
            detected: true,
            brand: Some(brand),
            extra_brand: Some(extra),
            score_override: 0,
        }
    }
}

/// Brand scoreboard entry.
#[derive(Debug, Clone)]
pub struct BrandScore {
    pub name: &'static str,
    pub score: i32,
}

/// Global brand scoreboard.
pub static BRAND_SCOREBOARD: Lazy<Mutex<Vec<BrandScore>>> = Lazy::new(|| {
    let all = brands::all_brands();
    let scoreboard: Vec<BrandScore> = all
        .into_iter()
        .map(|name| BrandScore { name, score: 0 })
        .collect();
    Mutex::new(scoreboard)
});

/// Global detected count.
pub static DETECTED_COUNT: Lazy<Mutex<u8>> = Lazy::new(|| Mutex::new(0));

/// Custom user-defined technique.
pub struct CustomTechnique {
    pub points: u8,
    pub run: Box<dyn Fn() -> bool + Send + Sync>,
    pub description: String,
}

/// Global custom technique list.
pub static CUSTOM_TECHNIQUES: Lazy<Mutex<Vec<CustomTechnique>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Score modification table: maps Flag -> delta to apply.
pub static SCORE_MODIFICATIONS: Lazy<Mutex<Vec<(Flag, i16)>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Default detection threshold score.
pub const DEFAULT_THRESHOLD: u16 = 150;
/// High threshold score.
pub const HIGH_THRESHOLD_SCORE: u16 = 300;

/// Add a score to the brand scoreboard.
pub fn add_brand_score(brand: &'static str) {
    let mut sb = BRAND_SCOREBOARD.lock().unwrap();
    for entry in sb.iter_mut() {
        if std::ptr::eq(entry.name, brand) || entry.name == brand {
            entry.score += 1;
            return;
        }
    }
}

/// Build the technique table — maps Flag -> (points, function).
/// Only includes techniques supported on the current platform.
#[allow(clippy::vec_init_then_push)]
pub fn build_technique_table() -> Vec<(Flag, Technique)> {
    let mut table = Vec::new();

    // ===== Cross-platform techniques =====
    table.push((Flag::Vmid, Technique { points: 100, run: techniques::cross_platform::vmid }));
    table.push((Flag::CpuBrand, Technique { points: 95, run: techniques::cross_platform::cpu_brand }));
    table.push((Flag::HypervisorBit, Technique { points: 100, run: techniques::cross_platform::hypervisor_bit }));
    table.push((Flag::HypervisorStr, Technique { points: 100, run: techniques::cross_platform::hypervisor_str }));
    table.push((Flag::Timer, Technique { points: 150, run: techniques::cross_platform::timer }));
    table.push((Flag::ThreadMismatch, Technique { points: 50, run: techniques::cross_platform::thread_mismatch }));
    table.push((Flag::CpuidSignature, Technique { points: 95, run: techniques::cross_platform::cpuid_signature }));
    table.push((Flag::BochsCpu, Technique { points: 100, run: techniques::cross_platform::bochs_cpu }));
    table.push((Flag::KgtSignature, Technique { points: 80, run: techniques::cross_platform::kgt_signature }));

    // ===== Windows techniques =====
    #[cfg(target_os = "windows")]
    {
        table.push((Flag::Dll, Technique { points: 50, run: techniques::windows::dll }));
        table.push((Flag::Wine, Technique { points: 100, run: techniques::windows::wine }));
        table.push((Flag::Mutex, Technique { points: 100, run: techniques::windows::mutex }));
        table.push((Flag::Drivers, Technique { points: 100, run: techniques::windows::drivers }));
        table.push((Flag::DiskSerial, Technique { points: 100, run: techniques::windows::disk_serial }));
        table.push((Flag::DeviceHandles, Technique { points: 100, run: techniques::windows::device_handles }));
        table.push((Flag::Display, Technique { points: 25, run: techniques::windows::display }));
        table.push((Flag::Audio, Technique { points: 25, run: techniques::windows::audio }));
        table.push((Flag::PowerCapabilities, Technique { points: 45, run: techniques::windows::power_capabilities }));
        table.push((Flag::GpuCapabilities, Technique { points: 45, run: techniques::windows::gpu_capabilities }));
        table.push((Flag::VirtualProcessors, Technique { points: 100, run: techniques::windows::virtual_processors }));
        table.push((Flag::HypervisorQuery, Technique { points: 100, run: techniques::windows::hypervisor_query }));
        table.push((Flag::VirtualRegistry, Technique { points: 90, run: techniques::windows::virtual_registry }));
        table.push((Flag::Gamarue, Technique { points: 10, run: techniques::windows::gamarue }));
        table.push((Flag::VmwareStr, Technique { points: 35, run: techniques::windows::vmware_str }));
        table.push((Flag::VpcInvalid, Technique { points: 75, run: techniques::windows::vpc_invalid }));
        table.push((Flag::DeviceString, Technique { points: 25, run: techniques::windows::device_string }));
        table.push((Flag::CuckooDir, Technique { points: 30, run: techniques::windows::cuckoo_dir }));
        table.push((Flag::CuckooPipe, Technique { points: 30, run: techniques::windows::cuckoo_pipe }));
        table.push((Flag::VmwareBackdoor, Technique { points: 100, run: techniques::windows::vmware_backdoor }));
        table.push((Flag::Ivshmem, Technique { points: 100, run: techniques::windows::ivshmem }));
        table.push((Flag::AcpiSignature, Technique { points: 100, run: techniques::windows::acpi_signature }));
        table.push((Flag::Trap, Technique { points: 100, run: techniques::windows::trap }));
        table.push((Flag::Ud, Technique { points: 100, run: techniques::windows::ud }));
        table.push((Flag::Blockstep, Technique { points: 100, run: techniques::windows::blockstep }));
        table.push((Flag::Dbvm, Technique { points: 150, run: techniques::windows::dbvm }));
        table.push((Flag::BootLogo, Technique { points: 100, run: techniques::windows::boot_logo }));
        table.push((Flag::KernelObjects, Technique { points: 100, run: techniques::windows::kernel_objects }));
        table.push((Flag::Nvram, Technique { points: 100, run: techniques::windows::nvram }));
        table.push((Flag::SmbiosIntegrity, Technique { points: 50, run: techniques::windows::smbios_integrity }));
        table.push((Flag::Edid, Technique { points: 100, run: techniques::windows::edid }));
        table.push((Flag::CpuHeuristic, Technique { points: 90, run: techniques::windows::cpu_heuristic }));
        table.push((Flag::Clock, Technique { points: 90, run: techniques::windows::clock }));
    }

    // ===== Linux + Windows techniques =====
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        table.push((Flag::Firmware, Technique { points: 100, run: techniques::cross_platform::firmware }));
        table.push((Flag::PciDevices, Technique { points: 95, run: techniques::cross_platform::pci_devices }));
        table.push((Flag::SystemRegisters, Technique { points: 50, run: techniques::cross_platform::system_registers }));
        table.push((Flag::Azure, Technique { points: 30, run: techniques::cross_platform::azure }));
    }

    // ===== Linux techniques =====
    #[cfg(target_os = "linux")]
    {
        table.push((Flag::Cvendor, Technique { points: 65, run: techniques::linux::chassis_vendor }));
        table.push((Flag::Ctype, Technique { points: 20, run: techniques::linux::chassis_type }));
        table.push((Flag::Dockerenv, Technique { points: 30, run: techniques::linux::dockerenv }));
        table.push((Flag::Dmidecode, Technique { points: 55, run: techniques::linux::dmidecode }));
        table.push((Flag::Dmesg, Technique { points: 55, run: techniques::linux::dmesg }));
        table.push((Flag::Hwmon, Technique { points: 35, run: techniques::linux::hwmon }));
        table.push((Flag::Systemd, Technique { points: 35, run: techniques::linux::systemd_virt }));
        table.push((Flag::LinuxUserHost, Technique { points: 10, run: techniques::linux::linux_user_host }));
        table.push((Flag::VmwareIomem, Technique { points: 65, run: techniques::linux::vmware_iomem }));
        table.push((Flag::VmwareIoports, Technique { points: 70, run: techniques::linux::vmware_ioports }));
        table.push((Flag::VmwareScsi, Technique { points: 40, run: techniques::linux::vmware_scsi }));
        table.push((Flag::VmwareDmesg, Technique { points: 65, run: techniques::linux::vmware_dmesg }));
        table.push((Flag::QemuVirtualDmi, Technique { points: 40, run: techniques::linux::qemu_virtual_dmi }));
        table.push((Flag::QemuUsb, Technique { points: 20, run: techniques::linux::qemu_usb }));
        table.push((Flag::HypervisorDir, Technique { points: 20, run: techniques::linux::hypervisor_dir }));
        table.push((Flag::UmlCpu, Technique { points: 80, run: techniques::linux::uml_cpu }));
        table.push((Flag::Kmsg, Technique { points: 5, run: techniques::linux::kmsg }));
        table.push((Flag::VboxModule, Technique { points: 15, run: techniques::linux::vbox_module }));
        table.push((Flag::SysinfoProc, Technique { points: 15, run: techniques::linux::sysinfo_proc }));
        table.push((Flag::DmiScan, Technique { points: 50, run: techniques::linux::dmi_scan }));
        table.push((Flag::SmbiosVmBit, Technique { points: 50, run: techniques::linux::smbios_vm_bit }));
        table.push((Flag::PodmanFile, Technique { points: 5, run: techniques::linux::podman_file }));
        table.push((Flag::WslProc, Technique { points: 30, run: techniques::linux::wsl_proc }));
        table.push((Flag::QemuFwCfg, Technique { points: 70, run: techniques::linux::qemu_fw_cfg }));
        table.push((Flag::FileAccessHistory, Technique { points: 15, run: techniques::linux::file_access_history }));
        table.push((Flag::Mac, Technique { points: 20, run: techniques::linux::mac_address_check }));
        table.push((Flag::NsjailPid, Technique { points: 75, run: techniques::linux::nsjail_pid }));
        table.push((Flag::BluestacksFolders, Technique { points: 5, run: techniques::linux::bluestacks_folders }));
        table.push((Flag::AmdSev, Technique { points: 50, run: techniques::linux::amd_sev }));
        table.push((Flag::Temperature, Technique { points: 80, run: techniques::linux::temperature }));
        table.push((Flag::Processes, Technique { points: 40, run: techniques::linux::processes }));
    }

    // ===== Linux + macOS techniques =====
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        table.push((Flag::ThreadCount, Technique { points: 35, run: techniques::cross_platform::thread_count }));
    }

    // ===== macOS techniques =====
    #[cfg(target_os = "macos")]
    {
        table.push((Flag::MacMemsize, Technique { points: 15, run: techniques::macos::hw_memsize }));
        table.push((Flag::MacIokit, Technique { points: 100, run: techniques::macos::io_kit }));
        table.push((Flag::MacSip, Technique { points: 100, run: techniques::macos::mac_sip }));
        table.push((Flag::IoregGrep, Technique { points: 100, run: techniques::macos::ioreg_grep }));
        table.push((Flag::Hwmodel, Technique { points: 100, run: techniques::macos::hwmodel }));
        table.push((Flag::MacSys, Technique { points: 100, run: techniques::macos::mac_sys }));
    }

    table
}

/// Global technique table (built once).
pub static TECHNIQUE_TABLE: Lazy<Vec<(Flag, Technique)>> = Lazy::new(build_technique_table);

/// Run all enabled techniques according to the flagset.
/// Returns accumulated score.
/// If `shortcut` is true, stops early when threshold is reached.
pub fn run_all(flags: &FlagSet, shortcut: bool) -> u16 {
    let mut points: u16 = 0;

    let threshold = if flags.high_threshold {
        HIGH_THRESHOLD_SCORE
    } else {
        DEFAULT_THRESHOLD
    };

    let table = &*TECHNIQUE_TABLE;

    for (flag, technique) in table.iter() {
        // Skip if not enabled in flagset
        if !flags.is_enabled(*flag) {
            continue;
        }

        // Skip unsupported platforms
        if !flag.is_supported_on_current_platform() {
            continue;
        }

        // Check cache first
        if memo::is_cached(*flag) {
            let data = memo::cache_fetch(*flag);
            if data.result {
                points += data.points as u16;
            }
            continue;
        }

        // Run the technique
        let result = (technique.run)();

        if result.detected {
            let pts = if result.score_override > 0 {
                result.score_override
            } else {
                technique.points
            };
            points += pts as u16;

            // Update detected count
            {
                let mut count = DETECTED_COUNT.lock().unwrap();
                *count += 1;
            }

            // Update brand scoreboard
            if let Some(brand) = result.brand {
                add_brand_score(brand);
            }
            if let Some(extra) = result.extra_brand {
                add_brand_score(extra);
            }

            let brand_name = result.brand.unwrap_or(brands::NULL_BRAND);
            memo::cache_store(*flag, true, pts, brand_name);
        } else {
            memo::cache_store(*flag, false, 0, brands::NULL_BRAND);
        }

        // Shortcut if threshold is met
        if shortcut && points >= threshold {
            return points;
        }
    }

    // Run custom techniques
    {
        let customs = CUSTOM_TECHNIQUES.lock().unwrap();
        for custom in customs.iter() {
            if (custom.run)() {
                let pts = custom.points;
                points += pts as u16;

                let mut count = DETECTED_COUNT.lock().unwrap();
                *count += 1;
            }

            if shortcut && points >= threshold {
                return points;
            }
        }
    }

    // Apply score modifications
    {
        let mods = SCORE_MODIFICATIONS.lock().unwrap();
        for &(flag, delta) in mods.iter() {
            if memo::is_cached(flag) {
                let data = memo::cache_fetch(flag);
                if data.result {
                    if delta < 0 {
                        let abs = (-delta) as u16;
                        points = points.saturating_sub(abs);
                    } else {
                        points += delta as u16;
                    }
                }
            }
        }
    }

    points
}

/// Add a custom user-defined technique.
pub fn add_custom(points: u8, description: &str, func: impl Fn() -> bool + Send + Sync + 'static) {
    let mut customs = CUSTOM_TECHNIQUES.lock().unwrap();
    customs.push(CustomTechnique {
        points,
        run: Box::new(func),
        description: description.to_string(),
    });
}

/// Modify the score contribution of a built-in technique by a delta.
/// Positive delta increases the score, negative decreases.
pub fn modify_score(flag: Flag, delta: i16) {
    let mut mods = SCORE_MODIFICATIONS.lock().unwrap();
    // Update existing or add new
    for entry in mods.iter_mut() {
        if entry.0 == flag {
            entry.1 = delta;
            return;
        }
    }
    mods.push((flag, delta));
}

/// Reset the core state (scoreboard, detected count). Useful for fresh runs.
pub fn reset() {
    {
        let mut sb = BRAND_SCOREBOARD.lock().unwrap();
        for entry in sb.iter_mut() {
            entry.score = 0;
        }
    }
    *DETECTED_COUNT.lock().unwrap() = 0;
    CUSTOM_TECHNIQUES.lock().unwrap().clear();
    SCORE_MODIFICATIONS.lock().unwrap().clear();
    memo::reset_all();
}
