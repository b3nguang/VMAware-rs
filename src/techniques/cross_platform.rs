//! Cross-platform VM detection techniques.
//! These work on Windows, Linux, and macOS (where applicable).

use crate::engine::TechniqueResult;
use crate::cpu;
use crate::brands;
use crate::util;

/// Check CPUID output of manufacturer ID for known VMs/hypervisors
/// at leaf 0 and 0x40000000-0x40000100.
pub fn vmid() -> TechniqueResult {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        return TechniqueResult::not_detected();
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        // Check standard hypervisor leaves
        let leaves_to_check: Vec<u32> = {
            let mut v = vec![0u32];
            for leaf in (0x4000_0000u32..=0x4000_0100).step_by(0x100) {
                v.push(leaf);
            }
            v
        };

        for &leaf_id in &leaves_to_check {
            if leaf_id != 0 && !cpu::is_leaf_supported(leaf_id) {
                continue;
            }

            let brand_str = cpu::cpu_manufacturer(leaf_id);
            if brand_str.is_empty() {
                continue;
            }

            // Check known VM brand strings
            if brand_str == "Microsoft Hv" {
                return TechniqueResult::detected_with_brands(brands::HYPERV, brands::VPC);
            }
            if brand_str.contains("KVM") {
                return TechniqueResult::detected_with_brand(brands::KVM);
            }

            let brand_map: &[(&str, &str)] = &[
                ("VMwareVMware", brands::VMWARE),
                ("VBoxVBoxVBox", brands::VBOX),
                ("TCGTCGTCGTCG", brands::QEMU),
                ("XenVMMXenVMM", brands::XEN),
                ("Linux KVM Hv", brands::KVM_HYPERV),
                (" prl hyperv ", brands::PARALLELS),
                (" lrpepyh  vr", brands::PARALLELS),
                ("bhyve bhyve ", brands::BHYVE),
                ("BHyVE BHyVE ", brands::BHYVE),
                ("ACRNACRNACRN", brands::ACRN),
                (" QNXQVMBSQG ", brands::QNX),
                ("___ NVMM ___", brands::NVMM),
                ("OpenBSDVMM58", brands::BSD_VMM),
                ("HAXMHAXMHAXM", brands::INTEL_HAXM),
                ("UnisysSpar64", brands::UNISYS),
                ("SRESRESRESRE", brands::LMHS),
                ("EVMMEVMMEVMM", brands::INTEL_KGT),
                ("LKVMLKVMLKVM", brands::LKVM),
                ("Neko Project", brands::NEKO_PROJECT),
                ("NoirVisor ZT", brands::NOIRVISOR),
            ];

            for &(pattern, brand) in brand_map {
                if brand_str == pattern {
                    return TechniqueResult::detected_with_brand(brand);
                }
            }

            if brand_str.contains("QXNQSBMV") {
                return TechniqueResult::detected_with_brand(brands::QNX);
            }
            if brand_str.contains("Apple VZ") {
                return TechniqueResult::detected_with_brand(brands::APPLE_VZ);
            }
        }

        TechniqueResult::not_detected()
    }
}

/// Check if CPU brand model contains any VM-specific string snippets.
pub fn cpu_brand() -> TechniqueResult {
    let brand = cpu::get_brand();
    if brand == "Unknown" || brand.is_empty() {
        return TechniqueResult::not_detected();
    }

    let lower = brand.to_lowercase();

    let vm_strings: &[(&str, &str)] = &[
        ("qemu", brands::QEMU),
        ("virtual", brands::NULL_BRAND),
        ("vmware", brands::VMWARE),
        ("virtualbox", brands::VBOX),
        ("vbox", brands::VBOX),
        ("kvm", brands::KVM),
        ("xen", brands::XEN),
        ("bochs", brands::BOCHS),
        ("parallels", brands::PARALLELS),
        ("bhyve", brands::BHYVE),
        ("hyperv", brands::HYPERV),
    ];

    for &(pattern, brand) in vm_strings {
        if lower.contains(pattern) {
            if brand == brands::NULL_BRAND {
                return TechniqueResult::detected();
            }
            return TechniqueResult::detected_with_brand(brand);
        }
    }

    TechniqueResult::not_detected()
}

/// Check if hypervisor feature bit in CPUID ECX bit 31 is enabled.
/// Always false for physical CPUs.
pub fn hypervisor_bit() -> TechniqueResult {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let r = cpu::cpuid(1, 0);
        let hv_bit = (r.ecx >> 31) & 1;
        if hv_bit == 1 {
            return TechniqueResult::detected();
        }
    }
    TechniqueResult::not_detected()
}

/// Check for hypervisor brand string length.
/// On physical machines the string is typically very short or empty.
pub fn hypervisor_str() -> TechniqueResult {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if !cpu::is_leaf_supported(cpu::leaf::HYPERVISOR) {
            return TechniqueResult::not_detected();
        }

        let brand = cpu::cpu_manufacturer(cpu::leaf::HYPERVISOR);
        if brand.len() > 2 && !brand.trim().is_empty() {
            return TechniqueResult::detected();
        }
    }
    TechniqueResult::not_detected()
}

/// Check for timing anomalies (RDTSC-based).
pub fn timer() -> TechniqueResult {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        // Measure time for CPUID calls — VMs typically take much longer
        let iterations = 10u32;
        let mut total: u64 = 0;

        for _ in 0..iterations {
            let start: u64;
            let end: u64;

            #[cfg(target_arch = "x86_64")]
            unsafe {
                start = std::arch::x86_64::_rdtsc();
                // Execute a CPUID (serializing instruction)
                let _ = std::arch::x86_64::__cpuid(0);
                end = std::arch::x86_64::_rdtsc();
            }

            #[cfg(target_arch = "x86")]
            unsafe {
                start = std::arch::x86::_rdtsc();
                let _ = std::arch::x86::__cpuid(0);
                end = std::arch::x86::_rdtsc();
            }

            total += end.wrapping_sub(start);
        }

        let avg = total / iterations as u64;
        // Threshold: bare metal typically < 500 cycles, VMs often > 1000
        if avg > 1000 {
            return TechniqueResult::detected();
        }
    }
    TechniqueResult::not_detected()
}

/// Check if thread count is suspiciously low (1-2 threads).
pub fn thread_count() -> TechniqueResult {
    let count = util::thread_count();
    if count <= 2 {
        return TechniqueResult::detected();
    }
    TechniqueResult::not_detected()
}

/// Check if thread count mismatches the expected count for the CPU model.
pub fn thread_mismatch() -> TechniqueResult {
    let brand = cpu::get_brand();
    let count = util::thread_count();

    if brand == "Unknown" || brand.is_empty() {
        return TechniqueResult::not_detected();
    }

    // Extract expected thread count from known CPU model patterns
    // Ryzen 9 -> typically 16-32 threads, if only 2-4 that's suspicious
    let lower = brand.to_lowercase();

    let expected_min = if lower.contains("ryzen 9") || lower.contains("i9-") || lower.contains("xeon") {
        8
    } else if lower.contains("ryzen 7") || lower.contains("i7-") {
        6
    } else if lower.contains("ryzen 5") || lower.contains("i5-") {
        4
    } else {
        return TechniqueResult::not_detected();
    };

    if count < expected_min {
        return TechniqueResult::detected();
    }

    TechniqueResult::not_detected()
}

/// Check for signatures in CPUID leaf 0x40000001.
pub fn cpuid_signature() -> TechniqueResult {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if !cpu::is_leaf_supported(0x4000_0001) {
            return TechniqueResult::not_detected();
        }

        let r = cpu::cpuid(0x4000_0001, 0);
        // Non-zero EAX on this leaf typically indicates a hypervisor
        if r.eax != 0 {
            return TechniqueResult::detected();
        }
    }
    TechniqueResult::not_detected()
}

/// Check for various Bochs-related emulation oversights through CPU checks.
pub fn bochs_cpu() -> TechniqueResult {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if !cpu::is_leaf_supported(cpu::leaf::PROC_EXT) {
            return TechniqueResult::not_detected();
        }

        let r = cpu::cpuid(cpu::leaf::PROC_EXT, 0);

        // Bochs has known quirks: AMD Easter Egg leaf returns specific values
        if cpu::is_leaf_supported(cpu::leaf::AMD_EASTER_EGG) {
            let easter = cpu::cpuid(cpu::leaf::AMD_EASTER_EGG, 0);
            // Check for "IT'S HAMMER TIME" string (Bochs signature)
            if easter.ecx == 0x4d414821 {
                return TechniqueResult::detected_with_brand(brands::BOCHS);
            }
        }

        // Another Bochs quirk: extended CPUID features inconsistency
        // If AMD features are reported on an Intel CPU, it's likely Bochs
        if cpu::is_intel() {
            let amd_features = r.ecx & (1 << 6); // SSE4a (AMD-only)
            if amd_features != 0 {
                return TechniqueResult::detected_with_brand(brands::BOCHS);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for Intel KGT (Trusty branch) hypervisor signature in CPUID.
pub fn kgt_signature() -> TechniqueResult {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if !cpu::is_leaf_supported(cpu::leaf::HYPERVISOR) {
            return TechniqueResult::not_detected();
        }

        let brand = cpu::cpu_manufacturer(cpu::leaf::HYPERVISOR);
        if brand == "EVMMEVMMEVMM" {
            return TechniqueResult::detected_with_brand(brands::INTEL_KGT);
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM signatures on firmware tables (Linux + Windows).
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn firmware() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        // Check ACPI tables
        let acpi_paths = [
            "/sys/firmware/acpi/tables/DSDT",
            "/sys/firmware/acpi/tables/SLIC",
            "/sys/firmware/acpi/tables/MSDM",
        ];

        for path in &acpi_paths {
            if let Ok(data) = std::fs::read(path) {
                let s = String::from_utf8_lossy(&data).to_lowercase();
                if s.contains("vmware") {
                    return TechniqueResult::detected_with_brand(brands::VMWARE);
                }
                if s.contains("vbox") || s.contains("virtualbox") {
                    return TechniqueResult::detected_with_brand(brands::VBOX);
                }
                if s.contains("qemu") {
                    return TechniqueResult::detected_with_brand(brands::QEMU);
                }
                if s.contains("hyper-v") || s.contains("microsoft") {
                    return TechniqueResult::detected_with_brand(brands::HYPERV);
                }
            }
        }

        // Check DMI/SMBIOS
        if let Some(vendor) = util::linux::read_dmi_field("sys_vendor") {
            let v = vendor.to_lowercase();
            if v.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if v.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if v.contains("virtualbox") || v.contains("innotek") { return TechniqueResult::detected_with_brand(brands::VBOX); }
            if v.contains("microsoft") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            if v.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
            if v.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Check firmware tables via registry
        if let Some(bios_vendor) = util::win::read_registry_string(
            "HKLM",
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "SystemManufacturer",
        ) {
            let v = bios_vendor.to_lowercase();
            if v.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if v.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if v.contains("virtualbox") || v.contains("innotek") { return TechniqueResult::detected_with_brand(brands::VBOX); }
            if v.contains("microsoft") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            if v.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
            if v.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
        }
    }

    TechniqueResult::not_detected()
}

/// Check for PCI vendor and device IDs that are VM-specific.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn pci_devices() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        // Known VM PCI vendor IDs
        let vm_pci_vendors: &[(&str, &str)] = &[
            ("15ad", brands::VMWARE),   // VMware
            ("80ee", brands::VBOX),     // VirtualBox
            ("1af4", brands::QEMU),     // Red Hat / virtio (QEMU/KVM)
            ("1414", brands::HYPERV),   // Microsoft Hyper-V
            ("5853", brands::XEN),      // Xen / Citrix
            ("1ab8", brands::PARALLELS),// Parallels
        ];

        if let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") {
            for entry in entries.flatten() {
                let vendor_path = format!("{}/vendor", entry.path().display());
                if let Ok(vendor) = std::fs::read_to_string(&vendor_path) {
                    let vendor = vendor.trim().trim_start_matches("0x").to_lowercase();
                    for &(vid, brand) in vm_pci_vendors {
                        if vendor == vid {
                            return TechniqueResult::detected_with_brand(brand);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Check for VM-specific PCI devices via registry
        let subkeys = util::win::enum_registry_subkeys(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Enum\PCI",
        );
        for key in &subkeys {
            let lower = key.to_lowercase();
            if lower.contains("ven_15ad") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("ven_80ee") { return TechniqueResult::detected_with_brand(brands::VBOX); }
            if lower.contains("ven_1af4") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("ven_1414") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            if lower.contains("ven_5853") { return TechniqueResult::detected_with_brand(brands::XEN); }
        }
    }

    TechniqueResult::not_detected()
}

/// Check system registers / task segment for anomalies.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn system_registers() -> TechniqueResult {
    // This is a simplified version — the full C++ version uses inline assembly
    // which is not portable in safe Rust. We use CPUID-based heuristics instead.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        // Check if CPUID indicates a hypervisor is present
        let r = cpu::cpuid(1, 0);
        let hv_present = (r.ecx >> 31) & 1 == 1;

        if hv_present {
            // Double-check with timing — STR instruction behaves differently in VMs
            // We approximate this with CPUID timing
            let start: u64;
            let end: u64;

            #[cfg(target_arch = "x86_64")]
            unsafe {
                start = std::arch::x86_64::_rdtsc();
                let _ = std::arch::x86_64::__cpuid(0x4000_0000);
                end = std::arch::x86_64::_rdtsc();
            }
            #[cfg(target_arch = "x86")]
            unsafe {
                start = std::arch::x86::_rdtsc();
                let _ = std::arch::x86::__cpuid(0x4000_0000);
                end = std::arch::x86::_rdtsc();
            }

            let elapsed = end.wrapping_sub(start);
            if elapsed > 500 {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for Azure hostname patterns.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn azure() -> TechniqueResult {
    if let Some(hostname) = util::get_hostname() {
        // Azure VM hostnames often follow patterns like "AZ-xxxxx" or contain "azure"
        let lower = hostname.to_lowercase();
        if lower.contains("azure") || lower.starts_with("az-") {
            return TechniqueResult::detected_with_brand(brands::AZURE_HYPERV);
        }
    }
    TechniqueResult::not_detected()
}
