/// macOS-specific VM detection techniques.

use crate::engine::TechniqueResult;

#[cfg(target_os = "macos")]
use crate::brands;
#[cfg(target_os = "macos")]
use crate::util;

/// Check if memory is too low for macOS system.
pub fn hw_memsize() -> TechniqueResult {
    #[cfg(target_os = "macos")]
    {
        if let Some(memsize_str) = util::macos::sysctl_string("hw.memsize") {
            if let Ok(memsize) = memsize_str.parse::<u64>() {
                // Less than 2GB is suspicious for macOS
                if memsize < 2 * 1024 * 1024 * 1024 {
                    return TechniqueResult::detected();
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check macOS IO kit registry for VM-specific strings.
pub fn io_kit() -> TechniqueResult {
    #[cfg(target_os = "macos")]
    {
        if let Some(output) = util::macos::ioreg(&["-l"]) {
            let lower = output.to_lowercase();
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("virtualbox") || lower.contains("vbox") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if lower.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for the status of System Integrity Protection and hv_mm_present.
pub fn mac_sip() -> TechniqueResult {
    #[cfg(target_os = "macos")]
    {
        // Check if hv_vmm_present indicates a hypervisor
        if let Some(val) = util::macos::sysctl_string("kern.hv_vmm_present") {
            if val.trim() == "1" {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM-strings in ioreg commands for macOS.
pub fn ioreg_grep() -> TechniqueResult {
    #[cfg(target_os = "macos")]
    {
        if let Some(output) = util::macos::ioreg(&["-rd1", "-c", "IOPlatformExpertDevice"]) {
            let lower = output.to_lowercase();
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("virtualbox") || lower.contains("vbox") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if lower.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("apple virtualization") || lower.contains("apple vz") {
                return TechniqueResult::detected_with_brand(brands::APPLE_VZ);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if the sysctl for hwmodel does not contain "Mac".
pub fn hwmodel() -> TechniqueResult {
    #[cfg(target_os = "macos")]
    {
        if let Some(model) = util::macos::sysctl_string("hw.model") {
            if !model.contains("Mac") && !model.contains("mac") {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM-strings in system profiler for macOS.
pub fn mac_sys() -> TechniqueResult {
    #[cfg(target_os = "macos")]
    {
        if let Some(output) = util::macos::system_profiler("SPHardwareDataType") {
            let lower = output.to_lowercase();
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("virtualbox") || lower.contains("vbox") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if lower.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("virtual machine") { return TechniqueResult::detected(); }
        }
    }
    TechniqueResult::not_detected()
}
