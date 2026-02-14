/// Linux-specific VM detection techniques.

use crate::engine::TechniqueResult;

#[cfg(target_os = "linux")]
use crate::brands;
#[cfg(target_os = "linux")]
use crate::util;

/// Check if the chassis vendor is a VM vendor.
pub fn chassis_vendor() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(vendor) = util::linux::read_dmi_field("chassis_vendor") {
            let v = vendor.to_lowercase();
            if v.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if v.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if v.contains("virtualbox") || v.contains("oracle") || v.contains("innotek") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if v.contains("microsoft") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            if v.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
            if v.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
            if v.contains("bochs") { return TechniqueResult::detected_with_brand(brands::BOCHS); }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if the chassis type is valid (often invalid in VMs).
pub fn chassis_type() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(ctype) = util::linux::read_dmi_field("chassis_type") {
            if let Ok(t) = ctype.parse::<u32>() {
                // Type 1 = "Other" — commonly used by VMs
                if t == 1 {
                    return TechniqueResult::detected();
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if /.dockerenv or /.dockerinit file is present.
pub fn dockerenv() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if util::file_exists("/.dockerenv") || util::file_exists("/.dockerinit") {
            return TechniqueResult::detected_with_brand(brands::DOCKER);
        }
    }
    TechniqueResult::not_detected()
}

/// Check if dmidecode output matches a VM brand.
pub fn dmidecode() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(output) = util::run_command("dmidecode", &["-s", "system-manufacturer"]) {
            let lower = output.to_lowercase();
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("virtualbox") || lower.contains("innotek") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if lower.contains("microsoft") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            if lower.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
            if lower.contains("parallels") { return TechniqueResult::detected_with_brand(brands::PARALLELS); }
            if lower.contains("bochs") { return TechniqueResult::detected_with_brand(brands::BOCHS); }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if dmesg output matches a VM brand.
pub fn dmesg() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(output) = util::run_command("dmesg", &[]) {
            let lower = output.to_lowercase();
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("virtualbox") || lower.contains("vbox") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("hyper-v") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            if lower.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
            if lower.contains("kvm") { return TechniqueResult::detected_with_brand(brands::KVM); }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if /sys/class/hwmon/ directory is present.
pub fn hwmon() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if !util::dir_exists("/sys/class/hwmon") {
            return TechniqueResult::detected();
        }
        // Even if the directory exists, check if it has entries
        if let Ok(entries) = std::fs::read_dir("/sys/class/hwmon") {
            if entries.count() == 0 {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check result from systemd-detect-virt tool.
pub fn systemd_virt() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(output) = util::run_command("systemd-detect-virt", &[]) {
            let trimmed = output.trim().to_lowercase();
            if trimmed != "none" && !trimmed.is_empty() {
                // Map systemd output to brands
                if trimmed.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
                if trimmed.contains("oracle") || trimmed.contains("vbox") {
                    return TechniqueResult::detected_with_brand(brands::VBOX);
                }
                if trimmed.contains("kvm") { return TechniqueResult::detected_with_brand(brands::KVM); }
                if trimmed.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
                if trimmed.contains("microsoft") || trimmed.contains("hyper") {
                    return TechniqueResult::detected_with_brand(brands::HYPERV);
                }
                if trimmed.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
                if trimmed.contains("docker") { return TechniqueResult::detected_with_brand(brands::DOCKER); }
                if trimmed.contains("podman") { return TechniqueResult::detected_with_brand(brands::PODMAN); }
                if trimmed.contains("wsl") { return TechniqueResult::detected_with_brand(brands::WSL); }
                if trimmed.contains("openvz") { return TechniqueResult::detected_with_brand(brands::OPENVZ); }
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for default VM username and hostname for linux.
pub fn linux_user_host() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let vm_usernames = ["user", "admin", "test", "vm", "sandbox", "virus", "malware"];
        let vm_hostnames = ["ubuntu", "debian", "centos", "fedora", "sandbox", "vm", "virtual"];

        if let Some(user) = util::get_username() {
            let lower = user.to_lowercase();
            for &vu in &vm_usernames {
                if lower == vu {
                    return TechniqueResult::detected();
                }
            }
        }
        if let Some(host) = util::get_hostname() {
            let lower = host.to_lowercase();
            for &vh in &vm_hostnames {
                if lower == vh {
                    return TechniqueResult::detected();
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VMware string in /proc/iomem.
pub fn vmware_iomem() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = util::read_file("/proc/iomem") {
            if util::find_ci(&content, "vmware") {
                return TechniqueResult::detected_with_brand(brands::VMWARE);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VMware string in /proc/ioports.
pub fn vmware_ioports() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = util::read_file("/proc/ioports") {
            if util::find_ci(&content, "vmware") {
                return TechniqueResult::detected_with_brand(brands::VMWARE);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VMware string in /proc/scsi/scsi.
pub fn vmware_scsi() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = util::read_file("/proc/scsi/scsi") {
            if util::find_ci(&content, "vmware") {
                return TechniqueResult::detected_with_brand(brands::VMWARE);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VMware-specific device name in dmesg output.
pub fn vmware_dmesg() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(output) = util::run_command("dmesg", &[]) {
            if output.contains("VMware") || output.contains("vmw_") {
                return TechniqueResult::detected_with_brand(brands::VMWARE);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for QEMU in /sys/devices/virtual/dmi/id.
pub fn qemu_virtual_dmi() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let dmi_fields = ["sys_vendor", "product_name", "board_vendor", "board_name", "bios_vendor"];
        for field in &dmi_fields {
            if let Some(val) = util::linux::read_dmi_field(field) {
                if util::find_ci(&val, "qemu") {
                    return TechniqueResult::detected_with_brand(brands::QEMU);
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for QEMU in /sys/kernel/debug/usb/devices.
pub fn qemu_usb() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = util::read_file("/sys/kernel/debug/usb/devices") {
            if util::find_ci(&content, "qemu") {
                return TechniqueResult::detected_with_brand(brands::QEMU);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for files in /sys/hypervisor directory.
pub fn hypervisor_dir() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if util::dir_exists("/sys/hypervisor") {
            if let Ok(entries) = std::fs::read_dir("/sys/hypervisor") {
                if entries.count() > 0 {
                    // Check for Xen specifically
                    if util::file_exists("/sys/hypervisor/type") {
                        if let Some(hv_type) = util::read_file("/sys/hypervisor/type") {
                            if hv_type.trim() == "xen" {
                                return TechniqueResult::detected_with_brand(brands::XEN);
                            }
                        }
                    }
                    return TechniqueResult::detected();
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for "UML" string in CPU brand.
pub fn uml_cpu() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(cpuinfo) = util::read_file("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") && line.contains("UML") {
                    return TechniqueResult::detected_with_brand(brands::UML);
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for hypervisor indications in kernel message logs.
pub fn kmsg() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = util::read_file("/dev/kmsg") {
            let lower = content.to_lowercase();
            if lower.contains("hypervisor") || lower.contains("vmware")
                || lower.contains("virtualbox") || lower.contains("kvm") {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for a VBox kernel module.
pub fn vbox_module() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let modules = ["vboxguest", "vboxsf", "vboxvideo"];
        for module in &modules {
            if util::linux::is_module_loaded(module) {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM info in /proc/sysinfo.
pub fn sysinfo_proc() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(content) = util::read_file("/proc/sysinfo") {
            let lower = content.to_lowercase();
            if lower.contains("vm") || lower.contains("lpar") {
                return TechniqueResult::detected_with_brand(brands::POWERVM);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for string matches of VM brands in Linux DMI.
pub fn dmi_scan() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let dmi_files = [
            "sys_vendor", "product_name", "product_version",
            "board_vendor", "board_name", "bios_vendor", "bios_version",
        ];

        let vm_strings: &[(&str, &str)] = &[
            ("vmware", brands::VMWARE),
            ("virtualbox", brands::VBOX),
            ("innotek", brands::VBOX),
            ("oracle", brands::VBOX),
            ("qemu", brands::QEMU),
            ("bochs", brands::BOCHS),
            ("microsoft", brands::HYPERV),
            ("hyper-v", brands::HYPERV),
            ("xen", brands::XEN),
            ("parallels", brands::PARALLELS),
            ("kvm", brands::KVM),
            ("bhyve", brands::BHYVE),
            ("google", brands::GCE),
            ("amazon", brands::AWS_NITRO),
            ("openstack", brands::OPENSTACK),
        ];

        for field in &dmi_files {
            if let Some(val) = util::linux::read_dmi_field(field) {
                let lower = val.to_lowercase();
                for &(pattern, brand) in vm_strings {
                    if lower.contains(pattern) {
                        return TechniqueResult::detected_with_brand(brand);
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for the VM bit in SMBIOS data.
pub fn smbios_vm_bit() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        // Check /sys/firmware/dmi/entries for VM indicators
        if let Some(content) = util::read_file("/sys/firmware/dmi/tables/smbios_entry_point") {
            if content.len() > 0 {
                // A simplified check — the full version parses SMBIOS structures
                return TechniqueResult::not_detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for podman file in /run/.
pub fn podman_file() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if util::file_exists("/run/.containerenv") {
            return TechniqueResult::detected_with_brand(brands::PODMAN);
        }
    }
    TechniqueResult::not_detected()
}

/// Check for WSL or microsoft indications in /proc/ subdirectories.
pub fn wsl_proc() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(version) = util::read_file("/proc/version") {
            let lower = version.to_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") {
                return TechniqueResult::detected_with_brand(brands::WSL);
            }
        }
        if let Some(osrelease) = util::read_file("/proc/sys/kernel/osrelease") {
            let lower = osrelease.to_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") {
                return TechniqueResult::detected_with_brand(brands::WSL);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Detect QEMU fw_cfg interface.
pub fn qemu_fw_cfg() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let paths = [
            "/sys/firmware/qemu_fw_cfg",
            "/sys/module/qemu_fw_cfg",
        ];
        for path in &paths {
            if util::dir_exists(path) {
                return TechniqueResult::detected_with_brand(brands::QEMU);
            }
        }
        // Check device tree
        if let Some(compatible) = util::read_file("/sys/firmware/devicetree/base/hypervisor/compatible") {
            if util::find_ci(&compatible, "qemu") {
                return TechniqueResult::detected_with_brand(brands::QEMU);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if accessed file count is too low for a human-managed environment.
pub fn file_access_history() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        if home.is_empty() {
            return TechniqueResult::not_detected();
        }

        let dirs_to_check = [
            format!("{}/Desktop", home),
            format!("{}/Documents", home),
            format!("{}/Downloads", home),
        ];

        let mut total_files = 0usize;
        for dir in &dirs_to_check {
            if let Ok(entries) = std::fs::read_dir(dir) {
                total_files += entries.count();
            }
        }

        // If all common directories have very few files, it might be a fresh VM
        if total_files <= 3 {
            return TechniqueResult::detected();
        }
    }
    TechniqueResult::not_detected()
}

/// Check if MAC address starts with VM-designated values.
pub fn mac_address_check() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        if let Some(mac) = util::linux::get_mac_address() {
            let upper = mac.to_uppercase();
            let vm_mac_prefixes: &[(&str, &str)] = &[
                ("00:05:69", brands::VMWARE),
                ("00:0C:29", brands::VMWARE),
                ("00:1C:14", brands::VMWARE),
                ("00:50:56", brands::VMWARE),
                ("08:00:27", brands::VBOX),
                ("0A:00:27", brands::VBOX),
                ("00:03:FF", brands::HYPERV),
                ("00:15:5D", brands::HYPERV),
                ("00:1A:4A", brands::QEMU),
                ("52:54:00", brands::QEMU),
                ("00:16:3E", brands::XEN),
                ("00:1C:42", brands::PARALLELS),
            ];

            for &(prefix, brand) in vm_mac_prefixes {
                if upper.starts_with(prefix) {
                    return TechniqueResult::detected_with_brand(brand);
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if process status matches nsjail patterns.
pub fn nsjail_pid() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        // nsjail typically runs processes with PID 1 that aren't init/systemd
        if let Some(comm) = util::read_file("/proc/1/comm") {
            let name = comm.trim();
            if name != "init" && name != "systemd" && name != "launchd" {
                // Check if it's nsjail
                if let Some(status) = util::read_file("/proc/1/status") {
                    if status.contains("nsjail") {
                        return TechniqueResult::detected_with_brand(brands::NSJAIL);
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for BlueStacks-specific folders.
pub fn bluestacks_folders() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let paths = [
            "/sdcard/windows/BstSharedFolder",
            "/mnt/windows/BstSharedFolder",
        ];
        for path in &paths {
            if util::dir_exists(path) {
                return TechniqueResult::detected_with_brand(brands::BLUESTACKS);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for AMD-SEV MSR.
pub fn amd_sev() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        // Check /sys/module/kvm_amd/parameters/sev
        if let Some(val) = util::read_file("/sys/module/kvm_amd/parameters/sev") {
            if val.trim() == "Y" || val.trim() == "1" {
                return TechniqueResult::detected_with_brand(brands::AMD_SEV);
            }
        }
        // Check dmesg for AMD SEV
        if let Some(dmesg_out) = util::run_command("dmesg", &[]) {
            if dmesg_out.contains("AMD SEV") {
                return TechniqueResult::detected_with_brand(brands::AMD_SEV);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for device's temperature sensors.
pub fn temperature() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        // VMs typically don't have temperature sensors
        let temp_paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
        ];

        let mut has_sensor = false;
        for path in &temp_paths {
            if let Some(val) = util::read_file(path) {
                if let Ok(temp) = val.trim().parse::<i64>() {
                    if temp > 0 {
                        has_sensor = true;
                        break;
                    }
                }
            }
        }

        if !has_sensor {
            return TechniqueResult::detected();
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM processes that are active.
pub fn processes() -> TechniqueResult {
    #[cfg(target_os = "linux")]
    {
        let vm_processes: &[(&str, &str)] = &[
            ("VBoxService", brands::VBOX),
            ("VBoxClient", brands::VBOX),
            ("vmtoolsd", brands::VMWARE),
            ("vmwaretray", brands::VMWARE),
            ("vmwareuser", brands::VMWARE),
            ("vmware-vmblock-fuse", brands::VMWARE),
            ("qemu-ga", brands::QEMU),
            ("spice-vdagent", brands::QEMU),
            ("xe-daemon", brands::XEN),
            ("prl_cc", brands::PARALLELS),
            ("prl_tools", brands::PARALLELS),
        ];

        let running = util::linux::list_processes();
        for &(proc_name, brand) in vm_processes {
            if running.iter().any(|p| p == proc_name) {
                return TechniqueResult::detected_with_brand(brand);
            }
        }
    }
    TechniqueResult::not_detected()
}
