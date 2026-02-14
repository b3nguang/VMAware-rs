//! Windows-specific VM detection techniques.

#[cfg(target_os = "windows")]
use crate::engine::TechniqueResult;
#[cfg(target_os = "windows")]
use crate::brands;
#[cfg(target_os = "windows")]
use crate::util;

#[cfg(not(target_os = "windows"))]
use crate::engine::TechniqueResult;

/// Check for VM-specific DLLs.
pub fn dll() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        let vm_dlls: &[(&str, &str)] = &[
            ("vmGuestLib.dll", brands::VMWARE),
            ("vboxhook.dll", brands::VBOX),
            ("VBoxService.exe", brands::VBOX),
            ("vboxdisp.dll", brands::VBOX),
            ("vboxogl.dll", brands::VBOX),
            ("vboxoglarrayspu.dll", brands::VBOX),
            ("vboxoglcrutil.dll", brands::VBOX),
            ("vboxoglfeedbackspu.dll", brands::VBOX),
            ("vboxoglpackspu.dll", brands::VBOX),
            ("vboxoglpassthroughspu.dll", brands::VBOX),
            ("paborea.dll", brands::PARALLELS),
            ("SbieDll.dll", brands::SANDBOXIE),
            ("SxIn.dll", brands::COMODO),
            ("cmdvrt32.dll", brands::COMODO),
            ("cmdvrt64.dll", brands::COMODO),
        ];

        for &(dll_name, brand) in vm_dlls {
            if util::win::is_dll_loaded(dll_name) {
                return TechniqueResult::detected_with_brand(brand);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for Wine environment.
pub fn wine() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check for wine_get_unix_file_name export in ntdll.dll
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::core::PCWSTR;

        let ntdll_wide = util::win::to_wide("ntdll.dll");
        unsafe {
            if let Ok(handle) = GetModuleHandleW(PCWSTR(ntdll_wide.as_ptr())) {
                let func_name = b"wine_get_unix_file_name\0";
                if GetProcAddress(handle, windows::core::PCSTR(func_name.as_ptr())).is_some() {
                    return TechniqueResult::detected_with_brand(brands::WINE);
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for mutex strings of VM brands.
pub fn mutex() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        let vm_mutexes: &[(&str, &str)] = &[
            ("MicrosoftVirtualPC7UserServiceMakeSureRunning", brands::VPC),
            ("VBoxTrayIPC", brands::VBOX),
            ("VBoxMiniRdrDN", brands::VBOX),
        ];

        for &(mutex_name, brand) in vm_mutexes {
            if util::win::mutex_exists(mutex_name) {
                return TechniqueResult::detected_with_brand(brand);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM-specific guest drivers.
/// Only checks guest-exclusive driver paths and services (not host-side ones).
pub fn drivers() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Guest-exclusive device paths only
        let vm_drivers: &[(&str, &str)] = &[
            (r"\\.\VBoxMiniRdrDN", brands::VBOX),
            (r"\\.\VBoxGuest", brands::VBOX),
            (r"\\.\VBoxTrayIPC", brands::VBOX),
            (r"\\.\pipe\VBoxMiniRdDN", brands::VBOX),
            (r"\\.\pipe\VBoxTrayIPC", brands::VBOX),
        ];

        for &(driver_path, brand) in vm_drivers {
            if util::file_exists(driver_path) {
                return TechniqueResult::detected_with_brand(brand);
            }
        }

        // Guest-exclusive driver services (not present on host machines)
        let guest_services: &[(&str, &str)] = &[
            (r"SYSTEM\CurrentControlSet\Services\VBoxGuest", brands::VBOX),
            (r"SYSTEM\CurrentControlSet\Services\VBoxMouse", brands::VBOX),
            (r"SYSTEM\CurrentControlSet\Services\VBoxSF", brands::VBOX),
            (r"SYSTEM\CurrentControlSet\Services\VBoxVideo", brands::VBOX),
            (r"SYSTEM\CurrentControlSet\Services\vmmouse", brands::VMWARE),
            (r"SYSTEM\CurrentControlSet\Services\vmvss", brands::VMWARE),
        ];

        for &(reg_path, brand) in guest_services {
            if let Some(start_val) = util::win::read_registry_string("HKLM", reg_path, "Start") {
                // Only count if the service is actually set to start (0=Boot, 1=System, 2=Auto, 3=Manual)
                if let Ok(start) = start_val.parse::<u32>() {
                    if start <= 3 {
                        return TechniqueResult::detected_with_brand(brand);
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for serial numbers of virtual disks.
pub fn disk_serial() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check disk hardware IDs in registry
        let subkeys = util::win::enum_registry_subkeys("HKLM", r"SYSTEM\CurrentControlSet\Enum\IDE");
        for key in &subkeys {
            let lower = key.to_lowercase();
            if lower.contains("vbox") { return TechniqueResult::detected_with_brand(brands::VBOX); }
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("virtual") { return TechniqueResult::detected(); }
        }

        let scsi_subkeys = util::win::enum_registry_subkeys("HKLM", r"SYSTEM\CurrentControlSet\Enum\SCSI");
        for key in &scsi_subkeys {
            let lower = key.to_lowercase();
            if lower.contains("vbox") { return TechniqueResult::detected_with_brand(brands::VBOX); }
            if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("virtual") { return TechniqueResult::detected(); }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for vm-specific device handles.
/// Only checks guest-only devices that wouldn't exist on a host with VM software installed.
pub fn device_handles() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Only guest-specific devices — NOT host-side ones like HGFS or vmci
        let device_names: &[(&str, &str)] = &[
            (r"\\.\VBoxMiniRdrDN", brands::VBOX),
            (r"\\.\VBoxGuest", brands::VBOX),
            (r"\\.\pipe\VBoxMiniRdDN", brands::VBOX),
            (r"\\.\pipe\VBoxTrayIPC", brands::VBOX),
        ];

        for &(name, brand) in device_names {
            use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL};
            use windows::Win32::Foundation::GENERIC_READ;
            use windows::core::PCWSTR;

            let wide = util::win::to_wide(name);
            unsafe {
                let handle = CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                );
                if let Ok(h) = handle {
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                    return TechniqueResult::detected_with_brand(brand);
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for display configurations commonly found in VMs.
pub fn display() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check display adapter description in registry
        let subkeys = util::win::enum_registry_subkeys(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
        );
        for key in &subkeys {
            let path = format!(
                r"SYSTEM\CurrentControlSet\Control\Class\{{4d36e968-e325-11ce-bfc1-08002be10318}}\{}",
                key
            );
            if let Some(desc) = util::win::read_registry_string("HKLM", &path, "DriverDesc") {
                let lower = desc.to_lowercase();
                if lower.contains("vmware") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
                if lower.contains("virtualbox") || lower.contains("vbox") { return TechniqueResult::detected_with_brand(brands::VBOX); }
                if lower.contains("qxl") || lower.contains("virtio") { return TechniqueResult::detected_with_brand(brands::QEMU); }
                if lower.contains("hyper-v") || lower.contains("microsoft basic") { return TechniqueResult::detected_with_brand(brands::HYPERV); }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if no waveform-audio output devices are present.
pub fn audio() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Media::Audio::waveOutGetNumDevs;
        unsafe {
            if waveOutGetNumDevs() == 0 {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check what power states are enabled.
pub fn power_capabilities() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // VMs typically don't support S1-S4 sleep states
        if let Some(val) = util::win::read_registry_string(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Power",
            "HibernateEnabled",
        ) {
            // Hibernate disabled could indicate VM
            if val == "0" {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for GPU capabilities related to VMs.
pub fn gpu_capabilities() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check for VM-specific GPU adapters in registry
        if let Some(desc) = util::win::read_registry_string(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Video",
            "",
        ) {
            let lower = desc.to_lowercase();
            if lower.contains("vmware") || lower.contains("virtualbox") || lower.contains("qxl") {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if virtual and logical processors are reported correctly.
pub fn virtual_processors() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::SystemInformation::GetSystemInfo;
        use windows::Win32::System::SystemInformation::SYSTEM_INFO;

        unsafe {
            let mut si = SYSTEM_INFO::default();
            GetSystemInfo(&mut si);

            // In some VMs, the number of processors can be inconsistent
            // Check if CPUID-reported count matches OS-reported count
            let os_count = si.dwNumberOfProcessors;
            let thread_count = crate::util::thread_count() as u32;

            if os_count != thread_count && os_count > 0 && thread_count > 0 {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check NtQuerySystemInformation for hypervisor detail.
pub fn hypervisor_query() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check for hypervisor presence via registry (SystemInformation leaf 0x9f)
        if let Some(val) = util::win::read_registry_string(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
            "Enabled",
        ) {
            if val == "1" {
                return TechniqueResult::detected();
            }
        }

        // Also check for VHD boot
        if let Some(val) = util::win::read_registry_string(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control",
            "BootVhdDevice",
        ) {
            if !val.is_empty() {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM-specific entries in the Windows registry.
pub fn virtual_registry() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check for Sandboxie-specific registry entries
        if util::win::read_registry_string("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion", "SbieDll").is_some() {
            return TechniqueResult::detected_with_brand(brands::SANDBOXIE);
        }

        // Check for VBox guest additions
        if util::win::read_registry_string("HKLM", r"SOFTWARE\Oracle\VirtualBox Guest Additions", "InstallDir").is_some() {
            return TechniqueResult::detected_with_brand(brands::VBOX);
        }

        // VMware tools
        if util::win::read_registry_string("HKLM", r"SOFTWARE\VMware, Inc.\VMware Tools", "InstallPath").is_some() {
            return TechniqueResult::detected_with_brand(brands::VMWARE);
        }

        // Hyper-V guest interfaces
        if util::win::read_registry_string("HKLM", r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", "HostName").is_some() {
            return TechniqueResult::detected_with_brand(brands::HYPERV);
        }

        // Parallels tools
        if util::win::read_registry_string("HKLM", r"SOFTWARE\Parallels\Tools", "InstallPath").is_some() {
            return TechniqueResult::detected_with_brand(brands::PARALLELS);
        }

        // QEMU guest agent
        if util::win::read_registry_string("HKLM", r"SYSTEM\CurrentControlSet\Services\QEMU-GA", "ImagePath").is_some() {
            return TechniqueResult::detected_with_brand(brands::QEMU);
        }

        // SystemManufacturer / SystemProductName from BIOS registry
        let bios_checks: &[(&str, &[(&str, &str)])] = &[
            ("SystemManufacturer", &[
                ("vmware", brands::VMWARE),
                ("innotek", brands::VBOX),
                ("oracle", brands::VBOX),
                ("qemu", brands::QEMU),
                ("xen", brands::XEN),
                ("parallels", brands::PARALLELS),
                ("microsoft corporation", brands::HYPERV),
            ]),
            ("SystemProductName", &[
                ("vmware", brands::VMWARE),
                ("virtualbox", brands::VBOX),
                ("virtual machine", brands::HYPERV),
                ("kvm", brands::KVM),
                ("bochs", brands::BOCHS),
            ]),
        ];

        for &(value_name, patterns) in bios_checks {
            if let Some(val) = util::win::read_registry_string(
                "HKLM",
                r"HARDWARE\DESCRIPTION\System\BIOS",
                value_name,
            ) {
                let lower = val.to_lowercase();
                for &(pat, brand) in patterns {
                    if lower.contains(pat) {
                        return TechniqueResult::detected_with_brand(brand);
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for Gamarue ransomware technique (VM-specific product IDs).
pub fn gamarue() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        let vm_product_ids = [
            "55274-649-6478953-23109",
            "76487-644-3177037-23510",
            "76487-337-8429955-22614",
        ];

        if let Some(product_id) = util::win::read_registry_string(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductId",
        ) {
            for &vm_id in &vm_product_ids {
                if product_id == vm_id {
                    return TechniqueResult::detected();
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check STR instruction for VMware.
pub fn vmware_str() -> TechniqueResult {
    // STR instruction-based detection is x86_32 only and requires inline assembly
    // Not safely implementable in Rust — return not detected
    TechniqueResult::not_detected()
}

/// Check for VPC invalid opcode method (32-bit only).
pub fn vpc_invalid() -> TechniqueResult {
    // VPC invalid opcode technique requires 32-bit x86 inline assembly
    TechniqueResult::not_detected()
}

/// Check if bogus device string would be accepted.
pub fn device_string() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL};
        use windows::Win32::Foundation::GENERIC_READ;
        use windows::core::PCWSTR;

        // Try to open a known non-existent device
        let bogus = r"\\.\BogusDeviceNameThatShouldNotExist";
        let wide = util::win::to_wide(bogus);
        unsafe {
            let result = CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            );
            if let Ok(handle) = result {
                // In some VM sandboxes, any device name is accepted
                let _ = windows::Win32::Foundation::CloseHandle(handle);
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for cuckoo directory.
pub fn cuckoo_dir() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        let paths = [
            r"C:\cuckoo",
            r"C:\stimulus",
        ];
        for path in &paths {
            if util::dir_exists(path) {
                return TechniqueResult::detected_with_brand(brands::CUCKOO);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for Cuckoo-specific piping mechanism.
pub fn cuckoo_pipe() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        if util::file_exists(r"\\.\pipe\cuckoo") {
            return TechniqueResult::detected_with_brand(brands::CUCKOO);
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VMware I/O port backdoor.
/// Uses registry-based and CPUID-based fallback since IN instruction requires inline assembly.
pub fn vmware_backdoor() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Fallback: check for VMware backdoor presence via CPUID hypervisor leaf
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use crate::cpu;
            if cpu::is_leaf_supported(cpu::leaf::HYPERVISOR) {
                let brand = cpu::cpu_manufacturer(cpu::leaf::HYPERVISOR);
                if brand == "VMwareVMware" {
                    // Additional confirmation: check VMware-specific CPUID leaf 0x40000010
                    if cpu::is_leaf_supported(0x4000_0010) {
                        let r = cpu::cpuid(0x4000_0010, 0);
                        // VMware returns TSC frequency info here
                        if r.eax != 0 {
                            return TechniqueResult::detected_with_brand(brands::VMWARE);
                        }
                    }
                }
            }
        }

        // Also check for VMware Tools communication channel via registry
        if let Some(val) = util::win::read_registry_string(
            "HKLM",
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            "InstallPath",
        ) {
            if !val.is_empty() {
                // Verify it's a guest installation, not just host tools
                if util::file_exists(&format!("{}\\vmtoolsd.exe", val.trim_end_matches('\\'))) {
                    return TechniqueResult::detected_with_brand(brands::VMWARE);
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for IVSHMEM device presence.
pub fn ivshmem() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // IVSHMEM is a shared memory device used by QEMU/KVM
        let subkeys = util::win::enum_registry_subkeys("HKLM", r"SYSTEM\CurrentControlSet\Enum\PCI");
        for key in &subkeys {
            let lower = key.to_lowercase();
            // Red Hat IVSHMEM device: VEN_1AF4&DEV_1110
            if lower.contains("ven_1af4") && lower.contains("dev_1110") {
                return TechniqueResult::detected_with_brand(brands::QEMU);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for VM-specific ACPI device signatures.
pub fn acpi_signature() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check ACPI table entries in registry
        let subkeys = util::win::enum_registry_subkeys("HKLM", r"SYSTEM\CurrentControlSet\Enum\ACPI");
        for key in &subkeys {
            let lower = key.to_lowercase();
            if lower.contains("vmw") { return TechniqueResult::detected_with_brand(brands::VMWARE); }
            if lower.contains("vbox") { return TechniqueResult::detected_with_brand(brands::VBOX); }
            if lower.contains("qemu") { return TechniqueResult::detected_with_brand(brands::QEMU); }
            if lower.contains("xen") { return TechniqueResult::detected_with_brand(brands::XEN); }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for trap-based hypervisor detection.
/// Uses CPUID-based heuristic as safe fallback for the assembly-based trap technique.
pub fn trap() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use crate::cpu;
            // If hypervisor bit is set, perform a timing-based trap check
            let r = cpu::cpuid(1, 0);
            let hv_bit = (r.ecx >> 31) & 1;
            if hv_bit == 1 {
                // Check if hypervisor leaf reports meaningful data
                if cpu::is_leaf_supported(cpu::leaf::HYPERVISOR) {
                    let hv = cpu::cpuid(cpu::leaf::HYPERVISOR, 0);
                    // A real hypervisor will have non-zero max leaf in EAX
                    if hv.eax > cpu::leaf::HYPERVISOR {
                        return TechniqueResult::detected();
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for undefined instruction behavior in VMs.
/// Uses timing-based heuristic as safe fallback.
pub fn ud() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // Measure CPUID timing variance — VMs show higher variance
            let mut times = [0u64; 5];
            for t in &mut times {
                let start: u64;
                let end: u64;
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    start = std::arch::x86_64::_rdtsc();
                    let _ = std::arch::x86_64::__cpuid(0);
                    end = std::arch::x86_64::_rdtsc();
                }
                #[cfg(target_arch = "x86")]
                unsafe {
                    start = std::arch::x86::_rdtsc();
                    let _ = std::arch::x86::__cpuid(0);
                    end = std::arch::x86::_rdtsc();
                }
                *t = end.wrapping_sub(start);
            }

            times.sort();
            let median = times[2];
            let max = times[4];
            // In VMs, max/median ratio is often very high due to VMEXIT overhead variance
            if median > 0 && max / median > 10 {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if a hypervisor improperly restores interruptibility state.
/// Uses CPUID timing consistency check as safe fallback.
pub fn blockstep() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // Measure back-to-back CPUID pairs — VMs often show step-like timing
            let mut deltas = [0u64; 10];
            for d in &mut deltas {
                let start: u64;
                let end: u64;
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    start = std::arch::x86_64::_rdtsc();
                    let _ = std::arch::x86_64::__cpuid(0);
                    let _ = std::arch::x86_64::__cpuid(0);
                    end = std::arch::x86_64::_rdtsc();
                }
                #[cfg(target_arch = "x86")]
                unsafe {
                    start = std::arch::x86::_rdtsc();
                    let _ = std::arch::x86::__cpuid(0);
                    let _ = std::arch::x86::__cpuid(0);
                    end = std::arch::x86::_rdtsc();
                }
                *d = end.wrapping_sub(start);
            }

            let avg: u64 = deltas.iter().sum::<u64>() / deltas.len() as u64;
            // On bare metal, back-to-back CPUID pairs take roughly 2x a single CPUID
            // In some VMs, the overhead is much higher due to blockstepping
            if avg > 2000 {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if Dark Byte's VM (DBVM) is present.
pub fn dbvm() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // DBVM uses specific CPUID leaf
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use crate::cpu;
            // DBVM responds to a specific CPUID call
            let r = cpu::cpuid(0x4000_0000, 0);
            let mut brand = [0u8; 13];
            brand[0..4].copy_from_slice(&r.ebx.to_le_bytes());
            brand[4..8].copy_from_slice(&r.ecx.to_le_bytes());
            brand[8..12].copy_from_slice(&r.edx.to_le_bytes());
            brand[12] = 0;
            let s = String::from_utf8_lossy(&brand);
            if s.contains("INTDBVM") || s.contains("DBVM") {
                return TechniqueResult::detected_with_brand(brands::DBVM);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check boot logo for known VM images.
pub fn boot_logo() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check OEM logo path in registry
        if let Some(logo) = util::win::read_registry_string(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation",
            "Logo",
        ) {
            let lower = logo.to_lowercase();
            if lower.contains("vmware") || lower.contains("virtualbox") || lower.contains("qemu") {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for any signs of VMs in Windows kernel object entities.
/// Only checks guest-exclusive services to avoid false positives on VM host machines.
pub fn kernel_objects() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Guest-exclusive services (these are NOT present on host machines
        // that merely have VMware Workstation or VirtualBox installed)
        let guest_services: &[(&str, &str)] = &[
            ("VBoxService", brands::VBOX),
            ("VBoxGuest", brands::VBOX),
            ("VBoxWddm", brands::VBOX),
            ("vm3dmp", brands::VMWARE),       // VMware SVGA 3D display driver (guest only)
            ("vmrawdsk", brands::VMWARE),      // VMware raw disk driver (guest only)
            ("vmusbmouse", brands::VMWARE),    // VMware USB mouse (guest only)
            ("vmvss", brands::VMWARE),         // VMware VSS provider (guest only)
            ("vmmouse", brands::VMWARE),       // VMware mouse driver (guest only)
            ("hvservice", brands::HYPERV),     // Hyper-V guest service
            ("vmicheartbeat", brands::HYPERV), // Hyper-V heartbeat
            ("vmicshutdown", brands::HYPERV),  // Hyper-V shutdown
            ("vmickvpexchange", brands::HYPERV), // Hyper-V KVP exchange
            ("vmicguestinterface", brands::HYPERV), // Hyper-V guest interface
            ("prl_fs", brands::PARALLELS),     // Parallels shared folders
            ("prl_tg", brands::PARALLELS),     // Parallels tools gate
            ("QEMU-GA", brands::QEMU),         // QEMU guest agent
            ("vioscsi", brands::QEMU),         // VirtIO SCSI
            ("viostor", brands::QEMU),         // VirtIO storage
            ("netkvm", brands::QEMU),          // VirtIO net
            ("balloon", brands::QEMU),         // VirtIO balloon
        ];

        for &(service, brand) in guest_services {
            let path = format!(r"SYSTEM\CurrentControlSet\Services\{}", service);
            // Check that the service exists and has a valid Start value
            if let Some(start_val) = util::win::read_registry_string("HKLM", &path, "Start") {
                if let Ok(start) = start_val.parse::<u32>() {
                    if start <= 4 {
                        return TechniqueResult::detected_with_brand(brand);
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for known NVRAM signatures on virtual firmware.
/// Checks UEFI firmware vendor string from registry as a safe fallback.
pub fn nvram() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check firmware type and vendor from BIOS registry
        let bios_fields: &[(&str, &[(&str, &str)])] = &[
            ("SystemBiosVersion", &[
                ("vbox", brands::VBOX),
                ("virtualbox", brands::VBOX),
                ("vmware", brands::VMWARE),
                ("qemu", brands::QEMU),
                ("bochs", brands::BOCHS),
            ]),
            ("SystemProductName", &[
                ("virtual", brands::NULL_BRAND),
                ("vmware", brands::VMWARE),
                ("vbox", brands::VBOX),
            ]),
        ];

        for &(value_name, patterns) in bios_fields {
            if let Some(val) = util::win::read_registry_string(
                "HKLM",
                r"HARDWARE\DESCRIPTION\System\BIOS",
                value_name,
            ) {
                let lower = val.to_lowercase();
                for &(pat, brand) in patterns {
                    if lower.contains(pat) {
                        if brand == brands::NULL_BRAND {
                            return TechniqueResult::detected();
                        }
                        return TechniqueResult::detected_with_brand(brand);
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check if SMBIOS is malformed/corrupted (typical for VMs).
pub fn smbios_integrity() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        if let Some(bios_ver) = util::win::read_registry_string(
            "HKLM",
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "BIOSVersion",
        ) {
            let lower = bios_ver.to_lowercase();
            if lower.contains("vbox") || lower.contains("virtualbox") {
                return TechniqueResult::detected_with_brand(brands::VBOX);
            }
            if lower.contains("vmware") {
                return TechniqueResult::detected_with_brand(brands::VMWARE);
            }
            if lower.contains("qemu") || lower.contains("bochs") || lower.contains("seabios") {
                return TechniqueResult::detected_with_brand(brands::QEMU);
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check for non-standard EDID configurations.
pub fn edid() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check EDID data in registry for VM monitor signatures
        let subkeys = util::win::enum_registry_subkeys("HKLM", r"SYSTEM\CurrentControlSet\Enum\DISPLAY");
        for key in &subkeys {
            let lower = key.to_lowercase();
            if lower.contains("vmw") || lower.contains("vbox") || lower.contains("qxl") {
                return TechniqueResult::detected();
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check whether the CPU is genuine and its instruction capabilities are not masked.
/// Detects VMs that mask or alter CPUID feature bits.
pub fn cpu_heuristic() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use crate::cpu;
            let r = cpu::cpuid(1, 0);
            let hv_bit = (r.ecx >> 31) & 1;

            if hv_bit == 1 {
                // Check for CPU feature inconsistencies that suggest masking
                let stepping = cpu::fetch_steppings();

                // Family 0 or model 0 with hypervisor bit is suspicious
                if stepping.family == 0 && stepping.model == 0 {
                    return TechniqueResult::detected();
                }

                // If hypervisor brand is known, check for feature masking
                if cpu::is_leaf_supported(cpu::leaf::HYPERVISOR) {
                    let hv = cpu::cpuid(cpu::leaf::HYPERVISOR, 0);
                    // Check if hypervisor reports suspiciously few features
                    let max_leaf = hv.eax;
                    if max_leaf > 0x4000_0000 && max_leaf < 0x4000_0003 {
                        // Very limited hypervisor leaf range — could be a masked VM
                        return TechniqueResult::detected();
                    }
                }
            }
        }
    }
    TechniqueResult::not_detected()
}

/// Check the presence of system timers.
pub fn clock() -> TechniqueResult {
    #[cfg(target_os = "windows")]
    {
        // Check for TSC frequency anomalies
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            use std::time::Instant;
            let start_tsc: u64;
            let end_tsc: u64;

            let start_time = Instant::now();

            #[cfg(target_arch = "x86_64")]
            unsafe {
                start_tsc = std::arch::x86_64::_rdtsc();
            }
            #[cfg(target_arch = "x86")]
            unsafe {
                start_tsc = std::arch::x86::_rdtsc();
            }

            // Spin for ~1ms
            while start_time.elapsed().as_micros() < 1000 {}

            #[cfg(target_arch = "x86_64")]
            unsafe {
                end_tsc = std::arch::x86_64::_rdtsc();
            }
            #[cfg(target_arch = "x86")]
            unsafe {
                end_tsc = std::arch::x86::_rdtsc();
            }

            let elapsed_tsc = end_tsc.wrapping_sub(start_tsc);
            let elapsed_us = start_time.elapsed().as_micros() as u64;

            if elapsed_us > 0 {
                let freq_mhz = elapsed_tsc / elapsed_us;
                // Very low TSC frequency could indicate VM timer virtualization issues
                if freq_mhz < 100 {
                    return TechniqueResult::detected();
                }
            }
        }
    }
    TechniqueResult::not_detected()
}
