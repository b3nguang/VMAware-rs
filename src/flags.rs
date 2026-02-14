/// Technique and setting flags for VM detection.
/// Each variant corresponds to a specific VM detection technique or a setting.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Flag {
    // Windows-specific
    GpuCapabilities = 0,
    AcpiSignature,
    PowerCapabilities,
    DiskSerial,
    Ivshmem,
    Drivers,
    DeviceHandles,
    VirtualProcessors,
    HypervisorQuery,
    Audio,
    Display,
    Dll,
    VmwareBackdoor,
    Wine,
    VirtualRegistry,
    Mutex,
    DeviceString,
    VpcInvalid,
    VmwareStr,
    Gamarue,
    CuckooDir,
    CuckooPipe,
    BootLogo,
    Trap,
    Ud,
    Blockstep,
    Dbvm,
    KernelObjects,
    Nvram,
    SmbiosIntegrity,
    Edid,
    CpuHeuristic,
    Clock,

    // Linux and Windows
    SystemRegisters,
    Firmware,
    PciDevices,
    Azure,

    // Linux
    SmbiosVmBit,
    Kmsg,
    Cvendor,
    QemuFwCfg,
    Systemd,
    Ctype,
    Dockerenv,
    Dmidecode,
    Dmesg,
    Hwmon,
    LinuxUserHost,
    VmwareIomem,
    VmwareIoports,
    VmwareScsi,
    VmwareDmesg,
    QemuVirtualDmi,
    QemuUsb,
    HypervisorDir,
    UmlCpu,
    VboxModule,
    SysinfoProc,
    DmiScan,
    PodmanFile,
    WslProc,
    FileAccessHistory,
    Mac,
    NsjailPid,
    BluestacksFolders,
    AmdSev,
    Temperature,
    Processes,

    // Linux and MacOS
    ThreadCount,

    // MacOS
    MacMemsize,
    MacIokit,
    MacSip,
    IoregGrep,
    Hwmodel,
    MacSys,

    // Cross-platform
    HypervisorBit,
    Vmid,
    ThreadMismatch,
    Timer,
    CpuBrand,
    HypervisorStr,
    CpuidSignature,
    BochsCpu,
    KgtSignature,

    // Sentinel for technique count (not a real technique)
    _TechniqueEnd,
}

/// Setting flags (not techniques)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Setting {
    Default,
    All,
    HighThreshold,
    Dynamic,
    Multiple,
    NullArg,
}

impl Flag {
    /// Total number of actual techniques (excluding _TechniqueEnd).
    pub const TECHNIQUE_COUNT: usize = Self::_TechniqueEnd as usize;

    /// Convert flag to its string name.
    pub fn to_str(self) -> &'static str {
        match self {
            Flag::Vmid => "VMID",
            Flag::CpuBrand => "CPU_BRAND",
            Flag::HypervisorBit => "HYPERVISOR_BIT",
            Flag::HypervisorStr => "HYPERVISOR_STR",
            Flag::Timer => "TIMER",
            Flag::ThreadCount => "THREAD_COUNT",
            Flag::Mac => "MAC",
            Flag::Temperature => "TEMPERATURE",
            Flag::Systemd => "SYSTEMD",
            Flag::Cvendor => "CVENDOR",
            Flag::Ctype => "CTYPE",
            Flag::Dockerenv => "DOCKERENV",
            Flag::Dmidecode => "DMIDECODE",
            Flag::Dmesg => "DMESG",
            Flag::Hwmon => "HWMON",
            Flag::Dll => "DLL",
            Flag::Hwmodel => "HWMODEL",
            Flag::Wine => "WINE",
            Flag::PowerCapabilities => "POWER_CAPABILITIES",
            Flag::Processes => "PROCESSES",
            Flag::LinuxUserHost => "LINUX_USER_HOST",
            Flag::Gamarue => "GAMARUE",
            Flag::BochsCpu => "BOCHS_CPU",
            Flag::MacMemsize => "MAC_MEMSIZE",
            Flag::MacIokit => "MAC_IOKIT",
            Flag::IoregGrep => "IOREG_GREP",
            Flag::MacSip => "MAC_SIP",
            Flag::VpcInvalid => "VPC_INVALID",
            Flag::SystemRegisters => "SYSTEM_REGISTERS",
            Flag::VmwareIomem => "VMWARE_IOMEM",
            Flag::VmwareIoports => "VMWARE_IOPORTS",
            Flag::VmwareScsi => "VMWARE_SCSI",
            Flag::VmwareDmesg => "VMWARE_DMESG",
            Flag::VmwareStr => "VMWARE_STR",
            Flag::VmwareBackdoor => "VMWARE_BACKDOOR",
            Flag::Mutex => "MUTEX",
            Flag::ThreadMismatch => "THREAD_MISMATCH",
            Flag::CuckooDir => "CUCKOO_DIR",
            Flag::CuckooPipe => "CUCKOO_PIPE",
            Flag::Azure => "AZURE",
            Flag::Display => "DISPLAY",
            Flag::DeviceString => "DEVICE_STRING",
            Flag::BluestacksFolders => "BLUESTACKS_FOLDERS",
            Flag::CpuidSignature => "CPUID_SIGNATURE",
            Flag::KgtSignature => "KGT_SIGNATURE",
            Flag::QemuVirtualDmi => "QEMU_VIRTUAL_DMI",
            Flag::QemuUsb => "QEMU_USB",
            Flag::HypervisorDir => "HYPERVISOR_DIR",
            Flag::UmlCpu => "UML_CPU",
            Flag::Kmsg => "KMSG",
            Flag::VboxModule => "VBOX_MODULE",
            Flag::SysinfoProc => "SYSINFO_PROC",
            Flag::DmiScan => "DMI_SCAN",
            Flag::SmbiosVmBit => "SMBIOS_VM_BIT",
            Flag::PodmanFile => "PODMAN_FILE",
            Flag::WslProc => "WSL_PROC",
            Flag::Drivers => "DRIVERS",
            Flag::DiskSerial => "DISK_SERIAL",
            Flag::Ivshmem => "IVSHMEM",
            Flag::GpuCapabilities => "GPU_CAPABILITIES",
            Flag::DeviceHandles => "DEVICE_HANDLES",
            Flag::QemuFwCfg => "QEMU_FW_CFG",
            Flag::VirtualProcessors => "VIRTUAL_PROCESSORS",
            Flag::HypervisorQuery => "HYPERVISOR_QUERY",
            Flag::AmdSev => "AMD_SEV",
            Flag::VirtualRegistry => "VIRTUAL_REGISTRY",
            Flag::Firmware => "FIRMWARE",
            Flag::FileAccessHistory => "FILE_ACCESS_HISTORY",
            Flag::Audio => "AUDIO",
            Flag::NsjailPid => "NSJAIL_PID",
            Flag::PciDevices => "PCI_DEVICES",
            Flag::AcpiSignature => "ACPI_SIGNATURE",
            Flag::Trap => "TRAP",
            Flag::Ud => "UNDEFINED_INSTRUCTION",
            Flag::Blockstep => "BLOCKSTEP",
            Flag::Dbvm => "DBVM",
            Flag::BootLogo => "BOOT_LOGO",
            Flag::MacSys => "MAC_SYS",
            Flag::KernelObjects => "KERNEL_OBJECTS",
            Flag::Nvram => "NVRAM",
            Flag::SmbiosIntegrity => "SMBIOS_INTEGRITY",
            Flag::Edid => "EDID",
            Flag::CpuHeuristic => "CPU_HEURISTIC",
            Flag::Clock => "CLOCK",
            Flag::_TechniqueEnd => "UNKNOWN",
        }
    }

    /// Returns true if this technique is supported on the current platform.
    pub fn is_supported_on_current_platform(self) -> bool {
        let idx = self as u8;
        // Windows-only range
        if idx <= Flag::Clock as u8 {
            return cfg!(target_os = "windows");
        }
        // Linux+Windows
        if idx >= Flag::SystemRegisters as u8 && idx <= Flag::Azure as u8 {
            return cfg!(target_os = "windows") || cfg!(target_os = "linux");
        }
        // Linux-only
        if idx >= Flag::SmbiosVmBit as u8 && idx <= Flag::Processes as u8 {
            return cfg!(target_os = "linux");
        }
        // Linux+macOS
        if self == Flag::ThreadCount {
            return cfg!(target_os = "linux") || cfg!(target_os = "macos");
        }
        // macOS-only
        if idx >= Flag::MacMemsize as u8 && idx <= Flag::MacSys as u8 {
            return cfg!(target_os = "macos");
        }
        // Cross-platform
        if idx >= Flag::HypervisorBit as u8 && idx <= Flag::KgtSignature as u8 {
            return true;
        }
        false
    }

    /// Iterate over all technique flags.
    pub fn all_techniques() -> impl Iterator<Item = Flag> {
        (0..Self::TECHNIQUE_COUNT).map(|i| unsafe { std::mem::transmute::<u8, Flag>(i as u8) })
    }

    /// Default disabled techniques (same as C++ version).
    pub fn default_disabled() -> Vec<Flag> {
        vec![Flag::VmwareDmesg]
    }
}

/// A set of enabled/disabled technique flags, analogous to the C++ flagset (bitset).
#[derive(Clone)]
pub struct FlagSet {
    bits: [bool; Flag::TECHNIQUE_COUNT],
    pub high_threshold: bool,
    pub dynamic: bool,
    pub multiple: bool,
}

impl Default for FlagSet {
    fn default() -> Self {
        Self::new_default()
    }
}

impl FlagSet {
    /// Create a flagset with all default techniques enabled.
    pub fn new_default() -> Self {
        let mut fs = Self {
            bits: [true; Flag::TECHNIQUE_COUNT],
            high_threshold: false,
            dynamic: false,
            multiple: false,
        };
        // Disable default-disabled techniques
        for flag in Flag::default_disabled() {
            fs.disable(flag);
        }
        fs
    }

    /// Create a flagset with ALL techniques enabled (including normally-disabled ones).
    pub fn new_all() -> Self {
        Self {
            bits: [true; Flag::TECHNIQUE_COUNT],
            high_threshold: false,
            dynamic: false,
            multiple: false,
        }
    }

    /// Create a flagset from specific flags only.
    pub fn from_flags(flags: &[Flag]) -> Self {
        let mut fs = Self {
            bits: [false; Flag::TECHNIQUE_COUNT],
            high_threshold: false,
            dynamic: false,
            multiple: false,
        };
        for &f in flags {
            fs.enable(f);
        }
        fs
    }

    pub fn enable(&mut self, flag: Flag) {
        let idx = flag as usize;
        if idx < Flag::TECHNIQUE_COUNT {
            self.bits[idx] = true;
        }
    }

    pub fn disable(&mut self, flag: Flag) {
        let idx = flag as usize;
        if idx < Flag::TECHNIQUE_COUNT {
            self.bits[idx] = false;
        }
    }

    pub fn is_enabled(&self, flag: Flag) -> bool {
        let idx = flag as usize;
        if idx < Flag::TECHNIQUE_COUNT {
            self.bits[idx]
        } else {
            false
        }
    }

    pub fn has_any_technique(&self) -> bool {
        self.bits.iter().any(|&b| b)
    }
}
