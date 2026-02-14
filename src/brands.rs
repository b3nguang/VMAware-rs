//! Official aliases for VM brands.
//! Using constants avoids typos and enables pointer-based comparison.

pub const NULL_BRAND: &str = "Unknown";
pub const VBOX: &str = "VirtualBox";
pub const VMWARE: &str = "VMware";
pub const VMWARE_EXPRESS: &str = "VMware Express";
pub const VMWARE_ESX: &str = "VMware ESX";
pub const VMWARE_GSX: &str = "VMware GSX";
pub const VMWARE_WORKSTATION: &str = "VMware Workstation";
pub const VMWARE_FUSION: &str = "VMware Fusion";
pub const VMWARE_HARD: &str = "VMware (with VmwareHardenedLoader)";
pub const BHYVE: &str = "bhyve";
pub const KVM: &str = "KVM";
pub const QEMU: &str = "QEMU";
pub const QEMU_KVM: &str = "QEMU+KVM";
pub const KVM_HYPERV: &str = "KVM Hyper-V Enlightenment";
pub const QEMU_KVM_HYPERV: &str = "QEMU+KVM Hyper-V Enlightenment";
pub const HYPERV: &str = "Microsoft Hyper-V";
pub const HYPERV_VPC: &str = "Microsoft Virtual PC/Hyper-V";
pub const PARALLELS: &str = "Parallels";
pub const XEN: &str = "Xen HVM";
pub const ACRN: &str = "ACRN";
pub const QNX: &str = "QNX hypervisor";
pub const HYBRID: &str = "Hybrid Analysis";
pub const SANDBOXIE: &str = "Sandboxie";
pub const DOCKER: &str = "Docker";
pub const WINE: &str = "Wine";
pub const VPC: &str = "Virtual PC";
pub const ANUBIS: &str = "Anubis";
pub const JOEBOX: &str = "JoeBox";
pub const THREATEXPERT: &str = "ThreatExpert";
pub const CWSANDBOX: &str = "CWSandbox";
pub const COMODO: &str = "Comodo";
pub const BOCHS: &str = "Bochs";
pub const NVMM: &str = "NetBSD NVMM";
pub const BSD_VMM: &str = "OpenBSD VMM";
pub const INTEL_HAXM: &str = "Intel HAXM";
pub const UNISYS: &str = "Unisys s-Par";
pub const LMHS: &str = "Lockheed Martin LMHS";
pub const CUCKOO: &str = "Cuckoo";
pub const BLUESTACKS: &str = "BlueStacks";
pub const JAILHOUSE: &str = "Jailhouse";
pub const APPLE_VZ: &str = "Apple VZ";
pub const INTEL_KGT: &str = "Intel KGT (Trusty)";
pub const AZURE_HYPERV: &str = "Microsoft Azure Hyper-V";
pub const SIMPLEVISOR: &str = "SimpleVisor";
pub const HYPERV_ARTIFACT: &str = "Hyper-V artifact (host running Hyper-V)";
pub const UML: &str = "User-mode Linux";
pub const POWERVM: &str = "IBM PowerVM";
pub const GCE: &str = "Google Compute Engine (KVM)";
pub const OPENSTACK: &str = "OpenStack (KVM)";
pub const KUBEVIRT: &str = "KubeVirt (KVM)";
pub const AWS_NITRO: &str = "AWS Nitro System EC2 (KVM-based)";
pub const PODMAN: &str = "Podman";
pub const WSL: &str = "WSL";
pub const OPENVZ: &str = "OpenVZ";
pub const BAREVISOR: &str = "Barevisor";
pub const HYPERPLATFORM: &str = "HyperPlatform";
pub const MINIVISOR: &str = "MiniVisor";
pub const INTEL_TDX: &str = "Intel TDX";
pub const LKVM: &str = "LKVM";
pub const AMD_SEV: &str = "AMD SEV";
pub const AMD_SEV_ES: &str = "AMD SEV-ES";
pub const AMD_SEV_SNP: &str = "AMD SEV-SNP";
pub const NEKO_PROJECT: &str = "Neko Project II";
pub const NOIRVISOR: &str = "NoirVisor";
pub const QIHOO: &str = "Qihoo 360 Sandbox";
pub const NSJAIL: &str = "nsjail";
pub const DBVM: &str = "DBVM";
pub const UTM: &str = "UTM";

/// Returns a list of all known brand strings (used for scoreboard initialization).
pub fn all_brands() -> Vec<&'static str> {
    vec![
        VBOX, VMWARE, VMWARE_EXPRESS, VMWARE_ESX, VMWARE_GSX,
        VMWARE_WORKSTATION, VMWARE_FUSION, VMWARE_HARD, BHYVE, KVM,
        QEMU, QEMU_KVM, KVM_HYPERV, QEMU_KVM_HYPERV, HYPERV,
        HYPERV_VPC, PARALLELS, XEN, ACRN, QNX, HYBRID, SANDBOXIE,
        DOCKER, WINE, VPC, ANUBIS, JOEBOX, THREATEXPERT, CWSANDBOX,
        COMODO, BOCHS, NVMM, BSD_VMM, INTEL_HAXM, UNISYS, LMHS,
        CUCKOO, BLUESTACKS, JAILHOUSE, APPLE_VZ, INTEL_KGT,
        AZURE_HYPERV, SIMPLEVISOR, HYPERV_ARTIFACT, UML, POWERVM,
        GCE, OPENSTACK, KUBEVIRT, AWS_NITRO, PODMAN, WSL, OPENVZ,
        BAREVISOR, HYPERPLATFORM, MINIVISOR, INTEL_TDX, LKVM,
        AMD_SEV, AMD_SEV_ES, AMD_SEV_SNP, NEKO_PROJECT, QIHOO,
        NOIRVISOR, NSJAIL, DBVM, UTM, NULL_BRAND,
    ]
}

/// Returns the VM type string for a given brand.
pub fn brand_to_type(brand: &str) -> &'static str {
    match brand {
        // Type 1
        b if std::ptr::eq(b, XEN) || b == XEN => "Hypervisor (type 1)",
        b if std::ptr::eq(b, VMWARE_ESX) || b == VMWARE_ESX => "Hypervisor (type 1)",
        b if std::ptr::eq(b, ACRN) || b == ACRN => "Hypervisor (type 1)",
        b if std::ptr::eq(b, QNX) || b == QNX => "Hypervisor (type 1)",
        b if std::ptr::eq(b, AZURE_HYPERV) || b == AZURE_HYPERV => "Hypervisor (type 1)",
        b if std::ptr::eq(b, KVM) || b == KVM => "Hypervisor (type 1)",
        b if std::ptr::eq(b, KVM_HYPERV) || b == KVM_HYPERV => "Hypervisor (type 1)",
        b if std::ptr::eq(b, QEMU_KVM_HYPERV) || b == QEMU_KVM_HYPERV => "Hypervisor (type 1)",
        b if std::ptr::eq(b, QEMU_KVM) || b == QEMU_KVM => "Hypervisor (type 1)",
        b if std::ptr::eq(b, INTEL_KGT) || b == INTEL_KGT => "Hypervisor (type 1)",
        b if std::ptr::eq(b, SIMPLEVISOR) || b == SIMPLEVISOR => "Hypervisor (type 1)",
        b if std::ptr::eq(b, OPENSTACK) || b == OPENSTACK => "Hypervisor (type 1)",
        b if std::ptr::eq(b, KUBEVIRT) || b == KUBEVIRT => "Hypervisor (type 1)",
        b if std::ptr::eq(b, POWERVM) || b == POWERVM => "Hypervisor (type 1)",
        b if std::ptr::eq(b, AWS_NITRO) || b == AWS_NITRO => "Hypervisor (type 1)",
        b if std::ptr::eq(b, LKVM) || b == LKVM => "Hypervisor (type 1)",
        b if std::ptr::eq(b, NOIRVISOR) || b == NOIRVISOR => "Hypervisor (type 1)",
        b if std::ptr::eq(b, WSL) || b == WSL => "Hypervisor (Type 1)",
        b if std::ptr::eq(b, DBVM) || b == DBVM => "Hypervisor (Type 1)",

        // Type 2
        b if std::ptr::eq(b, HYPERV) || b == HYPERV => "Hypervisor (type 2)",
        b if std::ptr::eq(b, BHYVE) || b == BHYVE => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VBOX) || b == VBOX => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VMWARE) || b == VMWARE => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VMWARE_EXPRESS) || b == VMWARE_EXPRESS => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VMWARE_GSX) || b == VMWARE_GSX => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VMWARE_WORKSTATION) || b == VMWARE_WORKSTATION => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VMWARE_FUSION) || b == VMWARE_FUSION => "Hypervisor (type 2)",
        b if std::ptr::eq(b, PARALLELS) || b == PARALLELS => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VPC) || b == VPC => "Hypervisor (type 2)",
        b if std::ptr::eq(b, NVMM) || b == NVMM => "Hypervisor (type 2)",
        b if std::ptr::eq(b, BSD_VMM) || b == BSD_VMM => "Hypervisor (type 2)",
        b if std::ptr::eq(b, HYPERV_VPC) || b == HYPERV_VPC => "Hypervisor (type 2)",
        b if std::ptr::eq(b, VMWARE_HARD) || b == VMWARE_HARD => "Hypervisor (type 2)",
        b if std::ptr::eq(b, UTM) || b == UTM => "Hypervisor (type 2)",
        b if std::ptr::eq(b, INTEL_HAXM) || b == INTEL_HAXM => "Hosted hypervisor / accelerator (type 2)",

        // Sandbox
        b if std::ptr::eq(b, CUCKOO) || b == CUCKOO => "Sandbox",
        b if std::ptr::eq(b, SANDBOXIE) || b == SANDBOXIE => "Sandbox",
        b if std::ptr::eq(b, HYBRID) || b == HYBRID => "Sandbox",
        b if std::ptr::eq(b, CWSANDBOX) || b == CWSANDBOX => "Sandbox",
        b if std::ptr::eq(b, JOEBOX) || b == JOEBOX => "Sandbox",
        b if std::ptr::eq(b, ANUBIS) || b == ANUBIS => "Sandbox",
        b if std::ptr::eq(b, COMODO) || b == COMODO => "Sandbox",
        b if std::ptr::eq(b, THREATEXPERT) || b == THREATEXPERT => "Sandbox",
        b if std::ptr::eq(b, QIHOO) || b == QIHOO => "Sandbox",

        // Misc
        b if std::ptr::eq(b, BOCHS) || b == BOCHS => "Emulator",
        b if std::ptr::eq(b, BLUESTACKS) || b == BLUESTACKS => "Emulator",
        b if std::ptr::eq(b, NEKO_PROJECT) || b == NEKO_PROJECT => "Emulator",
        b if std::ptr::eq(b, QEMU) || b == QEMU => "Emulator/Hypervisor (type 2)",
        b if std::ptr::eq(b, JAILHOUSE) || b == JAILHOUSE => "Partitioning Hypervisor",
        b if std::ptr::eq(b, UNISYS) || b == UNISYS => "Partitioning Hypervisor",
        b if std::ptr::eq(b, DOCKER) || b == DOCKER => "Container",
        b if std::ptr::eq(b, PODMAN) || b == PODMAN => "Container",
        b if std::ptr::eq(b, OPENVZ) || b == OPENVZ => "Container",
        b if std::ptr::eq(b, LMHS) || b == LMHS => "Hypervisor (unknown type)",
        b if std::ptr::eq(b, WINE) || b == WINE => "Compatibility layer",
        b if std::ptr::eq(b, INTEL_TDX) || b == INTEL_TDX => "Trusted Domain",
        b if std::ptr::eq(b, UML) || b == UML => "Paravirtualised/Hypervisor (type 2)",
        b if std::ptr::eq(b, AMD_SEV) || b == AMD_SEV => "VM encryptor",
        b if std::ptr::eq(b, AMD_SEV_ES) || b == AMD_SEV_ES => "VM encryptor",
        b if std::ptr::eq(b, AMD_SEV_SNP) || b == AMD_SEV_SNP => "VM encryptor",
        b if std::ptr::eq(b, GCE) || b == GCE => "Cloud VM service",
        b if std::ptr::eq(b, NSJAIL) || b == NSJAIL => "Process isolator",
        _ => "Unknown",
    }
}
