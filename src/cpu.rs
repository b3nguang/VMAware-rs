//! CPU operations module — wraps CPUID and related low-level CPU queries.

/// CPUID leaf constants
pub mod leaf {
    pub const FUNC_EXT: u32 = 0x8000_0000;
    pub const PROC_EXT: u32 = 0x8000_0001;
    pub const BRAND1: u32 = 0x8000_0002;
    pub const BRAND2: u32 = 0x8000_0003;
    pub const BRAND3: u32 = 0x8000_0004;
    pub const HYPERVISOR: u32 = 0x4000_0000;
    pub const AMD_EASTER_EGG: u32 = 0x8FFF_FFFF;
}

/// Result of a CPUID call.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Execute CPUID with given leaf and optional subleaf.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    #[cfg(target_arch = "x86_64")]
    {
        let result = unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) };
        CpuidResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        }
    }
    #[cfg(target_arch = "x86")]
    {
        let result = unsafe { std::arch::x86::__cpuid_count(leaf, subleaf) };
        CpuidResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn cpuid(_leaf: u32, _subleaf: u32) -> CpuidResult {
    CpuidResult::default()
}

/// Check if a given CPUID leaf is supported.
pub fn is_leaf_supported(p_leaf: u32) -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if p_leaf < 0x4000_0000 {
            let r = cpuid(0x0000_0000, 0);
            p_leaf <= r.eax
        } else if p_leaf < 0x8000_0000 {
            let r = cpuid(leaf::HYPERVISOR, 0);
            p_leaf <= r.eax
        } else if p_leaf < 0xC000_0000 {
            let r = cpuid(leaf::FUNC_EXT, 0);
            p_leaf <= r.eax
        } else {
            false
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = p_leaf;
        false
    }
}

/// Check if CPU is AMD.
pub fn is_amd() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let r = cpuid(0, 0);
        // "cAMD" in ecx
        r.ecx == 0x444d_4163
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Check if CPU is Intel.
pub fn is_intel() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let r = cpuid(0, 0);
        // "ntel" or "otel" in ecx
        r.ecx == 0x6c65_746e || r.ecx == 0x6c65_746f
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Helper: write a u32 as little-endian bytes into a buffer at the given offset.
fn write_le_u32(buf: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Get the CPU brand string (e.g. "Intel(R) Core(TM) i7-...").
pub fn get_brand() -> String {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if !is_leaf_supported(leaf::BRAND3) {
            return "Unknown".to_string();
        }

        let mut buffer = [0u8; 49];

        let r1 = cpuid(leaf::BRAND1, 0);
        write_le_u32(&mut buffer, 0, r1.eax);
        write_le_u32(&mut buffer, 4, r1.ebx);
        write_le_u32(&mut buffer, 8, r1.ecx);
        write_le_u32(&mut buffer, 12, r1.edx);

        let r2 = cpuid(leaf::BRAND2, 0);
        write_le_u32(&mut buffer, 16, r2.eax);
        write_le_u32(&mut buffer, 20, r2.ebx);
        write_le_u32(&mut buffer, 24, r2.ecx);
        write_le_u32(&mut buffer, 28, r2.edx);

        let r3 = cpuid(leaf::BRAND3, 0);
        write_le_u32(&mut buffer, 32, r3.eax);
        write_le_u32(&mut buffer, 36, r3.ebx);
        write_le_u32(&mut buffer, 40, r3.ecx);
        write_le_u32(&mut buffer, 44, r3.edx);

        buffer[48] = 0;

        let s = String::from_utf8_lossy(&buffer);
        let trimmed = s.trim_start().trim_end_matches('\0');
        trimmed.to_string()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        "Unknown".to_string()
    }
}

/// Get the CPU manufacturer string at a given CPUID leaf.
/// For leaf >= 0x40000000, the order is EBX, ECX, EDX.
/// Otherwise, the order is EBX, EDX, ECX (standard manufacturer ID).
pub fn cpu_manufacturer(leaf_id: u32) -> String {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let r = cpuid(leaf_id, 0);

        if r.ebx == 0 && r.ecx == 0 && r.edx == 0 {
            return String::new();
        }

        let mut buffer = [0u8; 13];

        if leaf_id >= 0x4000_0000 {
            write_le_u32(&mut buffer, 0, r.ebx);
            write_le_u32(&mut buffer, 4, r.ecx);
            write_le_u32(&mut buffer, 8, r.edx);
        } else {
            write_le_u32(&mut buffer, 0, r.ebx);
            write_le_u32(&mut buffer, 4, r.edx);
            write_le_u32(&mut buffer, 8, r.ecx);
        }

        buffer[12] = 0;
        let s = String::from_utf8_lossy(&buffer);
        s.trim_end_matches('\0').to_string()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = leaf_id;
        String::new()
    }
}

/// CPU stepping information.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stepping {
    pub model: u8,
    pub family: u8,
    pub extmodel: u8,
}

/// Fetch CPU stepping/model/family info from CPUID leaf 1.
pub fn fetch_steppings() -> Stepping {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let r = cpuid(1, 0);
        Stepping {
            model: ((r.eax >> 4) & 0xF) as u8,
            family: ((r.eax >> 8) & 0xF) as u8,
            extmodel: ((r.eax >> 16) & 0xF) as u8,
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        Stepping::default()
    }
}
