//! Utility functions used by VM detection techniques.
//! Includes file I/O, registry access, process checking, OS queries, etc.

use std::path::Path;

/// Check if a string contains a substring (case-insensitive).
pub fn find_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Check if a string contains a substring (case-sensitive).
pub fn find(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

/// Read a file to string, returning None on failure.
pub fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Check if a file exists.
pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Check if a directory exists.
pub fn dir_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// Run a command and capture stdout. Returns None on failure.
pub fn run_command(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
}

/// Get the hostname of the system.
pub fn get_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        run_command("hostname", &[])
            .map(|s| s.trim().to_string())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

/// Get the current username.
pub fn get_username() -> Option<String> {
    #[cfg(unix)]
    {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").ok()
    }
}

/// Get the number of logical CPUs/threads.
pub fn thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ============================== Windows-specific utilities ==============================

#[cfg(target_os = "windows")]
pub mod win {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    /// Convert a Rust string to a wide (UTF-16) null-terminated string.
    pub fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Read a registry string value. Returns None if not found.
    pub fn read_registry_string(hive: &str, subkey: &str, value_name: &str) -> Option<String> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkey = match hive {
            "HKLM" | "HKEY_LOCAL_MACHINE" => RegKey::predef(HKEY_LOCAL_MACHINE),
            "HKCU" | "HKEY_CURRENT_USER" => RegKey::predef(HKEY_CURRENT_USER),
            "HKCR" | "HKEY_CLASSES_ROOT" => RegKey::predef(HKEY_CLASSES_ROOT),
            _ => return None,
        };

        let key = hkey.open_subkey(subkey).ok()?;
        let val: String = key.get_value(value_name).ok()?;
        Some(val)
    }

    /// Enumerate registry subkey names.
    pub fn enum_registry_subkeys(hive: &str, subkey: &str) -> Vec<String> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkey = match hive {
            "HKLM" | "HKEY_LOCAL_MACHINE" => RegKey::predef(HKEY_LOCAL_MACHINE),
            "HKCU" | "HKEY_CURRENT_USER" => RegKey::predef(HKEY_CURRENT_USER),
            _ => return Vec::new(),
        };

        match hkey.open_subkey(subkey) {
            Ok(key) => key.enum_keys().filter_map(|k| k.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Check if a DLL is loaded/available.
    pub fn is_dll_loaded(dll_name: &str) -> bool {
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::core::PCWSTR;

        let wide = to_wide(dll_name);
        unsafe {
            GetModuleHandleW(PCWSTR(wide.as_ptr())).is_ok()
        }
    }

    /// Check if a mutex with the given name exists.
    pub fn mutex_exists(name: &str) -> bool {
        use windows::Win32::System::Threading::OpenMutexW;
        use windows::Win32::System::Threading::SYNCHRONIZATION_ACCESS_RIGHTS;
        use windows::core::PCWSTR;

        let wide = to_wide(name);
        unsafe {
            let result = OpenMutexW(
                SYNCHRONIZATION_ACCESS_RIGHTS(0x00100000), // SYNCHRONIZE
                false,
                PCWSTR(wide.as_ptr()),
            );
            result.is_ok()
        }
    }
}

// ============================== Linux-specific utilities ==============================

#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs;
    use std::path::Path;

    /// Read a sysfs/procfs file to string.
    pub fn read_sys_file(path: &str) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    }

    /// Check if a kernel module is loaded (via /proc/modules).
    pub fn is_module_loaded(module_name: &str) -> bool {
        if let Some(content) = super::read_file("/proc/modules") {
            content.lines().any(|line| {
                line.split_whitespace()
                    .next()
                    .map_or(false, |name| name == module_name)
            })
        } else {
            false
        }
    }

    /// List all running process names from /proc.
    pub fn list_processes() -> Vec<String> {
        let mut procs = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.chars().all(|c| c.is_ascii_digit()) {
                    let comm_path = format!("/proc/{}/comm", name_str);
                    if let Ok(comm) = fs::read_to_string(&comm_path) {
                        procs.push(comm.trim().to_string());
                    }
                }
            }
        }
        procs
    }

    /// Read DMI field from sysfs.
    pub fn read_dmi_field(field: &str) -> Option<String> {
        let path = format!("/sys/devices/virtual/dmi/id/{}", field);
        if Path::new(&path).exists() {
            fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
        } else {
            None
        }
    }

    /// Get MAC address of first non-loopback interface.
    pub fn get_mac_address() -> Option<String> {
        let net_dir = "/sys/class/net";
        if let Ok(entries) = fs::read_dir(net_dir) {
            for entry in entries.flatten() {
                let iface = entry.file_name().to_string_lossy().to_string();
                if iface == "lo" {
                    continue;
                }
                let addr_path = format!("{}/{}/address", net_dir, iface);
                if let Ok(addr) = fs::read_to_string(&addr_path) {
                    let addr = addr.trim().to_string();
                    if !addr.is_empty() && addr != "00:00:00:00:00:00" {
                        return Some(addr);
                    }
                }
            }
        }
        None
    }
}

// ============================== macOS-specific utilities ==============================

#[cfg(target_os = "macos")]
pub mod macos {
    /// Run sysctl and return the value as string.
    pub fn sysctl_string(key: &str) -> Option<String> {
        super::run_command("sysctl", &["-n", key])
            .map(|s| s.trim().to_string())
    }

    /// Run system_profiler to get hardware info.
    pub fn system_profiler(data_type: &str) -> Option<String> {
        super::run_command("system_profiler", &[data_type])
    }

    /// Run ioreg and return output.
    pub fn ioreg(args: &[&str]) -> Option<String> {
        super::run_command("ioreg", args)
    }
}
