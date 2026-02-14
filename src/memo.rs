//! Memoization / caching module.
//! Caches technique results, brand strings, CPU brand, and other computed values
//! to avoid re-running expensive detection logic.

use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::flags::Flag;
use crate::brands;

/// Cached data for a single technique result.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub has_value: bool,
    pub result: bool,
    pub points: u8,
    pub brand_name: &'static str,
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self {
            has_value: false,
            result: false,
            points: 0,
            brand_name: brands::NULL_BRAND,
        }
    }
}

/// Global technique result cache table.
pub static CACHE_TABLE: Lazy<Mutex<Vec<CacheEntry>>> = Lazy::new(|| {
    let mut v = Vec::with_capacity(Flag::TECHNIQUE_COUNT);
    v.resize_with(Flag::TECHNIQUE_COUNT, CacheEntry::default);
    Mutex::new(v)
});

/// Check if a technique result is cached.
pub fn is_cached(flag: Flag) -> bool {
    let idx = flag as usize;
    if idx >= Flag::TECHNIQUE_COUNT {
        return false;
    }
    let table = CACHE_TABLE.lock().unwrap();
    table[idx].has_value
}

/// Fetch cached technique data.
pub fn cache_fetch(flag: Flag) -> CacheEntry {
    let idx = flag as usize;
    let table = CACHE_TABLE.lock().unwrap();
    if idx < table.len() {
        table[idx].clone()
    } else {
        CacheEntry::default()
    }
}

/// Store a technique result in cache.
pub fn cache_store(flag: Flag, result: bool, points: u8, brand_name: &'static str) {
    let idx = flag as usize;
    let mut table = CACHE_TABLE.lock().unwrap();
    if idx < table.len() {
        table[idx] = CacheEntry {
            has_value: true,
            result,
            points,
            brand_name,
        };
    }
}

/// Brand cache (single best brand).
pub static BRAND_CACHE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub fn brand_is_cached() -> bool {
    BRAND_CACHE.lock().unwrap().is_some()
}

pub fn brand_fetch() -> String {
    BRAND_CACHE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| brands::NULL_BRAND.to_string())
}

pub fn brand_store(brand: &str) {
    *BRAND_CACHE.lock().unwrap() = Some(brand.to_string());
}

/// Multi-brand cache (for VM::MULTIPLE).
pub static MULTI_BRAND_CACHE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub fn multi_brand_is_cached() -> bool {
    MULTI_BRAND_CACHE.lock().unwrap().is_some()
}

pub fn multi_brand_fetch() -> String {
    MULTI_BRAND_CACHE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| brands::NULL_BRAND.to_string())
}

pub fn multi_brand_store(brand: &str) {
    *MULTI_BRAND_CACHE.lock().unwrap() = Some(brand.to_string());
}

/// CPU brand string cache.
pub static CPU_BRAND_CACHE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub fn cpu_brand_is_cached() -> bool {
    CPU_BRAND_CACHE.lock().unwrap().is_some()
}

pub fn cpu_brand_fetch() -> String {
    CPU_BRAND_CACHE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "Unknown".to_string())
}

pub fn cpu_brand_store(brand: &str) {
    *CPU_BRAND_CACHE.lock().unwrap() = Some(brand.to_string());
}

/// Conclusion message cache.
pub static CONCLUSION_CACHE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub fn conclusion_is_cached() -> bool {
    CONCLUSION_CACHE.lock().unwrap().is_some()
}

pub fn conclusion_fetch() -> String {
    CONCLUSION_CACHE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_default()
}

pub fn conclusion_store(msg: &str) {
    *CONCLUSION_CACHE.lock().unwrap() = Some(msg.to_string());
}

/// Hardened result cache.
pub static HARDENED_CACHE: Lazy<Mutex<Option<bool>>> = Lazy::new(|| Mutex::new(None));

pub fn hardened_is_cached() -> bool {
    HARDENED_CACHE.lock().unwrap().is_some()
}

pub fn hardened_fetch() -> bool {
    HARDENED_CACHE.lock().unwrap().unwrap_or(false)
}

pub fn hardened_store(val: bool) {
    *HARDENED_CACHE.lock().unwrap() = Some(val);
}

/// Hyper-V state cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervState {
    Unknown,
    RealVm,
    ArtifactVm,
    Enlightenment,
}

pub static HYPERV_CACHE: Lazy<Mutex<Option<HypervState>>> = Lazy::new(|| Mutex::new(None));

pub fn hyperv_is_cached() -> bool {
    HYPERV_CACHE.lock().unwrap().is_some()
}

pub fn hyperv_fetch() -> HypervState {
    HYPERV_CACHE
        .lock()
        .unwrap()
        .unwrap_or(HypervState::Unknown)
}

pub fn hyperv_store(state: HypervState) {
    *HYPERV_CACHE.lock().unwrap() = Some(state);
}

/// Reset all caches (useful for testing).
pub fn reset_all() {
    {
        let mut table = CACHE_TABLE.lock().unwrap();
        for entry in table.iter_mut() {
            *entry = CacheEntry::default();
        }
    }
    *BRAND_CACHE.lock().unwrap() = None;
    *MULTI_BRAND_CACHE.lock().unwrap() = None;
    *CPU_BRAND_CACHE.lock().unwrap() = None;
    *CONCLUSION_CACHE.lock().unwrap() = None;
    *HARDENED_CACHE.lock().unwrap() = None;
    *HYPERV_CACHE.lock().unwrap() = None;
}
