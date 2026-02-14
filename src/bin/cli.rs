//! VMAware-rs CLI tool.
//! Provides a command-line interface for VM detection.

use vmaware::{VM, VMAwareResult};
use vmaware::flags::{Flag, FlagSet};

fn print_help() {
    println!("VMAware-rs CLI - Virtual Machine Detection Tool");
    println!();
    println!("Usage: vmaware-cli [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -h, --help              Print this help message");
    println!("  -v, --version           Print version information");
    println!("  -d, --detect            Print VM detection result (1 = VM, 0 = baremetal)");
    println!("  -s, --stdout            Return 0 (VM) or 1 (baremetal) to stdout");
    println!("  -b, --brand             Print the most likely VM brand");
    println!("  -l, --brand-list        Print all possible VM brand strings");
    println!("  -c, --conclusion        Print the conclusion message");
    println!("  -p, --percent           Print the VM likeliness percentage (0-100)");
    println!("  -n, --number            Print the number of detection techniques");
    println!("  -t, --type              Print the VM type");
    println!("      --high-threshold    Use a higher detection threshold");
    println!("      --dynamic           Use dynamic conclusion messages");
    println!("      --verbose           Show detailed technique results");
    println!("      --detected-only     Only show detected techniques");
    println!("      --enums             Display technique enum names");
    println!("      --json              Output results as JSON");
}

fn print_version() {
    println!("VMAware-rs v{}", env!("CARGO_PKG_VERSION"));
    println!("Rust port of VMAware (https://github.com/kernelwernel/VMAware)");
    println!("License: MIT");
}

fn print_brand_list() {
    println!("Supported VM brands:");
    for brand in vmaware::brands::all_brands() {
        println!("  {}", brand);
    }
}

fn print_verbose(flags: &FlagSet, detected_only: bool, show_enums: bool) {
    let result = VMAwareResult::new(Some(flags));

    println!("╔══════════════════════════════════════════════╗");
    println!("║         VMAware-rs Detection Results         ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║ VM detected:    {:<28} ║", if result.is_vm { "Yes" } else { "No" });
    println!("║ Brand:          {:<28} ║", result.brand);
    println!("║ Type:           {:<28} ║", result.vm_type);
    println!("║ Percentage:     {:<28} ║", format!("{}%", result.percentage));
    println!("║ Detected count: {:<28} ║", result.detected_count);
    println!("║ Conclusion:     {:<28} ║", result.conclusion);
    println!("╠══════════════════════════════════════════════╣");
    println!("║              Technique Results               ║");
    println!("╠══════════════════════════════════════════════╣");

    for flag in Flag::all_techniques() {
        if !flags.is_enabled(flag) || !flag.is_supported_on_current_platform() {
            continue;
        }

        let detected = VM::check(flag);

        if detected_only && !detected {
            continue;
        }

        let status = if detected { "[+]" } else { "[-]" };
        let name = if show_enums {
            format!("VM::{}", flag.to_str())
        } else {
            flag.to_str().to_string()
        };

        println!("║ {} {:<40} ║", status, name);
    }

    println!("╚══════════════════════════════════════════════╝");
}

fn default_output(flags: &FlagSet) {
    let result = VMAwareResult::new(Some(flags));

    if result.is_vm {
        println!("Virtual machine detected!");
    } else {
        println!("Running on baremetal");
    }

    println!();
    println!("Brand:      {}", result.brand);
    println!("Type:       {}", result.vm_type);
    println!("Percentage: {}%", result.percentage);
    println!("Conclusion: {}", result.conclusion);
    println!();

    println!("Technique results ({} detected out of {}):", result.detected_count, result.technique_count);
    for flag in &result.detected_techniques {
        println!("  [+] VM::{}", flag.to_str());
    }
}

fn print_json(flags: &FlagSet, detected_only: bool) {
    let result = VMAwareResult::new(Some(flags));

    let mut techniques = Vec::new();
    for flag in Flag::all_techniques() {
        if !flags.is_enabled(flag) || !flag.is_supported_on_current_platform() {
            continue;
        }
        let detected = VM::check(flag);
        if detected_only && !detected {
            continue;
        }
        techniques.push(format!(
            "    {{ \"name\": \"{}\", \"detected\": {} }}",
            flag.to_str(),
            detected
        ));
    }

    // Escape any quotes in string fields
    let brand = result.brand.replace('\\', "\\\\").replace('"', "\\\"");
    let vm_type = result.vm_type.replace('\\', "\\\\").replace('"', "\\\"");
    let conclusion = result.conclusion.replace('\\', "\\\\").replace('"', "\\\"");

    println!("{{");
    println!("  \"is_vm\": {},", result.is_vm);
    println!("  \"brand\": \"{}\",", brand);
    println!("  \"type\": \"{}\",", vm_type);
    println!("  \"percentage\": {},", result.percentage);
    println!("  \"detected_count\": {},", result.detected_count);
    println!("  \"technique_count\": {},", result.technique_count);
    println!("  \"conclusion\": \"{}\",", conclusion);
    println!("  \"techniques\": [");
    for (i, t) in techniques.iter().enumerate() {
        if i < techniques.len() - 1 {
            println!("{},", t);
        } else {
            println!("{}", t);
        }
    }
    println!("  ]");
    println!("}}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut flags = FlagSet::new_default();
    let mut action: Option<String> = None;
    let mut verbose = false;
    let mut detected_only = false;
    let mut show_enums = false;
    let mut json_output = false;

    // Parse arguments
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-v" | "--version" => {
                print_version();
                return;
            }
            "-l" | "--brand-list" => {
                print_brand_list();
                return;
            }
            "--high-threshold" => {
                flags.high_threshold = true;
            }
            "--dynamic" => {
                flags.dynamic = true;
            }
            "--verbose" => {
                verbose = true;
            }
            "--detected-only" => {
                detected_only = true;
            }
            "--enums" => {
                show_enums = true;
            }
            "--json" => {
                json_output = true;
            }
            "-d" | "--detect" => action = Some("detect".to_string()),
            "-s" | "--stdout" => action = Some("stdout".to_string()),
            "-b" | "--brand" => action = Some("brand".to_string()),
            "-c" | "--conclusion" => action = Some("conclusion".to_string()),
            "-p" | "--percent" => action = Some("percent".to_string()),
            "-n" | "--number" => action = Some("number".to_string()),
            "-t" | "--type" => action = Some("type".to_string()),
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                eprintln!("Use --help for usage information.");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Execute action
    match action.as_deref() {
        Some("detect") => {
            let detected = VM::detect(Some(&flags));
            println!("{}", if detected { 1 } else { 0 });
        }
        Some("stdout") => {
            let detected = VM::detect(Some(&flags));
            std::process::exit(if detected { 0 } else { 1 });
        }
        Some("brand") => {
            println!("{}", VM::brand(Some(&flags)));
        }
        Some("conclusion") => {
            println!("{}", VM::conclusion(Some(&flags)));
        }
        Some("percent") => {
            println!("{}", VM::percentage(Some(&flags)));
        }
        Some("number") => {
            println!("{}", VM::technique_count());
        }
        Some("type") => {
            println!("{}", VM::vm_type(Some(&flags)));
        }
        _ => {
            if json_output {
                print_json(&flags, detected_only);
            } else if verbose || detected_only {
                print_verbose(&flags, detected_only, show_enums);
            } else {
                default_output(&flags);
            }
        }
    }
}
