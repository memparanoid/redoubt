// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#!/usr/bin/env rust-script
//! Generate dependency graphs and code snapshots for all workspace crates
//!
//! This tool:
//! 1. Discovers all crates in the workspace
//! 2. Generates dependency graphs using dep_graph_rs
//! 3. Parses graphs to identify entry points
//! 4. Partitions code into reviewable snapshots (~1500 LOC each)
//!
//! Output structure mirrors crates/:
//! - .claude/graphs/memcode/core/graph.dot
//! - .claude/snapshots/memcode/core/index.snap
//! - .claude/snapshots/memcode/core/part1.snap

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_SNAPSHOT_LOC: usize = 1500;

fn main() {
    let workspace_root = find_workspace_root();

    println!("🧹 Cleaning previous artifacts...");
    clean_artifacts(&workspace_root);

    println!("🔍 Discovering workspace crates...");
    let crates = discover_crates(&workspace_root);

    println!("📊 Found {} crates", crates.len());
    for crate_info in &crates {
        println!("  - {}", crate_info.relative_path);
    }

    println!("\n📈 Generating dependency graphs...");
    generate_all_graphs(&workspace_root, &crates);

    println!("\n📦 Generating snapshots...");
    generate_all_snapshots(&workspace_root, &crates);

    println!("\n✅ Done!");
}

fn clean_artifacts(workspace_root: &Path) {
    let graphs_dir = workspace_root.join(".claude/graphs");
    let snapshots_dir = workspace_root.join(".claude/snapshots");

    if graphs_dir.exists() {
        let _ = fs::remove_dir_all(&graphs_dir);
    }

    if snapshots_dir.exists() {
        let _ = fs::remove_dir_all(&snapshots_dir);
    }
}

fn find_workspace_root() -> PathBuf {
    // Start from current dir and walk up to find workspace Cargo.toml
    let mut current = std::env::current_dir().unwrap();

    loop {
        let cargo_toml = current.join("Cargo.toml");

        if cargo_toml.exists() {
            // Check if it's a workspace
            if let Ok(content) = fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return current;
                }
            }
        }

        // Go up one level
        if !current.pop() {
            panic!("Could not find workspace root");
        }
    }
}

#[derive(Debug, Clone)]
struct CrateInfo {
    name: String,
    relative_path: String,  // e.g., "memcode/core"
    lib_path: PathBuf,      // Full path to src/lib.rs
    src_dir: PathBuf,       // Full path to src/
}

fn discover_crates(workspace_root: &Path) -> Vec<CrateInfo> {
    let crates_dir = workspace_root.join("crates");

    read_dir_entries(&crates_dir)
        .into_iter()
        .flat_map(|entry| discover_crate_recursive(&entry, &crates_dir))
        .collect()
}

fn discover_crate_recursive(path: &Path, base: &Path) -> Vec<CrateInfo> {
    if !path.is_dir() {
        return vec![];
    }

    let mut result = Vec::new();
    let cargo_toml = path.join("Cargo.toml");
    let lib_rs = path.join("src/lib.rs");

    // Check if this is a crate (has Cargo.toml and src/lib.rs)
    if cargo_toml.exists() && lib_rs.exists() {
        let relative = path.strip_prefix(base).unwrap().to_path_buf();
        let name = extract_crate_name(&cargo_toml).unwrap_or_else(|| {
            relative.to_string_lossy().replace("/", "-")
        });

        result.push(CrateInfo {
            name,
            relative_path: relative.to_string_lossy().to_string(),
            lib_path: lib_rs,
            src_dir: path.join("src"),
        });
    }

    // Recurse into subdirectories
    for sub_entry in read_dir_entries(path) {
        result.extend(discover_crate_recursive(&sub_entry, base));
    }

    result
}

fn read_dir_entries(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}

fn extract_crate_name(cargo_toml: &Path) -> Option<String> {
    let content = fs::read_to_string(cargo_toml).ok()?;
    content
        .lines()
        .find(|line| line.starts_with("name"))
        .and_then(|line| line.split('=').nth(1))
        .map(|s| s.trim().trim_matches('"').to_string())
}

fn generate_all_graphs(workspace_root: &Path, crates: &[CrateInfo]) {
    let graphs_dir = workspace_root.join(".claude/graphs");

    for crate_info in crates {
        let output_dir = graphs_dir.join(&crate_info.relative_path);
        let output_file = output_dir.join("graph.dot");

        create_dir_all(&output_dir);

        println!("  Generating graph for {}...", crate_info.relative_path);

        let success = run_dep_graph_rs(&crate_info.lib_path, &output_file);

        if success {
            println!("    ✓ Written to {}", output_file.display());
        } else {
            println!("    ✗ Failed to generate graph");
        }
    }
}

fn run_dep_graph_rs(lib_path: &Path, output: &Path) -> bool {
    let result = Command::new("dep_graph_rs")
        .arg(lib_path)
        .arg("--mode")
        .arg("file")
        .output();

    match result {
        Ok(output_data) if output_data.status.success() => {
            fs::write(output, output_data.stdout).is_ok()
        }
        _ => false,
    }
}

fn create_dir_all(path: &Path) {
    let _ = fs::create_dir_all(path);
}

fn generate_all_snapshots(workspace_root: &Path, crates: &[CrateInfo]) {
    let graphs_dir = workspace_root.join(".claude/graphs");
    let snapshots_dir = workspace_root.join(".claude/snapshots");

    for crate_info in crates {
        let graph_file = graphs_dir.join(&crate_info.relative_path).join("graph.dot");
        let snapshot_dir = snapshots_dir.join(&crate_info.relative_path);

        if !graph_file.exists() {
            println!("  ⚠ Skipping {} (no graph found)", crate_info.relative_path);
            continue;
        }

        println!("  Processing {}...", crate_info.relative_path);

        create_dir_all(&snapshot_dir);

        // Collect all .rs files from src directory
        let all_files = collect_all_rust_files(&crate_info.src_dir);

        let graph_content = fs::read_to_string(&graph_file).unwrap();
        let edges = parse_dot_edges(&graph_content);
        let entry_points = find_entry_points(&edges);

        println!("    Found {} files, {} edges, {} entry points",
                 all_files.len(), edges.len(), entry_points.len());

        let partitions = partition_files(&all_files, &edges, &entry_points, &crate_info.src_dir);

        let total_loc: usize = partitions.iter()
            .flat_map(|p| p.iter())
            .map(|f| count_loc(f))
            .sum();
        println!("    Total LOC: {}, {} partitions", total_loc, partitions.len());

        write_snapshots(&snapshot_dir, &partitions, crate_info);
    }
}

fn collect_all_rust_files(src_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files_recursive(src_dir, &mut files);
    files
}

fn collect_rust_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in read_dir_entries(dir) {
        if entry.is_file() && entry.extension().map(|e| e == "rs").unwrap_or(false) {
            files.push(entry);
        } else if entry.is_dir() {
            collect_rust_files_recursive(&entry, files);
        }
    }
}

fn parse_dot_edges(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter(|line| line.contains("->") && !line.contains("lhead"))
        .filter_map(parse_edge_line)
        .collect()
}

fn parse_edge_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.split("->").collect();

    if parts.len() != 2 {
        return None;
    }

    let source = extract_node(parts[0])?;
    let dest = extract_node(parts[1].split('[').next()?)?;

    Some((source, dest))
}

fn extract_node(s: &str) -> Option<String> {
    let trimmed = s.trim().trim_matches('"');
    if trimmed.is_empty() {
        Some(String::new())
    } else {
        Some(trimmed.to_string())
    }
}

fn find_entry_points(edges: &[(String, String)]) -> Vec<String> {
    let incoming: HashSet<_> = edges.iter().map(|(_, dest)| dest.clone()).collect();
    let outgoing: HashSet<_> = edges.iter().map(|(src, _)| src.clone()).collect();

    // Entry points: nodes that appear as source but never as destination (except from "")
    edges
        .iter()
        .filter(|(src, _)| src.is_empty())
        .map(|(_, dest)| dest.clone())
        .filter(|dest| !incoming.contains(dest) || outgoing.contains(&String::new()))
        .collect()
}

fn partition_files(
    all_files: &[PathBuf],
    edges: &[(String, String)],
    entry_points: &[String],
    src_dir: &Path,
) -> Vec<Vec<PathBuf>> {
    let graph = build_adjacency_list(edges);
    let mut ordered_files = Vec::new();
    let mut visited = HashSet::new();

    // First, traverse graph to get dependency order
    for entry in entry_points {
        let mut queue = VecDeque::new();
        queue.push_back(entry.clone());

        while let Some(node) = queue.pop_front() {
            if visited.contains(&node) {
                continue;
            }
            visited.insert(node.clone());

            if let Some(file_path) = extract_file_path(&node, src_dir) {
                if !ordered_files.contains(&file_path) {
                    ordered_files.push(file_path);
                }
            }

            if let Some(neighbors) = graph.get(&node) {
                for neighbor in neighbors {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    // Add any files not in the dependency graph
    for file in all_files {
        if !ordered_files.contains(file) {
            ordered_files.push(file.clone());
        }
    }

    // Now partition by size
    let mut partitions = Vec::new();
    let mut current_partition = Vec::new();
    let mut current_loc = 0;

    for file_path in ordered_files {
        let loc = count_loc(&file_path);

        if current_loc + loc > MAX_SNAPSHOT_LOC && !current_partition.is_empty() {
            partitions.push(current_partition);
            current_partition = Vec::new();
            current_loc = 0;
        }

        current_partition.push(file_path);
        current_loc += loc;
    }

    if !current_partition.is_empty() {
        partitions.push(current_partition);
    }

    partitions
}

fn build_adjacency_list(edges: &[(String, String)]) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

    for (src, dest) in edges {
        graph.entry(src.clone()).or_default().push(dest.clone());
    }

    graph
}

fn extract_file_path(node: &str, src_dir: &Path) -> Option<PathBuf> {
    if node.is_empty() || !node.ends_with(".rs") {
        return None;
    }

    // Extract filename from full path in node
    let path = Path::new(node);
    let filename = path.file_name()?;

    // Look for file in src_dir
    find_file_recursive(src_dir, filename.to_str()?)
}

fn find_file_recursive(dir: &Path, filename: &str) -> Option<PathBuf> {
    for entry in read_dir_entries(dir) {
        if entry.is_file() && entry.file_name().map(|n| n == filename).unwrap_or(false) {
            return Some(entry);
        }

        if entry.is_dir() {
            if let Some(found) = find_file_recursive(&entry, filename) {
                return Some(found);
            }
        }
    }

    None
}

fn count_loc(file: &Path) -> usize {
    fs::read_to_string(file)
        .map(|content| content.lines().count())
        .unwrap_or(0)
}

fn write_snapshots(output_dir: &Path, partitions: &[Vec<PathBuf>], crate_info: &CrateInfo) {
    if partitions.is_empty() {
        return;
    }

    // If only one partition, no need for splitting
    if partitions.len() == 1 {
        write_single_snapshot(output_dir, &partitions[0], crate_info);
        return;
    }

    // Multiple partitions: create index + parts
    write_index_snapshot(output_dir, partitions.len(), crate_info);

    for (i, partition) in partitions.iter().enumerate() {
        let part_file = output_dir.join(format!("part{}.snap", i + 1));
        write_partition_snapshot(&part_file, partition, crate_info, i + 1);
    }
}

fn write_single_snapshot(output_dir: &Path, files: &[PathBuf], crate_info: &CrateInfo) {
    let snapshot_file = output_dir.join("snapshot.snap");
    let content = format_snapshot(files, crate_info, None);
    let _ = fs::write(snapshot_file, content);
    println!("    ✓ Single snapshot (no split needed)");
}

fn write_index_snapshot(output_dir: &Path, num_parts: usize, crate_info: &CrateInfo) {
    let index_file = output_dir.join("index.snap");
    let mut content = format!("# {} - Snapshot Index\n\n", crate_info.name);
    content.push_str("This crate has been split into multiple parts for review.\n\n");
    content.push_str("**IMPORTANT**: Read ALL parts proactively before starting the review.\n\n");
    content.push_str("Parts:\n\n");

    for i in 1..=num_parts {
        let part_path = output_dir.join(format!("part{}.snap", i));
        content.push_str(&format!("- {}\n", part_path.display()));
    }

    let _ = fs::write(index_file, content);
    println!("    ✓ Index snapshot + {} parts", num_parts);
}

fn write_partition_snapshot(
    file: &Path,
    files: &[PathBuf],
    crate_info: &CrateInfo,
    part_num: usize,
) {
    let content = format_snapshot(files, crate_info, Some(part_num));
    let _ = fs::write(file, content);
}

fn format_snapshot(files: &[PathBuf], crate_info: &CrateInfo, part: Option<usize>) -> String {
    let mut output = String::new();

    // Header
    let part_str = match part {
        Some(n) => format!(" (Part {})", n),
        None => String::new(),
    };

    // Get current timestamp in UTC
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let datetime = format_timestamp(now);

    output.push_str(&format!("# Crate: {}{}\n", crate_info.name, part_str));
    output.push_str(&format!("# Generated: {}\n", datetime));
    output.push_str("# Format: Optimized (compact headers, no padding, empty lines removed)\n");
    output.push_str(&format!("# All file paths below are relative to: crates/{}/\n", crate_info.relative_path));

    // Process each file
    for file in files {
        // Strip the src_dir prefix to get relative path within src/
        let relative = if let Ok(rel) = file.strip_prefix(&crate_info.src_dir) {
            PathBuf::from("src").join(rel)
        } else {
            file.clone()
        };

        output.push_str(&format!("\n=== {} ===\n", relative.display()));

        if let Ok(content) = fs::read_to_string(file) {
            format_file_content(&content, &mut output);
        }
    }

    output
}

fn format_timestamp(unix_seconds: u64) -> String {
    // Simple UTC timestamp formatting without external dependencies
    const SECONDS_PER_DAY: u64 = 86400;

    let days_since_epoch = unix_seconds / SECONDS_PER_DAY;
    let seconds_today = unix_seconds % SECONDS_PER_DAY;

    let hours = seconds_today / 3600;
    let minutes = (seconds_today % 3600) / 60;
    let seconds = seconds_today % 60;

    // Calculate year, month, day from Unix epoch (1970-01-01)
    let mut year = 1970;
    let mut days_left = days_since_epoch;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days_left < days_in_year {
            break;
        }
        days_left -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &month_days {
        if days_left < days_in_month {
            break;
        }
        days_left -= days_in_month;
        month += 1;
    }

    let day = days_left + 1;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn format_file_content(content: &str, output: &mut String) {
    let mut line_num = 1;

    for line in content.lines() {
        // Skip empty lines
        if line.trim().is_empty() {
            line_num += 1;
            continue;
        }

        // Write line number and content
        output.push_str(&format!("{:<5}{}\n", line_num, line));
        line_num += 1;
    }
}
