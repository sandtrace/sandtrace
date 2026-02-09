use crate::event::ProcessInfo;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct ProcessTree {
    cache: HashMap<i32, CachedProcess>,
    cache_ttl: Duration,
}

struct CachedProcess {
    info: ProcessInfo,
    fetched_at: Instant,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(5),
        }
    }

    pub fn lookup(&mut self, pid: i32) -> Option<ProcessInfo> {
        if let Some(cached) = self.cache.get(&pid) {
            if cached.fetched_at.elapsed() < self.cache_ttl {
                return Some(cached.info.clone());
            }
        }

        let info = read_process_info(pid)?;
        self.cache.insert(
            pid,
            CachedProcess {
                info: info.clone(),
                fetched_at: Instant::now(),
            },
        );
        Some(info)
    }

    pub fn lineage(&mut self, pid: i32) -> Vec<ProcessInfo> {
        let mut chain = Vec::new();
        let mut current_pid = pid;

        for _ in 0..64 {
            if current_pid <= 1 {
                break;
            }

            if let Some(info) = self.lookup(current_pid) {
                let next_pid = info.ppid;
                chain.push(info);
                current_pid = next_pid;
            } else {
                break;
            }
        }

        chain
    }

    pub fn evict_stale(&mut self) {
        self.cache
            .retain(|_, v| v.fetched_at.elapsed() < self.cache_ttl * 4);
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}

fn read_process_info(pid: i32) -> Option<ProcessInfo> {
    let proc = procfs::process::Process::new(pid).ok()?;
    let status = proc.status().ok()?;
    let cmdline = proc.cmdline().unwrap_or_default();
    let exe_path = proc.exe().ok().map(|p| p.to_string_lossy().to_string());

    Some(ProcessInfo {
        pid,
        ppid: status.ppid,
        name: status.name,
        exe_path,
        cmdline,
        uid: status.ruid,
    })
}

pub fn get_process_name(pid: i32) -> Option<String> {
    let proc = procfs::process::Process::new(pid).ok()?;
    let status = proc.status().ok()?;
    Some(status.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_self_process() {
        let pid = std::process::id() as i32;
        let info = read_process_info(pid);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty());
    }

    #[test]
    fn test_process_tree_lineage() {
        let pid = std::process::id() as i32;
        let mut tree = ProcessTree::new();
        let lineage = tree.lineage(pid);
        assert!(!lineage.is_empty());
        assert_eq!(lineage[0].pid, pid);
    }
}
