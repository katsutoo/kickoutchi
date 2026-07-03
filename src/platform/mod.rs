//! Home of the platform-specific collectors.

use crate::model::{ProcessContext, RelatedProcessHint};

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(windows)]
pub(crate) mod windows;

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    #[cfg(target_os = "linux")]
    {
        linux::collect_process_context(pid)
    }

    #[cfg(windows)]
    {
        windows::collect_process_context(pid)
    }

    #[cfg(target_os = "macos")]
    {
        macos::collect_process_context(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        ProcessContext::default()
    }
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    #[cfg(target_os = "linux")]
    {
        linux::collect_related_process_hints(port)
    }

    #[cfg(windows)]
    {
        windows::collect_related_process_hints(port)
    }

    #[cfg(target_os = "macos")]
    {
        macos::collect_related_process_hints(port)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = port;
        Vec::new()
    }
}

/// Best-effort command line for one PID, for the read-only inspect view.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn process_command_line(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux::process_command_line(pid)
    }

    #[cfg(target_os = "macos")]
    {
        macos::process_command_line(pid)
    }
}
