//! Home of the platform-specific collectors.

use crate::model::{ProcessContext, RelatedProcessHint};

#[cfg(target_os = "linux")]
pub(crate) mod linux;
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

    #[cfg(not(any(target_os = "linux", windows)))]
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

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = port;
        Vec::new()
    }
}
