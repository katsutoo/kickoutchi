//! Platform-specific collectors.

use crate::model::{ProcessContext, RelatedProcessHint};

#[cfg(target_os = "linux")]
pub(crate) mod linux;

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    #[cfg(target_os = "linux")]
    {
        linux::collect_process_context(pid)
    }

    #[cfg(not(target_os = "linux"))]
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

    #[cfg(not(target_os = "linux"))]
    {
        let _ = port;
        Vec::new()
    }
}
