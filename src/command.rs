//! Shell-command rendering for termination previews.
//!
//! Termination uses platform APIs. The preview shows an equivalent shell command
//! before confirmation.

use crate::model::Platform;
use crate::process::KillMode;

pub(crate) fn render_kill_command(platform: Platform, pid: u32, mode: KillMode) -> String {
    match (platform, mode) {
        (Platform::Linux | Platform::Macos, KillMode::Terminate) => format!("kill {pid}"),
        (Platform::Linux | Platform::Macos, KillMode::Force) => format!("kill -9 {pid}"),
        (Platform::Windows, KillMode::Terminate | KillMode::Force) => {
            format!("taskkill /F /PID {pid}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::render_kill_command;
    use crate::model::Platform;
    use crate::process::KillMode;

    #[test]
    fn renders_platform_equivalent_commands() {
        assert_eq!(
            render_kill_command(Platform::Linux, 18422, KillMode::Terminate),
            "kill 18422",
        );
        assert_eq!(
            render_kill_command(Platform::Linux, 18422, KillMode::Force),
            "kill -9 18422",
        );
        assert_eq!(
            render_kill_command(Platform::Macos, 18422, KillMode::Terminate),
            "kill 18422",
        );
        assert_eq!(
            render_kill_command(Platform::Macos, 18422, KillMode::Force),
            "kill -9 18422",
        );
        assert_eq!(
            render_kill_command(Platform::Windows, 18422, KillMode::Terminate),
            "taskkill /F /PID 18422",
        );
        assert_eq!(
            render_kill_command(Platform::Windows, 18422, KillMode::Force),
            "taskkill /F /PID 18422",
        );
    }
}
