//! Small, platform-neutral helpers shared by the TUI state transitions.

use crate::command;
use crate::docker;
use crate::model::{DockerPortContext, PortEntryView, ProcessContext};
use crate::platform;
use crate::process::{self, KillMode, KillTarget, TerminationOutcome};

pub(super) fn collect_selected_process_context(
    entry: PortEntryView<'_>,
    docker_enrichment: bool,
) -> ProcessContext {
    collect_selected_process_context_with(entry, docker_enrichment, docker::enrich_port)
}

pub(super) fn collect_selected_process_context_with<EnrichDocker>(
    entry: PortEntryView<'_>,
    docker_enrichment: bool,
    enrich_docker: EnrichDocker,
) -> ProcessContext
where
    EnrichDocker: FnOnce(PortEntryView<'_>) -> Option<DockerPortContext>,
{
    let mut context = entry
        .pid
        .map_or_else(ProcessContext::default, platform::collect_process_context);
    context.docker = if docker_enrichment {
        enrich_docker(entry)
    } else {
        None
    };
    context
}

pub(super) fn termination_status_line(
    target: &KillTarget,
    mode: KillMode,
    outcome: &TerminationOutcome,
) -> String {
    let description = outcome.status_description(target, mode);
    match outcome {
        TerminationOutcome::PermissionDenied => format!(
            "{description}; {}",
            process::permission_denied_hint(target.platform),
        ),
        TerminationOutcome::ProtectedProcess => {
            format!("{description} and requires stronger confirmation")
        }
        TerminationOutcome::Success
        | TerminationOutcome::OwnershipUnavailable
        | TerminationOutcome::AlreadyExited
        | TerminationOutcome::Cancelled
        | TerminationOutcome::TargetChanged
        | TerminationOutcome::UnsafePid(_)
        | TerminationOutcome::UnknownFailure(_)
        | TerminationOutcome::ThawFailed { .. } => description,
    }
}

pub(crate) fn kill_command_text(target: &KillTarget, mode: KillMode) -> String {
    command::render_kill_command(target.platform, target.pid, mode)
}

pub(super) fn preserved_selection(
    visible_row_indices: &[usize],
    selected_source_rows: Option<&[bool]>,
    fallback_index: usize,
) -> Option<usize> {
    if visible_row_indices.is_empty() {
        return None;
    }
    if let Some(selected_source_rows) = selected_source_rows
        && let Some(index) = visible_row_indices.iter().position(|&index| {
            *selected_source_rows
                .get(index)
                .expect("visible source indices must fit the selection mask")
        })
    {
        return Some(index);
    }
    Some(fallback_index.min(visible_row_indices.len() - 1))
}
