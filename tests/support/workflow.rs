const CI_WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const FUZZ_WORKFLOW: &str = include_str!("../../.github/workflows/fuzz.yml");
const RELEASE_WORKFLOW: &str = include_str!("../../.github/workflows/release.yml");
const RELEASE_POLICY: &str = include_str!("../../.github/release-policy.json");
const DIST_WORKSPACE: &str = include_str!("../../dist-workspace.toml");

use serde_yaml_ng::{Mapping, Value};

/// One source or script line with indentation, blanks, and comments removed.
/// A comment needs a separating space so URL fragments remain intact.
fn active_line(line: &str) -> Option<&str> {
    let line = line.trim();
    (!line.is_empty() && !line.starts_with('#'))
        .then(|| line.split(" #").next().expect("active line must exist"))
        .map(str::trim_end)
}

fn parsed_workflow(source: &str) -> Value {
    serde_yaml_ng::from_str(source).expect("workflow must be valid YAML")
}

fn mapping_value<'a>(mapping: &'a serde_yaml_ng::Mapping, key: &str) -> Option<&'a Value> {
    mapping
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn required_mapping<'a>(value: &'a Value, context: &str) -> &'a Mapping {
    value
        .as_mapping()
        .unwrap_or_else(|| panic!("{context} must be a mapping"))
}

fn required_sequence<'a>(mapping: &'a Mapping, key: &str) -> &'a [Value] {
    mapping_value(mapping, key)
        .and_then(Value::as_sequence)
        .unwrap_or_else(|| panic!("{key} must be a sequence"))
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        _ => panic!("expected a YAML scalar, got {value:?}"),
    }
}

fn yaml_scalar(mapping: &Mapping, key: &str) -> Option<String> {
    mapping_value(mapping, key).map(scalar_text)
}

fn yaml_mapping(mapping: &Mapping, key: &str) -> Vec<(String, String)> {
    mapping_value(mapping, key)
        .map_or_else(
            || panic!("missing YAML mapping {key}"),
            |value| required_mapping(value, key),
        )
        .iter()
        .map(|(key, value)| (scalar_text(key), scalar_text(value)))
        .collect()
}

fn yaml_sequence(mapping: &Mapping, key: &str) -> Vec<String> {
    required_sequence(mapping, key)
        .iter()
        .map(scalar_text)
        .collect()
}

fn workflow_root(workflow: &Value) -> &Mapping {
    required_mapping(workflow, "workflow root")
}

fn workflow_jobs(workflow: &Value) -> &Mapping {
    mapping_value(workflow_root(workflow), "jobs")
        .map(|value| required_mapping(value, "workflow jobs"))
        .expect("workflow must define jobs")
}

fn workflow_job<'a>(workflow: &'a Value, name: &str) -> &'a Mapping {
    mapping_value(workflow_jobs(workflow), name).map_or_else(
        || panic!("missing workflow job {name}"),
        |value| required_mapping(value, name),
    )
}

fn workflow_job_names(workflow: &Value) -> Vec<String> {
    workflow_jobs(workflow).keys().map(scalar_text).collect()
}

fn job_steps(job: &Mapping) -> Vec<&Mapping> {
    required_sequence(job, "steps")
        .iter()
        .map(|step| required_mapping(step, "workflow step"))
        .collect()
}

fn workflow_steps(workflow: &Value) -> Vec<&Mapping> {
    workflow_jobs(workflow)
        .values()
        .map(|job| required_mapping(job, "workflow job"))
        .filter(|job| mapping_value(job, "steps").is_some())
        .flat_map(job_steps)
        .collect()
}

fn step_name(step: &Mapping) -> Option<&str> {
    mapping_value(step, "name").and_then(Value::as_str)
}

fn job_step_names(job: &Mapping) -> Vec<&str> {
    job_steps(job).into_iter().filter_map(step_name).collect()
}

fn named_job_step<'a>(job: &'a Mapping, name: &str) -> &'a Mapping {
    job_steps(job)
        .into_iter()
        .find(|step| step_name(step) == Some(name))
        .unwrap_or_else(|| panic!("missing workflow step {name}"))
}

fn step_env(step: &Mapping, key: &str) -> Option<String> {
    mapping_value(step, "env")
        .map(|value| required_mapping(value, "step env"))
        .and_then(|env| yaml_scalar(env, key))
}

fn action_reference(step: &Mapping) -> Option<&str> {
    mapping_value(step, "uses").and_then(Value::as_str)
}

fn optional_step_script(step: &Mapping) -> Option<&str> {
    mapping_value(step, "run").and_then(Value::as_str)
}

fn step_script(step: &Mapping) -> &str {
    optional_step_script(step).expect("workflow step must define a run script")
}

fn release_policy() -> serde_json::Value {
    serde_json::from_str(RELEASE_POLICY).expect("release policy must be valid JSON")
}

fn policy_entries<'a>(policy: &'a serde_json::Value, matrix: &str) -> &'a [serde_json::Value] {
    policy
        .get(matrix)
        .and_then(|value| value.get("include"))
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("release policy {matrix}.include must be an array"))
}

fn script_lines(step: &Mapping) -> Vec<&str> {
    step_script(step).lines().filter_map(active_line).collect()
}

fn reusable_workflow_references(workflow: &str) -> Vec<String> {
    let workflow = parsed_workflow(workflow);
    workflow_jobs(&workflow)
        .values()
        .filter_map(Value::as_mapping)
        .filter_map(|job| mapping_value(job, "uses"))
        .map(|reference| {
            reference
                .as_str()
                .expect("reusable workflow reference must be a string")
                .to_owned()
        })
        .collect()
}

fn assert_pinned_reference(reference: &str, kind: &str) {
    if reference.starts_with("./") {
        return;
    }
    let (target, revision) = reference
        .rsplit_once('@')
        .unwrap_or_else(|| panic!("{kind} must specify a revision: {reference}"));
    assert!(target.contains('/'), "invalid {kind}: {reference}");
    assert_eq!(
        revision.len(),
        40,
        "{kind} must use a full commit SHA: {reference}"
    );
    assert!(
        revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{kind} must use a hexadecimal commit SHA: {reference}"
    );
}

fn assert_action_pins_and_checkout_credentials(workflow: &str) {
    let parsed = parsed_workflow(workflow);
    let steps = workflow_steps(&parsed);
    let actions = steps
        .iter()
        .filter_map(|step| action_reference(step).map(|reference| (step, reference)))
        .collect::<Vec<_>>();
    assert!(!actions.is_empty(), "workflow must use at least one action");

    for (step, reference) in actions {
        assert_pinned_reference(reference, "action reference");

        let action = reference.rsplit_once('@').map_or(reference, |pair| pair.0);
        if action == "actions/checkout" {
            let options = mapping_value(step, "with")
                .map(|value| required_mapping(value, "checkout options"))
                .expect("checkout must define options");
            assert_eq!(
                mapping_value(options, "persist-credentials").and_then(Value::as_bool),
                Some(false),
                "checkout must disable persisted credentials"
            );
            assert!(
                mapping_value(options, "token").is_none(),
                "checkout credentials must not be replaced with an explicit token"
            );
        }
    }

    for reference in reusable_workflow_references(workflow) {
        assert_pinned_reference(&reference, "reusable workflow reference");
    }
}

fn assert_read_only_default(workflow: &str) {
    let workflow = parsed_workflow(workflow);
    assert_eq!(
        yaml_mapping(workflow_root(&workflow), "permissions"),
        [("contents".to_owned(), "read".to_owned())],
        "workflow defaults must grant only read access to repository contents"
    );
}

fn assert_no_permission_shorthands(value: &Value) {
    match value {
        Value::Mapping(mapping) => {
            for (key, value) in mapping {
                if key.as_str() == Some("permissions") {
                    assert!(
                        value.as_str().is_none(),
                        "workflow must not use broad permission shorthands"
                    );
                }
                assert_no_permission_shorthands(value);
            }
        }
        Value::Sequence(sequence) => sequence.iter().for_each(assert_no_permission_shorthands),
        Value::Tagged(tagged) => assert_no_permission_shorthands(&tagged.value),
        _ => {}
    }
}

fn assert_release_job_permissions(workflow: &Value) {
    for name in workflow_job_names(workflow) {
        let job = workflow_job(workflow, &name);
        let permissions =
            mapping_value(job, "permissions").map(|_| yaml_mapping(job, "permissions"));

        match name.as_str() {
            "host" => assert_eq!(
                permissions,
                Some(vec![("contents".to_owned(), "write".to_owned())]),
                "only the GitHub release host job may write repository contents"
            ),
            "attest-release-artifacts" => assert_eq!(
                permissions,
                Some(vec![
                    ("contents".to_owned(), "read".to_owned()),
                    ("id-token".to_owned(), "write".to_owned()),
                    ("attestations".to_owned(), "write".to_owned()),
                ]),
                "only the attestation job may mint release provenance"
            ),
            "attest-published-manifest" => assert_eq!(
                permissions,
                Some(vec![
                    ("contents".to_owned(), "read".to_owned()),
                    ("id-token".to_owned(), "write".to_owned()),
                    ("attestations".to_owned(), "write".to_owned()),
                ]),
                "only the manifest-attestation job may mint post-publication provenance"
            ),
            _ => {
                if let Some(permissions) = permissions {
                    assert!(
                        permissions.iter().all(|(_, access)| access == "read"),
                        "release job {name} must not gain write permissions"
                    );
                }
            }
        }
    }
}

fn toml_string(source: &str, key: &str) -> String {
    let value = source
        .lines()
        .filter_map(active_line)
        .find_map(|line| {
            let (candidate, value) = line.split_once('=')?;
            (candidate.trim() == key).then(|| value.trim())
        })
        .unwrap_or_else(|| panic!("missing TOML key {key}"));
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{key} must be a TOML string"))
        .to_owned()
}

fn assert_exact_semver(version: &str) {
    let components = version.split('.').collect::<Vec<_>>();
    assert_eq!(components.len(), 3, "version must be exact: {version}");
    assert!(
        components.iter().all(|component| !component.is_empty()
            && component.bytes().all(|byte| byte.is_ascii_digit())),
        "version must contain only numeric SemVer components: {version}"
    );
}

fn assert_no_ref_expression_in_run_scripts(workflow: &str) {
    fn inspect(value: &Value) {
        match value {
            Value::Mapping(mapping) => {
                for (key, value) in mapping {
                    if key.as_str() == Some("run") {
                        let script = value.as_str().expect("workflow run value must be a string");
                        assert!(
                            !script.contains("${{ github.ref"),
                            "tag/ref expressions must not be spliced into shell scripts"
                        );
                    }
                    inspect(value);
                }
            }
            Value::Sequence(sequence) => sequence.iter().for_each(inspect),
            Value::Tagged(tagged) => inspect(&tagged.value),
            _ => {}
        }
    }

    inspect(&parsed_workflow(workflow));
}

fn assert_release_binary_journey(
    step: &Mapping,
    kickoutchi_path: &str,
    kick_path: &str,
    require_linux_capabilities: bool,
) {
    assert_eq!(
        step_env(step, "KICKOUTCHI_RELEASE_E2E_REQUIRED").as_deref(),
        Some("1")
    );
    assert_eq!(
        step_env(step, "KICKOUTCHI_E2E_KICKOUTCHI").as_deref(),
        Some(kickoutchi_path)
    );
    assert_eq!(
        step_env(step, "KICKOUTCHI_E2E_KICK").as_deref(),
        Some(kick_path)
    );
    assert_eq!(
        step_env(step, "KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES").as_deref(),
        require_linux_capabilities.then_some("1")
    );

    let active = script_lines(step);
    assert!(
        active.contains(&"cargo test --locked --all-features --test cli_contract"),
        "release journey must run the ordinary CLI contract suite"
    );
    assert!(
        active.contains(&"cargo test --locked --all-features --test cli_contract required_release_artifact_paths_are_complete_and_versioned -- --exact --ignored"),
        "release journey must run the ignored artifact-path contract exactly"
    );
}
