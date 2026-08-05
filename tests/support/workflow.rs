const CI_WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const FUZZ_WORKFLOW: &str = include_str!("../../.github/workflows/fuzz.yml");
const RELEASE_WORKFLOW: &str = include_str!("../../.github/workflows/release.yml");
const DIST_WORKSPACE: &str = include_str!("../../dist-workspace.toml");

use serde_yaml_ng::{Mapping, Value};

fn parsed_workflow(source: &str) -> Value {
    serde_yaml_ng::from_str(source).expect("workflow must be valid YAML")
}

fn mapping_value<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
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
        .filter_map(Value::as_mapping)
        .filter(|job| mapping_value(job, "steps").is_some())
        .flat_map(job_steps)
        .collect()
}

fn step_name(step: &Mapping) -> Option<&str> {
    mapping_value(step, "name").and_then(Value::as_str)
}

fn named_job_step<'a>(job: &'a Mapping, name: &str) -> &'a Mapping {
    job_steps(job)
        .into_iter()
        .find(|step| step_name(step) == Some(name))
        .unwrap_or_else(|| panic!("missing workflow step {name}"))
}

fn step_script(step: &Mapping) -> &str {
    mapping_value(step, "run")
        .and_then(Value::as_str)
        .expect("workflow step must define a run script")
}

fn step_env(step: &Mapping, key: &str) -> Option<String> {
    mapping_value(step, "env")
        .map(|value| required_mapping(value, "step environment"))
        .and_then(|environment| yaml_scalar(environment, key))
}

fn job_needs(job: &Mapping) -> Vec<String> {
    match mapping_value(job, "needs") {
        None => Vec::new(),
        Some(Value::Sequence(values)) => values.iter().map(scalar_text).collect(),
        Some(value) => vec![scalar_text(value)],
    }
}

fn matrix_entries(job: &Mapping) -> &[Value] {
    let strategy = mapping_value(job, "strategy")
        .map(|value| required_mapping(value, "job strategy"))
        .expect("matrix job must define a strategy");
    let matrix = mapping_value(strategy, "matrix")
        .map(|value| required_mapping(value, "job matrix"))
        .expect("strategy must define a matrix");
    required_sequence(matrix, "include")
}

fn assert_pinned_actions_and_checkout_credentials(workflow: &str) {
    let workflow = parsed_workflow(workflow);
    let mut action_count = 0;

    for step in workflow_steps(&workflow) {
        let Some(reference) = mapping_value(step, "uses").and_then(Value::as_str) else {
            continue;
        };
        action_count += 1;
        let (action, revision) = reference
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("action must specify a revision: {reference}"));
        assert_eq!(revision.len(), 40, "action must use a full SHA: {reference}");
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "action SHA must be hexadecimal: {reference}"
        );

        if action == "actions/checkout" {
            let options = mapping_value(step, "with")
                .map(|value| required_mapping(value, "checkout options"))
                .expect("checkout must define options");
            assert_eq!(
                mapping_value(options, "persist-credentials").and_then(Value::as_bool),
                Some(false),
                "checkout must not persist credentials"
            );
            assert!(
                mapping_value(options, "token").is_none(),
                "checkout tokens must not be persisted"
            );
        }
    }

    assert!(action_count > 0, "workflow must use at least one action");
}

fn assert_no_permission_shorthands(value: &Value) {
    match value {
        Value::Mapping(mapping) => {
            for (key, value) in mapping {
                if key.as_str() == Some("permissions") {
                    assert!(
                        value.as_str().is_none(),
                        "workflow must not use a permission shorthand"
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

fn assert_read_only_default(workflow: &str) {
    let workflow = parsed_workflow(workflow);
    assert_eq!(
        yaml_mapping(workflow_root(&workflow), "permissions"),
        [("contents".to_owned(), "read".to_owned())]
    );
}

fn assert_release_job_permissions(workflow: &Value) {
    for name in workflow_job_names(workflow) {
        let job = workflow_job(workflow, &name);
        let permissions = mapping_value(job, "permissions").map(|_| yaml_mapping(job, "permissions"));

        match name.as_str() {
            "host" => assert_eq!(
                permissions,
                Some(vec![("contents".to_owned(), "write".to_owned())])
            ),
            "attest-release-artifacts" => assert_eq!(
                permissions,
                Some(vec![
                    ("contents".to_owned(), "read".to_owned()),
                    ("id-token".to_owned(), "write".to_owned()),
                    ("attestations".to_owned(), "write".to_owned()),
                ])
            ),
            _ => assert!(
                permissions
                    .is_none_or(|entries| entries.iter().all(|(_, access)| access == "read")),
                "release job {name} has unnecessary write access"
            ),
        }
    }
}

fn assert_no_ref_expression_in_scripts(workflow: &str) {
    for step in workflow_steps(&parsed_workflow(workflow)) {
        if let Some(script) = mapping_value(step, "run").and_then(Value::as_str) {
            assert!(
                !script.contains("${{ github.ref"),
                "tag/ref expressions must reach scripts through environment variables"
            );
        }
    }
}

fn toml_string(source: &str, key: &str) -> String {
    let value = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
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
        "version must contain only numeric components: {version}"
    );
}
