const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const DIST_WORKSPACE: &str = include_str!("../dist-workspace.toml");

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

fn installer_target(entry: &Value) -> String {
    let entry = required_mapping(entry, "installer matrix entry");
    assert!(
        yaml_scalar(entry, "runner").is_some(),
        "every installer journey must name a native runner"
    );
    yaml_scalar(entry, "targets_json")
        .expect("installer matrix entry must name its validated target")
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

        if name == "host" {
            assert_eq!(
                permissions,
                Some(vec![("contents".to_owned(), "write".to_owned())]),
                "only the GitHub release host job may write repository contents"
            );
        } else if let Some(permissions) = permissions {
            assert!(
                permissions.iter().all(|(_, access)| access == "read"),
                "release job {name} must not gain write permissions"
            );
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

#[test]
fn actions_are_sha_pinned_and_checkout_never_persists_credentials() {
    assert_action_pins_and_checkout_credentials(CI_WORKFLOW);
    assert_action_pins_and_checkout_credentials(RELEASE_WORKFLOW);
}

#[test]
fn workflow_permissions_follow_least_privilege() {
    assert_read_only_default(CI_WORKFLOW);
    assert_read_only_default(RELEASE_WORKFLOW);
    let ci = parsed_workflow(CI_WORKFLOW);
    let release = parsed_workflow(RELEASE_WORKFLOW);
    assert_no_permission_shorthands(&ci);
    assert_no_permission_shorthands(&release);
    for name in workflow_job_names(&ci) {
        if let Some(permissions) = mapping_value(workflow_job(&ci, &name), "permissions") {
            assert!(
                required_mapping(permissions, "CI job permissions")
                    .values()
                    .all(|access| access.as_str() == Some("read")),
                "CI job {name} must remain read-only"
            );
        }
    }
    assert_release_job_permissions(&release);
}

#[test]
fn ci_runs_one_push_branch_and_keeps_pull_request_coverage() {
    let ci = parsed_workflow(CI_WORKFLOW);
    let triggers = mapping_value(workflow_root(&ci), "on")
        .map(|value| required_mapping(value, "CI triggers"))
        .expect("CI workflow must define triggers");
    let push = mapping_value(triggers, "push")
        .map(|value| required_mapping(value, "CI push trigger"))
        .expect("CI workflow must define a push trigger");

    assert_eq!(yaml_sequence(push, "branches"), ["shrek"]);
    assert!(
        mapping_value(triggers, "pull_request").is_some(),
        "pull request CI must remain enabled"
    );
    assert!(
        mapping_value(triggers, "schedule").is_some(),
        "scheduled CI must remain enabled"
    );
}

#[test]
fn ci_lanes_run_independently_and_feed_one_required_completion_gate() {
    const LANES: [&str; 5] = ["supply-chain", "linux", "nix", "windows", "macos"];

    let ci = parsed_workflow(CI_WORKFLOW);
    for lane in LANES {
        assert!(
            mapping_value(workflow_job(&ci, lane), "needs").is_none(),
            "CI lane {lane} must start independently"
        );
    }

    let complete = workflow_job(&ci, "ci-complete");
    let mut needs = yaml_sequence(complete, "needs");
    needs.sort_unstable();
    let mut expected = LANES.map(str::to_owned).to_vec();
    expected.sort_unstable();
    assert_eq!(needs, expected, "CI completion must depend on every lane");
    assert!(
        yaml_scalar(complete, "if").is_some_and(|condition| condition.contains("always()")),
        "CI completion must run even when an upstream lane fails"
    );

    let gate = named_job_step(complete, "Require every CI lane");
    let script = step_script(gate);
    for lane in ["SUPPLY_CHAIN", "LINUX", "NIX", "WINDOWS", "MACOS"] {
        let expected_result = format!(
            "${{{{ needs.{}.result }}}}",
            lane.to_ascii_lowercase().replace('_', "-")
        );
        assert_eq!(
            step_env(gate, &format!("{lane}_RESULT")).as_deref(),
            Some(expected_result.as_str()),
            "aggregate gate must receive the {lane} result"
        );
    }
    assert!(
        script.contains("test \"$result\" = \"success\""),
        "aggregate gate must fail closed on any non-success result"
    );
}

#[test]
fn formatting_and_doctests_run_once_while_native_quality_checks_remain() {
    let ci = parsed_workflow(CI_WORKFLOW);
    let linux_steps = job_step_names(workflow_job(&ci, "linux"));
    assert!(linux_steps.contains(&"Check formatting"));
    assert!(linux_steps.contains(&"Run doctests"));

    for platform in ["linux", "windows", "macos"] {
        let steps = job_step_names(workflow_job(&ci, platform));
        assert!(steps.contains(&"Run Clippy"), "{platform} must run Clippy");
        assert!(steps.contains(&"Run tests"), "{platform} must run tests");
    }
    for platform in ["windows", "macos"] {
        let steps = job_step_names(workflow_job(&ci, platform));
        assert!(
            !steps.contains(&"Check formatting"),
            "{platform} must not duplicate formatting"
        );
        assert!(
            !steps.contains(&"Run doctests"),
            "{platform} must not duplicate doctests"
        );
    }
}

#[test]
fn cargo_dist_linux_runner_images_are_digest_pinned() {
    const TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];

    let workspace =
        toml::from_str::<toml::Value>(DIST_WORKSPACE).expect("dist workspace must be valid TOML");
    let runners = workspace
        .get("dist")
        .and_then(|dist| dist.get("github-custom-runners"))
        .and_then(toml::Value::as_table)
        .expect("dist must configure GitHub custom runners");
    assert_eq!(
        runners.len(),
        TARGETS.len(),
        "every configured custom runner must be reviewed for immutable images"
    );

    // The contract is structural: every runner image is immutable
    // (digest-pinned) and both architectures build from the identical image.
    // The digest value itself is the workflow file's to own.
    let mut images = Vec::new();
    for target in TARGETS {
        let image = runners
            .get(target)
            .and_then(|runner| runner.get("container"))
            .and_then(|container| container.get("image"))
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("custom runner {target} must define a container image"));
        let digest = image.split_once("@sha256:").map_or_else(
            || panic!("custom runner {target} image must be digest-pinned"),
            |(_, digest)| digest,
        );
        assert!(
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "custom runner {target} digest must be a full sha256 hex digest"
        );
        images.push(image);
    }
    assert_eq!(
        images[0], images[1],
        "both Linux targets must build from the identical pinned image"
    );
}

#[test]
fn release_runs_are_globally_serialized_without_cancellation() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    assert_eq!(
        yaml_mapping(workflow_root(&release), "concurrency"),
        [
            ("group".to_owned(), "${{ github.workflow }}".to_owned()),
            ("cancel-in-progress".to_owned(), "false".to_owned()),
        ]
    );
}

#[test]
fn release_tag_is_rechecked_against_the_verified_commit_before_publication() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let host = workflow_job(&release, "host");
    let host_step = job_steps(host)
        .into_iter()
        .find(|step| mapping_value(step, "id").and_then(Value::as_str) == Some("host"))
        .expect("missing dist host step");
    let create_step = named_job_step(host, "Create GitHub Release");

    for step in [host_step, create_step] {
        assert_eq!(
            step_env(step, "RELEASE_COMMIT").as_deref(),
            Some("${{ github.sha }}")
        );
        assert_eq!(
            step_env(step, "RELEASE_TAG").as_deref(),
            Some("${{ needs.plan.outputs.tag }}")
        );
        let active = script_lines(step);
        assert!(active.contains(
            &"git fetch --force --no-tags origin \"refs/tags/${RELEASE_TAG}:refs/tags/${RELEASE_TAG}\""
        ));
        assert!(
            active
                .contains(&"TAG_COMMIT=\"$(git rev-parse --verify \"${RELEASE_TAG}^{commit}\")\"")
        );
        assert!(active.contains(&"test \"$TAG_COMMIT\" = \"$RELEASE_COMMIT\""));
    }
}

#[test]
fn every_release_job_has_the_approved_timeout() {
    // The contract is that no release job can hang forever and none gets an
    // unreviewed multi-hour window; the exact minutes per job are a tuning
    // choice the workflow file owns.
    const TIMEOUT_MINUTES_MAX: u64 = 60;

    let release = parsed_workflow(RELEASE_WORKFLOW);
    let jobs = workflow_job_names(&release);
    assert!(!jobs.is_empty(), "release workflow must define jobs");
    for job_name in jobs {
        let timeout = yaml_scalar(workflow_job(&release, &job_name), "timeout-minutes")
            .unwrap_or_else(|| panic!("release job {job_name} must set timeout-minutes"));
        let minutes = timeout.parse::<u64>().unwrap_or_else(|_| {
            panic!("release job {job_name} timeout-minutes must be a literal integer")
        });
        assert!(
            (1..=TIMEOUT_MINUTES_MAX).contains(&minutes),
            "release job {job_name} timeout of {minutes} minutes is outside 1..={TIMEOUT_MINUTES_MAX}"
        );
    }
}

#[test]
fn native_release_binary_journeys_run_the_complete_artifact_path_contract() {
    let ci = parsed_workflow(CI_WORKFLOW);
    let release = parsed_workflow(RELEASE_WORKFLOW);
    for (job_name, kickoutchi_path, kick_path, linux) in [
        (
            "linux",
            "${{ github.workspace }}/target/release/kickoutchi",
            "${{ github.workspace }}/target/release/kick",
            true,
        ),
        (
            "windows",
            "${{ github.workspace }}\\target\\release\\kickoutchi.exe",
            "${{ github.workspace }}\\target\\release\\kick.exe",
            false,
        ),
        (
            "macos",
            "${{ github.workspace }}/target/release/kickoutchi",
            "${{ github.workspace }}/target/release/kick",
            false,
        ),
    ] {
        let job = workflow_job(&ci, job_name);
        let step = named_job_step(job, "Run release binary journeys");
        assert_release_binary_journey(step, kickoutchi_path, kick_path, linux);
    }

    let verify = workflow_job(&release, "verify");
    for (platform, kickoutchi_path, kick_path, linux) in [
        (
            "Linux",
            "${{ github.workspace }}/target/release/kickoutchi",
            "${{ github.workspace }}/target/release/kick",
            true,
        ),
        (
            "Windows",
            "${{ github.workspace }}\\target\\release\\kickoutchi.exe",
            "${{ github.workspace }}\\target\\release\\kick.exe",
            false,
        ),
        (
            "macOS",
            "${{ github.workspace }}/target/release/kickoutchi",
            "${{ github.workspace }}/target/release/kick",
            false,
        ),
    ] {
        let step = named_job_step(verify, &format!("Run release binary journeys ({platform})"));
        assert_release_binary_journey(step, kickoutchi_path, kick_path, linux);
    }
}

#[test]
fn nix_validation_uses_the_evaluated_package_version_without_provenance_markers() {
    let ci = parsed_workflow(CI_WORKFLOW);
    let nix = workflow_job(&ci, "nix");
    let step = named_job_step(nix, "Build and verify native Nix package");
    let active = script_lines(step);

    assert!(active.contains(
        &"PACKAGE_VERSION=\"$(nix eval --raw \".#packages.${{ matrix.system }}.kickoutchi.version\")\""
    ));
    let version_checks = active
        .iter()
        .filter(|line| line.contains("./result/bin/") && line.contains("--version"))
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        version_checks,
        [
            "test \"$(./result/bin/kickoutchi --version)\" = \"kickoutchi ${PACKAGE_VERSION}\"",
            "test \"$(./result/bin/kick --version)\" = \"kickoutchi ${PACKAGE_VERSION}\"",
        ],
        "Nix validation must compare against the evaluated package version"
    );
    assert!(
        active
            .iter()
            .all(|line| !line.contains("install-provenance")),
        "Nix validation must not require a deleted provenance marker"
    );
}

#[test]
fn homebrew_validates_both_installed_binaries_without_formula_provenance_mutation() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let homebrew = workflow_job(&release, "publish-homebrew-formula");
    let step = named_job_step(homebrew, "Commit formula files");
    let active = script_lines(step);

    assert!(active.contains(&"brew install --formula \"nuggocto/tap/${FORMULA_NAME}\""));
    assert!(active.contains(
        &r#"test "$("${prefix}/bin/kickoutchi" --version)" = "kickoutchi ${FORMULA_VERSION}""#
    ));
    assert!(active.contains(
        &r#"test "$("${prefix}/bin/kick" --version)" = "kickoutchi ${FORMULA_VERSION}""#
    ));
    assert!(
        active
            .iter()
            .all(|line| !line.contains("install-provenance")),
        "Homebrew validation must not require a deleted provenance marker"
    );
    assert!(
        active.iter().all(|line| !line.starts_with("ruby -e")),
        "the generated formula must not be mutated with Ruby"
    );
}

#[test]
fn cargo_dist_is_installed_locked_at_the_configured_exact_version() {
    let configured = toml_string(DIST_WORKSPACE, "cargo-dist-version");
    assert_exact_semver(&configured);

    let release = parsed_workflow(RELEASE_WORKFLOW);
    let release_env = yaml_mapping(workflow_root(&release), "env");
    let workflow_version = release_env
        .iter()
        .find_map(|(key, value)| (key == "DIST_VERSION").then_some(value))
        .expect("release workflow must define DIST_VERSION");
    assert_eq!(workflow_version, &configured);

    let installs = workflow_steps(&release)
        .into_iter()
        .filter_map(optional_step_script)
        .flat_map(str::lines)
        .filter_map(active_line)
        .filter(|line| line.contains("cargo install") && line.contains("cargo-dist"))
        .collect::<Vec<_>>();
    assert!(
        !installs.is_empty(),
        "release workflow must install cargo-dist"
    );
    for install in installs {
        assert!(
            install.contains("--locked"),
            "unlocked cargo-dist install: {install}"
        );
        assert!(
            install.contains("--version \"$DIST_VERSION\"")
                || install.contains("--version $env:DIST_VERSION"),
            "cargo-dist install must use the pinned workflow version: {install}"
        );
    }
}

#[test]
fn tag_and_ref_values_are_passed_to_shells_through_environment_variables() {
    assert_no_ref_expression_in_run_scripts(RELEASE_WORKFLOW);

    let release = parsed_workflow(RELEASE_WORKFLOW);
    let plan = workflow_job(&release, "plan");
    let outputs = yaml_mapping(plan, "outputs");
    for key in ["tag", "tag-flag", "publishing"] {
        let value = outputs
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
            .unwrap_or_else(|| panic!("release plan must expose {key}"));
        assert!(
            value.contains("github.event_name == 'push'")
                && value.contains("startsWith(github.ref, 'refs/tags/')"),
            "release plan output {key} must require a pushed tag"
        );
    }

    let plan_step = job_steps(plan)
        .into_iter()
        .find(|step| step_env(step, "PLAN_ARGS").is_some())
        .expect("release plan must pass its arguments through the environment");
    assert!(step_script(plan_step).contains("dist $PLAN_ARGS"));
    assert!(
        step_env(plan_step, "PLAN_ARGS").is_some_and(|value| {
            value.contains("github.event_name == 'push'")
                && value.contains("startsWith(github.ref, 'refs/tags/')")
        }),
        "manual dispatches, including tag-ref dispatches, must remain non-publishing"
    );

    for job_name in ["build-local-artifacts", "build-global-artifacts", "host"] {
        let job = workflow_job(&release, job_name);
        let tag_step = job_steps(job)
            .into_iter()
            .find(|step| step_env(step, "TAG_FLAG").is_some())
            .unwrap_or_else(|| panic!("release job {job_name} must pass TAG_FLAG through env"));
        assert!(
            step_script(tag_step).contains("$TAG_FLAG"),
            "release job {job_name} must consume the environment value"
        );
    }

    let release_step = named_job_step(workflow_job(&release, "host"), "Create GitHub Release");
    assert!(
        step_script(release_step).contains("\"$RELEASE_TAG\""),
        "the release tag must be quoted when passed to gh"
    );
}

#[test]
fn homebrew_token_is_available_only_to_the_final_push_step() {
    const TAP_TOKEN: &str = "${{ secrets.HOMEBREW_TAP_TOKEN }}";

    assert_eq!(
        RELEASE_WORKFLOW.matches(TAP_TOKEN).count(),
        1,
        "the Homebrew token must have one workflow reference"
    );
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let homebrew = workflow_job(&release, "publish-homebrew-formula");
    let steps = job_steps(homebrew);
    let push = steps.last().expect("Homebrew job must have a push step");
    assert_eq!(step_env(push, "GH_TOKEN").as_deref(), Some(TAP_TOKEN));
    assert!(script_lines(push).contains(&"git push"));
}

#[test]
fn release_publication_requires_successful_same_run_verification() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let host = workflow_job(&release, "host");
    assert!(
        yaml_sequence(host, "needs")
            .iter()
            .any(|job| job == "verify"),
        "GitHub release publication must depend on verification"
    );
    assert!(
        yaml_scalar(host, "if")
            .is_some_and(|condition| condition.contains("needs.verify.result == 'success'")),
        "GitHub release publication must require successful verification"
    );

    let homebrew = workflow_job(&release, "publish-homebrew-formula");
    assert!(
        yaml_sequence(homebrew, "needs")
            .iter()
            .any(|job| job == "host"),
        "Homebrew publication must remain downstream of verified GitHub publication"
    );
}

#[test]
fn native_archives_are_validated_before_upload_and_publication() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let local = workflow_job(&release, "build-local-artifacts");
    let steps = job_steps(local);
    let build = steps
        .iter()
        .position(|step| {
            optional_step_script(step).is_some_and(|script| script.contains("dist build"))
        })
        .expect("local artifacts must be built");
    let validation = steps
        .iter()
        .position(|step| {
            optional_step_script(step).is_some_and(|script| {
                script.contains("cargo test --locked --test release_artifact_validator")
            })
        })
        .expect("native archives must be validated");
    let upload = steps
        .iter()
        .position(|step| {
            action_reference(step)
                .is_some_and(|action| action.starts_with("actions/upload-artifact@"))
        })
        .expect("local artifacts must be uploaded");

    assert!(
        build < validation && validation < upload,
        "every native archive must be validated after build and before upload"
    );
    let step = &steps[validation];
    assert_eq!(
        step_env(step, "KICKOUTCHI_RELEASE_DISTRIB").as_deref(),
        Some("target/distrib")
    );
    assert_eq!(
        step_env(step, "KICKOUTCHI_RELEASE_TARGETS_JSON").as_deref(),
        Some("${{ toJSON(matrix.targets) }}")
    );
    assert_eq!(
        step_env(step, "KICKOUTCHI_RELEASE_RUNNER_OS").as_deref(),
        Some("${{ runner.os }}")
    );
    assert_eq!(
        step_env(step, "KICKOUTCHI_RELEASE_RUNNER_ARCH").as_deref(),
        Some("${{ runner.arch }}")
    );
    assert!(
        step_script(step)
            .contains("validate_generated_native_archive -- --exact --ignored --nocapture")
    );
    assert!(
        mapping_value(step, "continue-on-error").is_none()
            && !step_script(step).contains("|| true"),
        "archive validation must fail closed"
    );

    let host = workflow_job(&release, "host");
    assert!(
        yaml_sequence(host, "needs")
            .iter()
            .any(|job| job == "build-local-artifacts"),
        "publication must remain downstream of validated local artifacts"
    );
    assert!(
        yaml_scalar(host, "if").is_some_and(|condition| {
            condition.contains("needs.build-local-artifacts.result == 'success'")
        }),
        "publication must require validated local artifacts to succeed"
    );
}

#[test]
fn arch_metadata_is_compared_with_native_makepkg_output() {
    let ci = parsed_workflow(CI_WORKFLOW);
    let image = yaml_mapping(workflow_root(&ci), "env")
        .into_iter()
        .find_map(|(key, value)| (key == "ARCHLINUX_IMAGE").then_some(value))
        .expect("CI must pin the Arch validation image");
    let (_, digest) = image
        .rsplit_once("@sha256:")
        .expect("Arch image must use a digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let supply_chain = workflow_job(&ci, "supply-chain");
    let step = named_job_step(supply_chain, "Verify regenerated Arch metadata");
    let script = script_lines(step).join("\n");
    assert!(script.contains("$ARCHLINUX_IMAGE"));
    assert!(script.contains("$GITHUB_WORKSPACE:/workspace:ro"));
    assert!(script.contains("for package in kickoutchi kickoutchi-bin"));
    assert!(script.contains("runuser -u nobody"));
    assert!(script.contains("diff -u .SRCINFO <(makepkg --printsrcinfo)"));
}

#[test]
fn linux_updater_is_rebuilt_from_pinned_source_before_validation() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    assert_eq!(
        yaml_mapping(workflow_root(&release), "env")
            .into_iter()
            .find_map(|(key, value)| (key == "AXOUPDATER_VERSION").then_some(value))
            .as_deref(),
        Some("0.10.0"),
    );

    let local = workflow_job(&release, "build-local-artifacts");
    let rebuild = named_job_step(local, "Rebuild Linux updater at supported ABI floor");
    assert_eq!(
        yaml_scalar(rebuild, "if").as_deref(),
        Some("runner.os == 'Linux'")
    );
    assert_eq!(
        step_env(rebuild, "UPDATER_TARGET").as_deref(),
        Some("${{ join(matrix.targets, '') }}")
    );
    let rebuild_script = step_script(rebuild);
    assert!(rebuild_script.contains("test \"$RUST_HOST\" = \"$UPDATER_TARGET\""));
    assert!(
        rebuild_script
            .contains("cargo install --locked axoupdater-cli --version \"$AXOUPDATER_VERSION\"")
    );
    assert!(rebuild_script.contains(
        "install -m 0755 target/axoupdater/bin/axoupdater \"target/distrib/kickoutchi-${UPDATER_TARGET}-update\""
    ));
    let steps = job_steps(local);
    let position = |name| {
        steps
            .iter()
            .position(|step| step_name(step) == Some(name))
            .unwrap_or_else(|| panic!("missing workflow step {name}"))
    };
    assert!(position("Build artifacts") < position("Rebuild Linux updater at supported ABI floor"));
    assert!(
        position("Rebuild Linux updater at supported ABI floor")
            < position("Validate native release archive")
    );
    assert!(position("Validate native release archive") < position("Upload artifacts"));
}

#[test]
fn installers_and_updater_are_executed_before_and_after_publication() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let installers = workflow_job(&release, "validate-installers");
    assert!(
        yaml_sequence(installers, "needs")
            .iter()
            .any(|job| job == "build-global-artifacts")
    );
    let strategy = mapping_value(installers, "strategy")
        .map(|value| required_mapping(value, "installer strategy"))
        .expect("installer job must define a strategy");
    let matrix = mapping_value(strategy, "matrix")
        .map(|value| required_mapping(value, "installer matrix"))
        .expect("installer strategy must define a matrix");
    let include = required_sequence(matrix, "include");
    assert_eq!(
        include.len(),
        3,
        "Linux, macOS, and Windows installers must run"
    );
    let targets = include.iter().map(installer_target).collect::<Vec<_>>();
    assert_eq!(
        targets,
        [
            "[\"x86_64-unknown-linux-gnu\"]",
            "[\"aarch64-apple-darwin\"]",
            "[\"x86_64-pc-windows-msvc\"]",
        ],
        "Linux, macOS, and Windows installer artifacts must each run natively"
    );

    let execute = named_job_step(installers, "Execute generated installer and updater");
    assert_eq!(
        step_env(execute, "KICKOUTCHI_RELEASE_INSTALLER").as_deref(),
        Some("target/distrib/${{ matrix.installer }}")
    );
    assert!(
        step_script(execute)
            .contains("validate_generated_native_installer -- --exact --ignored --nocapture")
    );
    assert!(mapping_value(execute, "continue-on-error").is_none());

    let host = workflow_job(&release, "host");
    assert!(
        yaml_sequence(host, "needs")
            .iter()
            .any(|job| job == "validate-installers")
    );
    assert!(yaml_scalar(host, "if").is_some_and(|condition| {
        condition.contains("needs.validate-installers.result == 'success'")
    }));

    let published = workflow_job(&release, "validate-published-release");
    assert!(
        yaml_sequence(published, "needs")
            .iter()
            .any(|job| job == "host")
    );
    assert!(
        yaml_scalar(published, "if")
            .is_some_and(|condition| condition.contains("needs.host.result == 'success'"))
    );
    let download = named_job_step(published, "Download published installer");
    assert_eq!(
        step_env(download, "RELEASE_TAG").as_deref(),
        Some("${{ needs.plan.outputs.tag }}")
    );
    assert!(step_script(download).contains("gh release download \"$RELEASE_TAG\""));
    let smoke = named_job_step(published, "Execute published installer and updater");
    assert_eq!(
        step_env(smoke, "KICKOUTCHI_RELEASE_PUBLIC").as_deref(),
        Some("1")
    );
    assert_eq!(
        step_env(smoke, "KICKOUTCHI_RELEASE_TAG").as_deref(),
        Some("${{ needs.plan.outputs.tag }}")
    );
    assert_eq!(
        step_env(smoke, "KICKOUTCHI_RELEASE_GITHUB_TOKEN").as_deref(),
        Some("${{ secrets.GITHUB_TOKEN }}")
    );

    let homebrew = workflow_job(&release, "publish-homebrew-formula");
    assert!(
        yaml_sequence(homebrew, "needs")
            .iter()
            .any(|job| job == "validate-published-release")
    );
    assert!(yaml_scalar(homebrew, "if").is_some_and(|condition| {
        condition.contains("needs.validate-published-release.result == 'success'")
    }));

    let complete = workflow_job(&release, "publication-complete");
    assert!(
        yaml_sequence(complete, "needs")
            .iter()
            .any(|job| job == "validate-published-release")
    );
    assert!(yaml_scalar(complete, "if").is_some_and(|condition| {
        condition.contains("needs.validate-published-release.result == 'success'")
    }));
    let confirm = named_job_step(complete, "Confirm publication gates");
    assert_eq!(step_script(confirm), "true");
    assert!(action_reference(confirm).is_none());
}

#[test]
fn structured_workflow_accessors_cover_all_jobs_and_yaml_forms() {
    let fixture = parsed_workflow(
        r#"
permissions: { contents: read }
jobs:
  first:
    needs: [zeroth, other]
    steps:
      - { uses: actions/checkout@1111111111111111111111111111111111111111, with: { persist-credentials: false } }
      - name: Multi line step
        env: { TOKEN: "${{ secrets.EXAMPLE }}" }
        run: |
          echo one
          echo two
  "second":
    steps:
      - { name: Only step, run: "echo done" }
"#,
    );

    assert_eq!(workflow_job_names(&fixture), ["first", "second"]);
    assert_eq!(
        yaml_mapping(workflow_root(&fixture), "permissions"),
        [("contents".to_owned(), "read".to_owned())]
    );
    let first = workflow_job(&fixture, "first");
    assert_eq!(yaml_sequence(first, "needs"), ["zeroth", "other"]);
    let steps = job_steps(first);
    assert_eq!(steps.len(), 2);
    assert_eq!(workflow_steps(&fixture).len(), 3);
    assert_eq!(
        action_reference(steps[0]),
        Some("actions/checkout@1111111111111111111111111111111111111111")
    );
    assert_eq!(
        step_env(steps[1], "TOKEN").as_deref(),
        Some("${{ secrets.EXAMPLE }}")
    );
    assert!(step_script(steps[1]).contains("echo one\necho two"));
    assert_eq!(step_env(steps[0], "TOKEN"), None);
}

#[test]
fn run_script_scanner_covers_every_yaml_mapping_form() {
    let safe = r#"
jobs:
  fixture:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$SAFE_REF"
      - { "run": "echo $SAFE_REF" }
      - name: quoted key
        'run': |
          echo "$SAFE_REF"
"#;
    assert_no_ref_expression_in_run_scripts(safe);

    for hostile in [
        "jobs:\n  fixture:\n    steps:\n      - run: echo ${{ github.ref_name }}\n",
        "jobs:\n  fixture:\n    steps:\n      - { name: inline, run: 'echo ${{ github.ref }}' }\n",
        "jobs:\n  fixture:\n    steps:\n      - 'run': |\n          echo ${{ github.ref_name }}\n",
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_no_ref_expression_in_run_scripts(hostile)).is_err(),
            "run expression escaped structural scanning: {hostile}"
        );
    }
}

#[test]
fn reusable_workflows_are_discovered_and_require_commit_pins() {
    let pinned = r"
jobs:
  remote:
    uses: owner/repository/.github/workflows/ci.yml@1111111111111111111111111111111111111111
  local:
    uses: ./.github/workflows/local.yml
";
    assert_eq!(
        reusable_workflow_references(pinned),
        [
            "owner/repository/.github/workflows/ci.yml@1111111111111111111111111111111111111111",
            "./.github/workflows/local.yml",
        ]
    );
    for reference in reusable_workflow_references(pinned) {
        assert_pinned_reference(&reference, "reusable workflow reference");
    }

    assert!(
        std::panic::catch_unwind(|| {
            assert_pinned_reference(
                "owner/repository/.github/workflows/ci.yml@main",
                "reusable workflow reference",
            );
        })
        .is_err(),
        "a mutable reusable-workflow ref must fail the security contract"
    );
}

#[test]
fn commented_write_permissions_are_still_detected() {
    let annotated = "permissions:\n  contents: write  # needed for the release\njobs: {}";
    assert!(
        std::panic::catch_unwind(|| assert_read_only_default(annotated)).is_err(),
        "an annotated write permission must fail the read-only contract"
    );
}
