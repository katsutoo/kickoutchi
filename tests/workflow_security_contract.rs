const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const DIST_WORKSPACE: &str = include_str!("../dist-workspace.toml");

use serde_yaml_ng::Value;

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// One workflow line with indentation, blank lines, and comments removed.
///
/// The result is trimmed again after the comment is stripped. Several
/// assertions below compare the whole line (`== "permissions: read-all"`) or
/// its suffix (`ends_with(": write")`), and leaving the space that separated
/// the comment would quietly exempt any line carrying one — exactly the lines
/// a reviewer is most likely to annotate.
fn active_line(line: &str) -> Option<&str> {
    let line = line.trim();
    (!line.is_empty() && !line.starts_with('#'))
        .then(|| line.split(" #").next().expect("active line must exist"))
        .map(str::trim_end)
}

fn yaml_block(source: &str, key: &str, indent: usize) -> String {
    let header = format!("{key}:");
    let mut block = Vec::new();
    let mut found = false;

    for line in source.lines() {
        if !found {
            found = indentation(line) == indent && active_line(line) == Some(header.as_str());
            continue;
        }
        if active_line(line).is_some() && indentation(line) <= indent {
            break;
        }
        block.push(line);
    }

    assert!(found, "missing YAML block {key}");
    block.join("\n")
}

fn yaml_scalar(source: &str, key: &str, indent: usize) -> Option<String> {
    source.lines().find_map(|line| {
        if indentation(line) != indent {
            return None;
        }
        let line = active_line(line)?;
        let (candidate, value) = line.split_once(':')?;
        (candidate == key).then(|| value.trim().to_owned())
    })
}

fn yaml_mapping(source: &str, key: &str, indent: usize) -> Vec<(String, String)> {
    yaml_block(source, key, indent)
        .lines()
        .filter_map(|line| {
            if indentation(line) != indent + 2 {
                return None;
            }
            let (key, value) = active_line(line)?.split_once(':')?;
            Some((key.to_owned(), value.trim().to_owned()))
        })
        .collect()
}

fn yaml_sequence(source: &str, key: &str, indent: usize) -> Vec<String> {
    yaml_block(source, key, indent)
        .lines()
        .filter_map(|line| {
            (indentation(line) == indent + 2)
                .then(|| active_line(line))
                .flatten()?
                .strip_prefix("- ")
                .map(str::to_owned)
        })
        .collect()
}

fn sequence_items(source: &str, indent: usize) -> Vec<String> {
    let mut items = Vec::new();
    let mut item = None::<String>;

    for line in source.lines() {
        let starts_item = indentation(line) == indent
            && active_line(line).is_some_and(|line| line.starts_with("- "));
        if starts_item {
            if let Some(item) = item.take() {
                items.push(item);
            }
            item = Some(line.to_owned());
        } else if let Some(item) = &mut item {
            item.push('\n');
            item.push_str(line);
        }
    }
    if let Some(item) = item {
        items.push(item);
    }

    items
}

fn workflow_job(workflow: &str, name: &str) -> String {
    yaml_block(&yaml_block(workflow, "jobs", 0), name, 2)
}

fn workflow_job_names(workflow: &str) -> Vec<String> {
    yaml_block(workflow, "jobs", 0)
        .lines()
        .filter_map(|line| {
            if indentation(line) != 2 {
                return None;
            }
            active_line(line)?.strip_suffix(':').map(str::to_owned)
        })
        .collect()
}

fn workflow_steps(workflow: &str) -> Vec<String> {
    sequence_items(workflow, 6)
        .into_iter()
        .filter(|item| {
            item.lines().any(|line| {
                active_line(line).is_some_and(|line| {
                    line.starts_with("- name:")
                        || line.starts_with("- uses:")
                        || line.starts_with("- id:")
                })
            })
        })
        .collect()
}

fn job_steps(job: &str) -> Vec<String> {
    sequence_items(&yaml_block(job, "steps", 4), 6)
}

fn step_name(step: &str) -> Option<&str> {
    step.lines().find_map(|line| {
        active_line(line)?
            .strip_prefix("- name: ")
            .map(|name| name.trim_matches('"'))
    })
}

fn named_job_step(job: &str, name: &str) -> String {
    job_steps(job)
        .into_iter()
        .find(|step| step_name(step) == Some(name))
        .unwrap_or_else(|| panic!("missing workflow step {name}"))
}

fn step_env(step: &str, key: &str) -> Option<String> {
    let env = step
        .lines()
        .any(|line| indentation(line) == 8 && active_line(line) == Some("env:"));
    env.then(|| yaml_scalar(&yaml_block(step, "env", 8), key, 10))
        .flatten()
}

fn action_reference(step: &str) -> Option<String> {
    step.lines().find_map(|line| {
        active_line(line).and_then(|line| {
            line.strip_prefix("- uses: ")
                .or_else(|| line.strip_prefix("uses: "))
                .map(str::to_owned)
        })
    })
}

fn parsed_workflow(source: &str) -> Value {
    serde_yaml_ng::from_str(source).expect("workflow must be valid YAML")
}

fn mapping_value<'a>(mapping: &'a serde_yaml_ng::Mapping, key: &str) -> Option<&'a Value> {
    mapping
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn reusable_workflow_references(workflow: &str) -> Vec<String> {
    let workflow = parsed_workflow(workflow);
    let root = workflow
        .as_mapping()
        .expect("workflow root must be a mapping");
    let jobs = mapping_value(root, "jobs")
        .and_then(Value::as_mapping)
        .expect("workflow jobs must be a mapping");

    jobs.values()
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
    let steps = workflow_steps(workflow);
    let actions = steps
        .iter()
        .filter_map(|step| action_reference(step).map(|reference| (step, reference)))
        .collect::<Vec<_>>();
    assert!(!actions.is_empty(), "workflow must use at least one action");

    for (step, reference) in actions {
        assert_pinned_reference(&reference, "action reference");

        let action = reference
            .rsplit_once('@')
            .map_or(reference.as_str(), |pair| pair.0);
        if action == "actions/checkout" {
            let active = step.lines().filter_map(active_line).collect::<Vec<_>>();
            assert!(
                active.contains(&"persist-credentials: false"),
                "checkout must disable persisted credentials"
            );
            assert!(
                !active.iter().any(|line| line.starts_with("token:")),
                "checkout credentials must not be replaced with an explicit token"
            );
        }
    }

    for reference in reusable_workflow_references(workflow) {
        assert_pinned_reference(&reference, "reusable workflow reference");
    }
}

fn assert_read_only_default(workflow: &str) {
    assert_eq!(
        yaml_mapping(workflow, "permissions", 0),
        [("contents".to_owned(), "read".to_owned())],
        "workflow defaults must grant only read access to repository contents"
    );
    assert!(
        !workflow
            .lines()
            .filter_map(active_line)
            .any(|line| { line == "permissions: read-all" || line == "permissions: write-all" }),
        "workflow must not use broad permission shorthands"
    );
}

fn assert_release_job_permissions() {
    for name in workflow_job_names(RELEASE_WORKFLOW) {
        let job = workflow_job(RELEASE_WORKFLOW, &name);
        let permissions = job
            .lines()
            .any(|line| indentation(line) == 4 && active_line(line) == Some("permissions:"));
        let permissions = permissions.then(|| yaml_mapping(&job, "permissions", 4));

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
    step: &str,
    kickoutchi_path: &str,
    kick_path: &str,
    require_linux_capabilities: bool,
) {
    assert_eq!(
        step_env(step, "KICKOUTCHI_RELEASE_E2E_REQUIRED").as_deref(),
        Some("\"1\"")
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
        require_linux_capabilities.then_some("\"1\"")
    );

    let active = step.lines().filter_map(active_line).collect::<Vec<_>>();
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
    assert!(
        !CI_WORKFLOW
            .lines()
            .filter_map(active_line)
            .any(|line| line.ends_with(": write")),
        "CI must remain read-only"
    );
    assert_release_job_permissions();
}

#[test]
fn cargo_dist_linux_runner_images_are_digest_pinned() {
    const IMAGE: &str = "rust:1.95-bullseye@sha256:28afaeb8445f2a2e7d878bd34ed39ba02bb517efb29986188cbd59b7cf4f2fdf";
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

    for target in TARGETS {
        let image = runners
            .get(target)
            .and_then(|runner| runner.get("container"))
            .and_then(|container| container.get("image"))
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("custom runner {target} must define a container image"));
        assert_eq!(image, IMAGE, "custom runner {target} image must be pinned");
    }
}

#[test]
fn release_runs_are_globally_serialized_without_cancellation() {
    assert_eq!(
        yaml_mapping(RELEASE_WORKFLOW, "concurrency", 0),
        [
            ("group".to_owned(), "${{ github.workflow }}".to_owned()),
            ("cancel-in-progress".to_owned(), "false".to_owned()),
        ]
    );
}

#[test]
fn release_tag_is_rechecked_against_the_verified_commit_before_publication() {
    let host = workflow_job(RELEASE_WORKFLOW, "host");
    let host_step = job_steps(&host)
        .into_iter()
        .find(|step| {
            step.lines()
                .filter_map(active_line)
                .any(|line| line == "- id: host")
        })
        .expect("missing dist host step");
    let create_step = named_job_step(&host, "Create GitHub Release");

    for step in [&host_step, &create_step] {
        assert_eq!(
            step_env(step, "RELEASE_COMMIT").as_deref(),
            Some("\"${{ github.sha }}\"")
        );
        assert_eq!(
            step_env(step, "RELEASE_TAG").as_deref(),
            Some("\"${{ needs.plan.outputs.tag }}\"")
        );
        let active = step.lines().filter_map(active_line).collect::<Vec<_>>();
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
    const EXPECTED: [(&str, &str); 7] = [
        ("verify", "35"),
        ("plan", "20"),
        ("build-local-artifacts", "45"),
        ("build-global-artifacts", "30"),
        ("host", "20"),
        ("publish-homebrew-formula", "30"),
        ("publication-complete", "10"),
    ];

    let jobs = workflow_job_names(RELEASE_WORKFLOW);
    assert_eq!(
        jobs.len(),
        EXPECTED.len(),
        "new release jobs must receive an approved timeout"
    );
    for job_name in jobs {
        let expected = EXPECTED
            .iter()
            .find_map(|(name, timeout)| (*name == job_name).then_some(*timeout))
            .unwrap_or_else(|| panic!("release job {job_name} has no approved timeout"));
        assert_eq!(
            yaml_scalar(
                &workflow_job(RELEASE_WORKFLOW, &job_name),
                "timeout-minutes",
                4
            )
            .as_deref(),
            Some(expected),
            "release job {job_name} timeout changed"
        );
    }
}

#[test]
fn native_release_binary_journeys_run_the_complete_artifact_path_contract() {
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
        let job = workflow_job(CI_WORKFLOW, job_name);
        let step = named_job_step(&job, "Run release binary journeys");
        assert_release_binary_journey(&step, kickoutchi_path, kick_path, linux);
    }

    let verify = workflow_job(RELEASE_WORKFLOW, "verify");
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
        let step = named_job_step(
            &verify,
            &format!("Run release binary journeys ({platform})"),
        );
        assert_release_binary_journey(&step, kickoutchi_path, kick_path, linux);
    }
}

#[test]
fn nix_validation_uses_the_evaluated_package_version_without_provenance_markers() {
    let nix = workflow_job(CI_WORKFLOW, "nix");
    let step = named_job_step(&nix, "Build and verify native Nix package");
    let active = step.lines().filter_map(active_line).collect::<Vec<_>>();

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
    let homebrew = workflow_job(RELEASE_WORKFLOW, "publish-homebrew-formula");
    let step = named_job_step(&homebrew, "Commit formula files");
    let active = step.lines().filter_map(active_line).collect::<Vec<_>>();

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

    let release_env = yaml_mapping(RELEASE_WORKFLOW, "env", 0);
    let workflow_version = release_env
        .iter()
        .find_map(|(key, value)| (key == "DIST_VERSION").then_some(value))
        .expect("release workflow must define DIST_VERSION")
        .trim_matches('"');
    assert_eq!(workflow_version, configured);

    let installs = RELEASE_WORKFLOW
        .lines()
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

    let plan = workflow_job(RELEASE_WORKFLOW, "plan");
    let outputs = yaml_mapping(&plan, "outputs", 4);
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

    let plan_step = job_steps(&plan)
        .into_iter()
        .find(|step| step_env(step, "PLAN_ARGS").is_some())
        .expect("release plan must pass its arguments through the environment");
    assert!(plan_step.contains("dist $PLAN_ARGS"));
    assert!(
        step_env(&plan_step, "PLAN_ARGS").is_some_and(|value| {
            value.contains("github.event_name == 'push'")
                && value.contains("startsWith(github.ref, 'refs/tags/')")
        }),
        "manual dispatches, including tag-ref dispatches, must remain non-publishing"
    );

    for job_name in ["build-local-artifacts", "build-global-artifacts", "host"] {
        let job = workflow_job(RELEASE_WORKFLOW, job_name);
        let tag_step = job_steps(&job)
            .into_iter()
            .find(|step| step_env(step, "TAG_FLAG").is_some())
            .unwrap_or_else(|| panic!("release job {job_name} must pass TAG_FLAG through env"));
        assert!(
            tag_step.contains("$TAG_FLAG"),
            "release job {job_name} must consume the environment value"
        );
    }

    let release_step = named_job_step(
        &workflow_job(RELEASE_WORKFLOW, "host"),
        "Create GitHub Release",
    );
    assert!(
        release_step.contains("\"$RELEASE_TAG\""),
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
    let homebrew = workflow_job(RELEASE_WORKFLOW, "publish-homebrew-formula");
    let steps = job_steps(&homebrew);
    let push = steps.last().expect("Homebrew job must have a push step");
    assert_eq!(step_env(push, "GH_TOKEN").as_deref(), Some(TAP_TOKEN));
    assert!(
        push.lines()
            .filter_map(active_line)
            .any(|line| line == "git push")
    );
}

#[test]
fn release_publication_requires_successful_same_run_verification() {
    let host = workflow_job(RELEASE_WORKFLOW, "host");
    assert!(
        yaml_sequence(&host, "needs", 4)
            .iter()
            .any(|job| job == "verify"),
        "GitHub release publication must depend on verification"
    );
    assert!(
        yaml_scalar(&host, "if", 4)
            .is_some_and(|condition| condition.contains("needs.verify.result == 'success'")),
        "GitHub release publication must require successful verification"
    );

    let homebrew = workflow_job(RELEASE_WORKFLOW, "publish-homebrew-formula");
    assert!(
        yaml_sequence(&homebrew, "needs", 4)
            .iter()
            .any(|job| job == "host"),
        "Homebrew publication must remain downstream of verified GitHub publication"
    );
}

#[test]
fn native_archives_are_validated_before_upload_and_publication() {
    let local = workflow_job(RELEASE_WORKFLOW, "build-local-artifacts");
    let steps = job_steps(&local);
    let build = steps
        .iter()
        .position(|step| step.contains("dist build"))
        .expect("local artifacts must be built");
    let validation = steps
        .iter()
        .position(|step| step.contains("cargo test --locked --test release_artifact_validator"))
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
    assert!(step.contains("validate_generated_native_archive -- --exact --ignored --nocapture"));
    assert!(
        !step
            .lines()
            .filter_map(active_line)
            .any(|line| line.starts_with("continue-on-error:") || line.contains("|| true")),
        "archive validation must fail closed"
    );

    let host = workflow_job(RELEASE_WORKFLOW, "host");
    assert!(
        yaml_sequence(&host, "needs", 4)
            .iter()
            .any(|job| job == "build-local-artifacts"),
        "publication must remain downstream of validated local artifacts"
    );
    assert!(
        yaml_scalar(&host, "if", 4).is_some_and(|condition| {
            condition.contains("needs.build-local-artifacts.result == 'success'")
        }),
        "publication must require validated local artifacts to succeed"
    );
}

/// The shape-specific helpers above remain a deliberately small YAML reader;
/// security-sensitive key enumeration uses `serde_yaml_ng` so valid alternate
/// YAML spellings cannot evade it. A helper that silently returned nothing
/// would still make the shape assertions pass vacuously, so these tests exercise
/// nesting, comments, inline comments, blank lines, multi-line steps, and loud
/// failure for missing blocks.
#[cfg(test)]
mod yaml_reader {
    use super::{
        action_reference, active_line, indentation, job_steps, sequence_items, step_env,
        workflow_job, workflow_job_names, workflow_steps, yaml_block, yaml_mapping, yaml_scalar,
        yaml_sequence,
    };

    const FIXTURE: &str = r#"# leading comment
name: Fixture
permissions:
  contents: read

env:
  PINNED: "1.2.3"

jobs:
  first:
    runs-on: ubuntu-latest  # inline comment
    permissions:
      contents: read
    needs:
      - zeroth
      - other
    if: ${{ needs.zeroth.result == 'success' }}
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111 # v1
        with:
          persist-credentials: false

      - name: Multi line step
        env:
          TOKEN: ${{ secrets.EXAMPLE }}
        run: |
          echo one
          echo two
  second:
    runs-on: ubuntu-latest
    steps:
      - name: Only step
        run: echo done
"#;

    #[test]
    fn active_line_strips_comments_and_blanks() {
        assert_eq!(active_line("  key: value"), Some("key: value"));
        assert_eq!(active_line("  key: value  # trailing"), Some("key: value"));
        assert_eq!(active_line("   # whole line"), None);
        assert_eq!(active_line("    "), None);
        // A `#` that is not comment-separated stays part of the value.
        assert_eq!(
            active_line("url: http://x/#frag"),
            Some("url: http://x/#frag")
        );
        assert_eq!(indentation("    key:"), 4);
    }

    #[test]
    fn scalars_mappings_and_sequences_read_the_requested_depth() {
        assert_eq!(yaml_scalar(FIXTURE, "name", 0).as_deref(), Some("Fixture"));
        // A key at another indentation must not be picked up.
        assert_eq!(yaml_scalar(FIXTURE, "contents", 0), None);
        assert_eq!(
            yaml_mapping(FIXTURE, "permissions", 0),
            [("contents".to_owned(), "read".to_owned())]
        );
        assert_eq!(
            yaml_mapping(FIXTURE, "env", 0),
            [("PINNED".to_owned(), "\"1.2.3\"".to_owned())]
        );

        let first = workflow_job(FIXTURE, "first");
        assert_eq!(yaml_sequence(&first, "needs", 4), ["zeroth", "other"]);
        assert_eq!(
            yaml_scalar(&first, "if", 4).as_deref(),
            Some("${{ needs.zeroth.result == 'success' }}")
        );
    }

    #[test]
    fn blocks_end_at_the_next_key_of_equal_or_lower_indentation() {
        let permissions = yaml_block(FIXTURE, "permissions", 0);
        assert!(permissions.contains("contents: read"));
        assert!(!permissions.contains("PINNED"), "{permissions}");

        // The first job's block must not bleed into the second job.
        let first = workflow_job(FIXTURE, "first");
        assert!(first.contains("Multi line step"));
        assert!(!first.contains("Only step"), "{first}");
    }

    #[test]
    fn missing_blocks_fail_loudly_rather_than_returning_nothing() {
        // A silent empty block is what would make the real assertions vacuous.
        let missing = std::panic::catch_unwind(|| yaml_block(FIXTURE, "absent", 0));
        assert!(
            missing.is_err(),
            "a missing block must panic, not return empty"
        );
    }

    #[test]
    fn jobs_and_steps_are_enumerated_completely() {
        assert_eq!(workflow_job_names(FIXTURE), ["first", "second"]);

        let first = workflow_job(FIXTURE, "first");
        let steps = job_steps(&first);
        assert_eq!(steps.len(), 2, "{steps:#?}");
        // A blank line inside a step must not split it into two items.
        assert!(steps[0].contains("persist-credentials: false"));
        assert!(steps[1].contains("echo one") && steps[1].contains("echo two"));

        // Every step across the file is found, so an un-scanned step cannot
        // hide an unpinned action.
        assert_eq!(workflow_steps(FIXTURE).len(), 3);
        assert_eq!(sequence_items(&yaml_block(&first, "steps", 4), 6).len(), 2);
    }

    #[test]
    fn step_details_are_read_from_the_right_step() {
        let steps = job_steps(&workflow_job(FIXTURE, "first"));
        assert_eq!(
            action_reference(&steps[0]).as_deref(),
            Some("actions/checkout@1111111111111111111111111111111111111111")
        );
        assert_eq!(action_reference(&steps[1]), None);
        assert_eq!(
            step_env(&steps[1], "TOKEN").as_deref(),
            Some("${{ secrets.EXAMPLE }}")
        );
        // A step with no env block must report none rather than borrowing one.
        assert_eq!(step_env(&steps[0], "TOKEN"), None);
        assert_eq!(step_env(&steps[1], "ABSENT"), None);
    }
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

/// Regression for the inline-comment blind spot: a permission line annotated
/// with a comment must still be seen as a write permission, or the read-only
/// assertion above would exempt exactly the lines reviewers annotate.
#[test]
fn commented_write_permissions_are_still_detected() {
    let annotated = "        contents: write  # needed for the release";
    let line = active_line(annotated).expect("annotated line is active");
    assert_eq!(line, "contents: write");
    assert!(line.ends_with(": write"));
}
