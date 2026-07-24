const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const DIST_WORKSPACE: &str = include_str!("../dist-workspace.toml");

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn active_line(line: &str) -> Option<&str> {
    let line = line.trim();
    (!line.is_empty() && !line.starts_with('#'))
        .then(|| line.split(" #").next().expect("active line must exist"))
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

fn assert_action_pins_and_checkout_credentials(workflow: &str) {
    let steps = workflow_steps(workflow);
    let actions = steps
        .iter()
        .filter_map(|step| action_reference(step).map(|reference| (step, reference)))
        .collect::<Vec<_>>();
    assert!(!actions.is_empty(), "workflow must use at least one action");

    for (step, reference) in actions {
        if reference.starts_with("./") {
            continue;
        }
        let (action, revision) = reference
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("action must specify a revision: {reference}"));
        assert!(
            action.contains('/'),
            "invalid action reference: {reference}"
        );
        assert_eq!(
            revision.len(),
            40,
            "action must use a full commit SHA: {reference}"
        );
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "action must use a hexadecimal commit SHA: {reference}"
        );

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
    let lines = workflow.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let Some(active) = active_line(line) else {
            continue;
        };
        let Some(run) = active.strip_prefix("run:") else {
            continue;
        };
        assert!(
            !run.contains("${{ github.ref"),
            "tag/ref expressions must reach shell commands through environment variables"
        );

        let run_indent = indentation(line);
        for script_line in lines.iter().skip(index + 1) {
            if active_line(script_line).is_some() && indentation(script_line) <= run_indent {
                break;
            }
            assert!(
                !script_line.contains("${{ github.ref"),
                "tag/ref expressions must not be spliced into shell scripts"
            );
        }
    }
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
            value.contains("startsWith(github.ref, 'refs/tags/')"),
            "release plan output {key} must be derived only from a tag ref"
        );
    }

    let plan_step = job_steps(&plan)
        .into_iter()
        .find(|step| step_env(step, "PLAN_ARGS").is_some())
        .expect("release plan must pass its arguments through the environment");
    assert!(plan_step.contains("dist $PLAN_ARGS"));

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

    let release_step = job_steps(&workflow_job(RELEASE_WORKFLOW, "host"))
        .into_iter()
        .find(|step| step_env(step, "RELEASE_TAG").is_some())
        .expect("GitHub release creation must receive RELEASE_TAG through env");
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
    let unix = steps
        .iter()
        .position(|step| step.contains("python3 .github/scripts/validate-release-artifact.py"))
        .expect("Unix archives must be validated");
    let windows = steps
        .iter()
        .position(|step| step.contains("python .github/scripts/validate-release-artifact.py"))
        .expect("Windows archives must be validated");
    let upload = steps
        .iter()
        .position(|step| {
            action_reference(step)
                .is_some_and(|action| action.starts_with("actions/upload-artifact@"))
        })
        .expect("local artifacts must be uploaded");

    assert!(
        build < unix && unix < upload && build < windows && windows < upload,
        "every native archive must be validated after build and before upload"
    );
    for (step, condition, python, targets_argument) in [
        (
            &steps[unix],
            "runner.os != 'Windows'",
            "python3",
            "--targets-json \"$TARGETS_JSON\"",
        ),
        (
            &steps[windows],
            "runner.os == 'Windows'",
            "python",
            "--targets-json $env:TARGETS_JSON",
        ),
    ] {
        assert_eq!(yaml_scalar(step, "if", 8).as_deref(), Some(condition));
        assert_eq!(
            step_env(step, "TARGETS_JSON").as_deref(),
            Some("${{ toJSON(matrix.targets) }}")
        );
        assert!(step.contains(&format!(
            "{python} .github/scripts/validate-release-artifact.py"
        )));
        assert!(step.contains("--distrib target/distrib"));
        assert!(step.contains(targets_argument));
        assert!(step.contains("--runner-os \"${{ runner.os }}\""));
        assert!(step.contains("--runner-arch \"${{ runner.arch }}\""));
        assert!(
            !step
                .lines()
                .filter_map(active_line)
                .any(|line| line.starts_with("continue-on-error:") || line.contains("|| true")),
            "archive validation must fail closed"
        );
    }

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
