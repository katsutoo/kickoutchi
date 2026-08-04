include!("support/workflow.rs");

#[test]
fn actions_are_sha_pinned_and_checkout_never_persists_credentials() {
    assert_action_pins_and_checkout_credentials(CI_WORKFLOW);
    assert_action_pins_and_checkout_credentials(FUZZ_WORKFLOW);
    assert_action_pins_and_checkout_credentials(RELEASE_WORKFLOW);
}

#[test]
fn workflow_permissions_follow_least_privilege() {
    assert_read_only_default(CI_WORKFLOW);
    assert_read_only_default(FUZZ_WORKFLOW);
    assert_read_only_default(RELEASE_WORKFLOW);
    let ci = parsed_workflow(CI_WORKFLOW);
    let fuzz = parsed_workflow(FUZZ_WORKFLOW);
    let release = parsed_workflow(RELEASE_WORKFLOW);
    assert_no_permission_shorthands(&ci);
    assert_no_permission_shorthands(&fuzz);
    assert_no_permission_shorthands(&release);
    for (workflow_name, workflow) in [("CI", &ci), ("parser robustness", &fuzz)] {
        for name in workflow_job_names(workflow) {
            if let Some(permissions) = mapping_value(workflow_job(workflow, &name), "permissions") {
                assert!(
                    required_mapping(permissions, "job permissions")
                        .values()
                        .all(|access| access.as_str() == Some("read")),
                    "{workflow_name} job {name} must remain read-only"
                );
            }
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
fn parser_campaigns_are_bounded_scheduled_and_keep_saved_corpora_in_ci() {
    let workflow = parsed_workflow(FUZZ_WORKFLOW);
    let root = workflow_root(&workflow);
    let triggers = mapping_value(root, "on")
        .map(|value| required_mapping(value, "parser campaign triggers"))
        .expect("parser campaign workflow must define triggers");
    assert!(mapping_value(triggers, "workflow_dispatch").is_some());
    assert!(mapping_value(triggers, "schedule").is_some());
    assert!(mapping_value(triggers, "push").is_none());
    assert!(mapping_value(triggers, "pull_request").is_none());

    let environment = yaml_mapping(root, "env");
    assert!(
        environment
            .iter()
            .any(|(name, value)| name == "RUST_NIGHTLY" && value.starts_with("nightly-2026-")),
        "parser campaigns must pin a dated nightly toolchain"
    );
    assert!(
        environment
            .iter()
            .any(|(name, value)| name == "CARGO_FUZZ_VERSION" && value == "0.13.2"),
        "parser campaign runner must use the reviewed exact version"
    );

    let job = workflow_job(&workflow, "parser-campaign");
    assert_eq!(yaml_scalar(job, "timeout-minutes").as_deref(), Some("15"));
    let strategy = mapping_value(job, "strategy")
        .map(|value| required_mapping(value, "parser campaign strategy"))
        .expect("parser campaign must define a strategy");
    let matrix = mapping_value(strategy, "matrix")
        .map(|value| required_mapping(value, "parser campaign matrix"))
        .expect("parser campaign must define a matrix");
    let include = required_sequence(matrix, "include");
    assert_eq!(include.len(), 3);
    let mut targets = include
        .iter()
        .map(|entry| {
            let entry = required_mapping(entry, "parser campaign entry");
            (
                yaml_scalar(entry, "target").expect("campaign target"),
                yaml_scalar(entry, "max_input_bytes").expect("campaign input limit"),
            )
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    assert_eq!(
        targets,
        [
            ("archive_member_path".to_owned(), "4097".to_owned()),
            ("config".to_owned(), "65537".to_owned()),
            ("linux_proc".to_owned(), "65537".to_owned()),
        ]
    );

    let campaign = named_job_step(job, "Run bounded parser campaign");
    let script = step_script(campaign);
    for required in [
        "fuzz/corpus/$PARSER_TARGET",
        "-max_total_time=60",
        "-max_len=\"$MAX_INPUT_BYTES\"",
        "-timeout=5",
        "-rss_limit_mb=1024",
    ] {
        assert!(
            script.contains(required),
            "parser campaign is missing bound {required}"
        );
    }
    assert!(mapping_value(campaign, "continue-on-error").is_none());
    let lock = named_job_step(job, "Verify campaign dependency lock");
    assert!(step_script(lock).contains("--locked"));

    let ci = parsed_workflow(CI_WORKFLOW);
    let dependency_check = named_job_step(workflow_job(&ci, "supply-chain"), "Run cargo-deny");
    assert!(
        step_script(dependency_check).contains("--manifest-path fuzz/Cargo.toml"),
        "ordinary CI must validate the parser-campaign dependency lock"
    );
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
    // The policy owns the tuning values. The workflow may consume them, but it
    // must not grow a second independently maintained timeout table.
    const TIMEOUT_MINUTES_MAX: u64 = 60;

    let release = parsed_workflow(RELEASE_WORKFLOW);
    let policy = release_policy();
    let timeouts = policy
        .get("timeouts")
        .and_then(serde_json::Value::as_object)
        .expect("release policy timeouts must be an object");
    let mut policy_jobs = timeouts
        .keys()
        .map(|name| name.replace('_', "-"))
        .collect::<Vec<_>>();
    let mut workflow_jobs = workflow_job_names(&release);
    policy_jobs.sort_unstable();
    workflow_jobs.sort_unstable();
    assert_eq!(
        policy_jobs, workflow_jobs,
        "every release job needs one policy timeout"
    );

    for (policy_name, value) in timeouts {
        let job_name = policy_name.replace('_', "-");
        let minutes = value
            .as_u64()
            .unwrap_or_else(|| panic!("release timeout {policy_name} must be an integer"));
        assert!(
            (1..=TIMEOUT_MINUTES_MAX).contains(&minutes),
            "release job {job_name} timeout of {minutes} minutes is outside 1..={TIMEOUT_MINUTES_MAX}"
        );
        let job = workflow_job(&release, &job_name);
        let configured = yaml_scalar(job, "timeout-minutes")
            .unwrap_or_else(|| panic!("release job {job_name} must set timeout-minutes"));
        if job_name == "release-policy" {
            assert_eq!(
                configured,
                minutes.to_string(),
                "the bootstrap policy job is literal"
            );
        } else {
            assert!(
                yaml_sequence(job, "needs")
                    .iter()
                    .any(|dependency| dependency == "release-policy"),
                "release job {job_name} must consume the policy job directly"
            );
            assert_eq!(
                configured,
                format!("${{{{ fromJSON(needs.release-policy.outputs.timeouts).{policy_name} }}}}"),
                "release job {job_name} must read its timeout from release-policy.json"
            );
        }
    }

    let policy_job = workflow_job(&release, "release-policy");
    let load = named_job_step(policy_job, "Load release policy");
    let script = step_script(load);
    assert!(script.contains("policy=.github/release-policy.json"));
    assert!(script.contains("jq -c '.verify_matrix'"));
    assert!(script.contains("jq -c '.installer_matrix'"));
    assert!(script.contains("jq -c '.timeouts'"));
}

#[test]
fn release_policy_installer_targets_exist_in_cargo_dist_artifact_matrix() {
    let policy = release_policy();
    assert_eq!(
        policy
            .get("artifact_targets_source")
            .and_then(serde_json::Value::as_str),
        Some("dist-workspace.toml"),
        "cargo-dist must remain the single owner of the artifact target matrix",
    );

    let dist = toml::from_str::<toml::Value>(DIST_WORKSPACE)
        .expect("dist workspace configuration must be valid TOML");
    let artifact_targets = dist
        .get("dist")
        .and_then(|dist| dist.get("targets"))
        .and_then(toml::Value::as_array)
        .expect("cargo-dist must define its artifact targets")
        .iter()
        .map(|target| target.as_str().expect("artifact target must be a string"))
        .collect::<Vec<_>>();

    for installer in policy_entries(&policy, "installer_matrix") {
        let targets_json = installer
            .get("targets_json")
            .and_then(serde_json::Value::as_str)
            .expect("installer policy entry must contain targets_json");
        let installer_targets = serde_json::from_str::<Vec<String>>(targets_json)
            .expect("installer targets_json must be a string array");
        assert!(!installer_targets.is_empty());
        for target in installer_targets {
            assert!(
                artifact_targets.contains(&target.as_str()),
                "installer target {target} is absent from cargo-dist's artifact matrix",
            );
        }
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
    let strategy = mapping_value(verify, "strategy")
        .map(|value| required_mapping(value, "verify strategy"))
        .expect("release verification must define a strategy");
    assert_eq!(
        yaml_scalar(strategy, "matrix").as_deref(),
        Some("${{ fromJSON(needs.release-policy.outputs.verify-matrix) }}")
    );
    let policy = release_policy();
    let verify_names = policy_entries(&policy, "verify_matrix")
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("every verification entry must name its lane")
        })
        .collect::<Vec<_>>();
    assert_eq!(verify_names, ["Linux", "Windows", "macOS", "Supply Chain"]);
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
    assert!(
        yaml_sequence(host, "needs")
            .iter()
            .any(|job| job == "attest-release-artifacts"),
        "GitHub release publication must depend on artifact attestation"
    );
    assert!(
        yaml_scalar(host, "if").is_some_and(|condition| {
            condition.contains("needs.attest-release-artifacts.result == 'success'")
        }),
        "GitHub release publication must require artifact attestation to succeed"
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
fn prepared_release_assets_are_pre_attested_and_host_manifest_is_attested_afterward() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let attest = workflow_job(&release, "attest-release-artifacts");
    let needs = yaml_sequence(attest, "needs");
    for prerequisite in [
        "plan",
        "verify",
        "build-local-artifacts",
        "build-global-artifacts",
        "validate-installers",
    ] {
        assert!(
            needs.iter().any(|job| job == prerequisite),
            "attestation must depend on {prerequisite}"
        );
    }
    let condition = yaml_scalar(attest, "if").expect("attestation job must be conditional");
    assert!(
        condition.contains("needs.plan.outputs.publishing == 'true'")
            && condition.contains("github.event_name == 'workflow_dispatch'"),
        "tag releases and manual dry runs must exercise attestation"
    );
    for prerequisite in [
        "plan",
        "verify",
        "build-local-artifacts",
        "build-global-artifacts",
        "validate-installers",
    ] {
        assert!(
            condition.contains(&format!("needs.{prerequisite}.result == 'success'")),
            "attestation must fail closed when {prerequisite} fails"
        );
    }

    let stage = named_job_step(attest, "Stage publication assets");
    let stage_script = step_script(stage);
    assert!(stage_script.contains("target/distrib/*"));
    assert!(stage_script.contains("*-dist-manifest.json) continue"));
    assert!(stage_script.contains("target/attestation-subjects/"));
    assert!(
        !stage_script.contains("|| true"),
        "publication-asset staging must fail closed"
    );

    let generate = named_job_step(attest, "Generate artifact attestations");
    assert!(
        action_reference(generate).is_some_and(|action| action.starts_with("actions/attest@")),
        "the dedicated job must use the official attestation action"
    );
    let options = mapping_value(generate, "with")
        .map(|value| required_mapping(value, "attestation options"))
        .expect("attestation action must define its subjects");
    assert_eq!(
        yaml_scalar(options, "subject-path").as_deref(),
        Some("target/attestation-subjects/*")
    );

    let generated_verify = named_job_step(attest, "Verify generated attestations");
    assert!(
        step_script(generated_verify).contains("gh attestation verify"),
        "the generated provenance must be verified in the same run"
    );
    assert!(
        !step_script(generated_verify).contains("|| true"),
        "generated-provenance verification must fail closed"
    );

    let published = workflow_job(&release, "validate-published-release");
    let steps = job_steps(published);
    let download = steps
        .iter()
        .position(|step| step_name(step) == Some("Download published assets"))
        .expect("published assets must be downloaded");
    let verify = steps
        .iter()
        .position(|step| step_name(step) == Some("Verify published artifact attestations"))
        .expect("published artifact provenance must be verified");
    let execute = steps
        .iter()
        .position(|step| step_name(step) == Some("Execute published installer and updater"))
        .expect("published installer journey must remain enabled");
    assert!(
        download < verify && verify < execute,
        "published provenance must be checked before executing the installer"
    );
    assert!(
        step_script(steps[verify]).contains("gh attestation verify"),
        "every downloaded asset must be verified with the GitHub CLI"
    );

    assert!(
        yaml_sequence(published, "needs")
            .iter()
            .any(|job| job == "attest-published-manifest"),
        "published validation must wait for the host-generated manifest attestation"
    );
    assert!(
        yaml_scalar(published, "if").is_some_and(|condition| {
            condition.contains("needs.attest-published-manifest.result == 'success'")
        }),
        "published validation must fail closed when manifest attestation fails"
    );

    let manifest_attest = workflow_job(&release, "attest-published-manifest");
    assert_eq!(
        yaml_sequence(manifest_attest, "needs"),
        ["release-policy", "plan", "host"],
        "manifest provenance must be created only after the release host succeeds"
    );
    let manifest_condition =
        yaml_scalar(manifest_attest, "if").expect("manifest attestation must be conditional");
    assert!(
        manifest_condition.contains("needs.plan.outputs.publishing == 'true'")
            && manifest_condition.contains("needs.host.result == 'success'"),
        "manifest attestation must run only for a successfully hosted release"
    );
    let download_manifest = named_job_step(manifest_attest, "Download published release manifest");
    let download_script = step_script(download_manifest);
    assert!(download_script.contains("--pattern dist-manifest.json"));
    assert!(download_script.contains("--repo \"$GITHUB_REPOSITORY\""));
    assert!(!download_script.contains("|| true"));
    let generate_manifest =
        named_job_step(manifest_attest, "Generate release-manifest attestation");
    assert!(
        action_reference(generate_manifest)
            .is_some_and(|action| action.starts_with("actions/attest@")),
        "the host-generated manifest must use the official attestation action"
    );
    let verify_manifest = named_job_step(manifest_attest, "Verify release-manifest attestation");
    assert!(step_script(verify_manifest).contains("gh attestation verify"));
    assert!(!step_script(verify_manifest).contains("|| true"));
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
fn installer_matrix_is_policy_driven_and_runs_on_native_hosts() {
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
    assert_eq!(
        yaml_scalar(strategy, "matrix").as_deref(),
        Some("${{ fromJSON(needs.release-policy.outputs.installer-matrix) }}")
    );
    let policy = release_policy();
    let include = policy_entries(&policy, "installer_matrix");
    assert_eq!(
        include.len(),
        3,
        "Linux, macOS, and Windows installers must run"
    );
    let targets = include
        .iter()
        .map(|entry| {
            assert!(
                entry
                    .get("runner")
                    .and_then(serde_json::Value::as_str)
                    .is_some(),
                "every installer journey must name a native runner"
            );
            entry
                .get("targets_json")
                .and_then(serde_json::Value::as_str)
                .expect("every installer journey must name its validated target")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        [
            "[\"x86_64-unknown-linux-gnu\"]",
            "[\"aarch64-apple-darwin\"]",
            "[\"x86_64-pc-windows-msvc\"]",
        ],
        "Linux, macOS, and Windows installer artifacts must each run natively"
    );
}

#[test]
fn installers_and_updater_are_executed_before_and_after_publication() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let installers = workflow_job(&release, "validate-installers");

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
    let download = named_job_step(published, "Download published assets");
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
