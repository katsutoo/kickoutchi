const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const UNIX_DIST_INSTALLER: &str = include_str!("../.github/scripts/install-cargo-dist.sh");
const WINDOWS_DIST_INSTALLER: &str = include_str!("../.github/scripts/install-cargo-dist.ps1");
const BREW_STYLE: &str = r#"brew style --except-cops FormulaAudit/Homepage,FormulaAudit/Desc,FormulaAuditStrict --fix "Formula/${filename}""#;
const BREW_RELEASE_LOOP: &str = r#"for release in $(echo "$PLAN" | jq --compact-output '.releases[] | select([.artifacts[] | endswith(".rb")] | any)'); do"#;

fn normalized_workflow() -> String {
    RELEASE_WORKFLOW.replace("\r\n", "\n")
}

fn active_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn workflow_steps(workflow: &str) -> Vec<&str> {
    workflow.split("\n      - ").skip(1).collect()
}

fn compact_expression(line: &str) -> String {
    line.chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != '\'' && *character != '"'
        })
        .flat_map(char::to_lowercase)
        .collect()
}

fn validate_checkout_credentials(workflow: &str) -> Result<(), String> {
    let checkout_steps = workflow_steps(workflow)
        .into_iter()
        .filter(|step| step.contains("uses: actions/checkout@"))
        .collect::<Vec<_>>();
    if checkout_steps.len() != 7 {
        return Err(format!(
            "expected seven release checkout steps, found {}",
            checkout_steps.len()
        ));
    }
    for step in checkout_steps {
        let lines = active_lines(step).collect::<Vec<_>>();
        if lines
            .iter()
            .filter(|line| **line == "persist-credentials: false")
            .count()
            != 1
        {
            return Err("every checkout must explicitly disable persisted credentials".to_owned());
        }
        if lines.iter().any(|line| {
            (line.starts_with("persist-credentials:") && *line != "persist-credentials: false")
                || line.starts_with("token:")
        }) {
            return Err("checkout must not receive or persist a repository token".to_owned());
        }
    }
    Ok(())
}

fn validate_repository_token_scope(workflow: &str) -> Result<(), String> {
    const TOKEN: &str = "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}";
    const EXPECTED_STEPS: [(&str, &str); 3] = [
        ("id: plan", "dist $PLAN_ARGS"),
        ("id: host", "dist host $TAG_FLAG"),
        ("name: Create GitHub Release", "gh release create"),
    ];

    fn references_repository_token(line: &str) -> bool {
        let compact = compact_expression(line);
        compact.contains("secrets.github_token")
            || compact.contains("secrets[github_token]")
            || compact.contains("github.token")
            || compact.contains("github[token]")
    }

    if active_lines(workflow)
        .map(compact_expression)
        .any(|line| line.contains("secrets[") || line.contains("github["))
    {
        return Err("dynamic secret and GitHub-context indexing is forbidden".to_owned());
    }
    let global_references = active_lines(workflow)
        .filter(|line| references_repository_token(line))
        .count();
    if global_references != EXPECTED_STEPS.len() {
        return Err(format!(
            "repository token must appear exactly {} times",
            EXPECTED_STEPS.len()
        ));
    }

    let mut actual_steps = Vec::new();
    for step in workflow_steps(workflow) {
        let lines = active_lines(step).collect::<Vec<_>>();
        let references = lines
            .iter()
            .filter(|line| references_repository_token(line))
            .count();
        if references == 0 {
            continue;
        }
        if references != 1 || !lines.contains(&TOKEN) {
            return Err("repository token must use the step-scoped GH_TOKEN form".to_owned());
        }
        let header = lines
            .first()
            .copied()
            .ok_or_else(|| "token-bearing step must have a header".to_owned())?;
        let (_, required_command) = EXPECTED_STEPS
            .iter()
            .find(|(expected_header, _)| *expected_header == header)
            .ok_or_else(|| format!("repository token is forbidden in step {header:?}"))?;
        if !lines.iter().any(|line| line.contains(required_command)) {
            return Err(format!(
                "token-bearing step {header:?} must run its publication command"
            ));
        }
        actual_steps.push(header);
    }
    let expected_headers = EXPECTED_STEPS.map(|(header, _)| header);
    if actual_steps != expected_headers {
        return Err("repository tokens must remain in the three approved steps".to_owned());
    }
    Ok(())
}

fn unix_archive_hash_pairs(installer: &str) -> Result<Vec<(String, String)>, String> {
    let mut archive = None;
    let mut pairs = Vec::new();
    for line in installer.lines().map(str::trim) {
        if let Some(value) = line
            .strip_prefix("archive=\"")
            .and_then(|value| value.strip_suffix('"'))
        {
            archive = Some(value.to_owned());
            continue;
        }
        if let Some(value) = line.strip_prefix("expected_sha256=\"${") {
            let variable = value
                .split_once(':')
                .map(|(variable, _)| variable)
                .ok_or_else(|| "checksum assignment must require its variable".to_owned())?;
            let archive = archive
                .take()
                .ok_or_else(|| "checksum assignment must follow its archive".to_owned())?;
            pairs.push((archive, variable.to_owned()));
        }
    }
    Ok(pairs)
}

fn validate_windows_executable_selection(installer: &str) -> Result<(), String> {
    let lines = active_lines(installer).collect::<Vec<_>>();
    let checksum = lines
        .iter()
        .position(|line| *line == "if ($actualSha256 -ne $expectedSha256) {")
        .ok_or_else(|| "Windows checksum mismatch must enter a failing branch".to_owned())?;
    let checksum_failure = lines
        .iter()
        .position(|line| *line == "throw \"cargo-dist archive checksum mismatch: $actualSha256\"")
        .ok_or_else(|| "Windows checksum mismatch must stop installation".to_owned())?;
    let extract = lines
        .iter()
        .position(|line| line.starts_with("Expand-Archive -LiteralPath $archive"))
        .ok_or_else(|| "Windows archive extraction must be explicit".to_owned())?;
    let enumerate = lines
        .iter()
        .position(|line| {
            *line
                == "$binaries = @(Get-ChildItem -Path $extracted -Filter \"dist.exe\" -File -Recurse)"
        })
        .ok_or_else(|| "Windows installer must enumerate dist.exe candidates".to_owned())?;
    let unique = lines
        .iter()
        .position(|line| *line == "if ($binaries.Count -ne 1) {")
        .ok_or_else(|| "Windows installer must require exactly one dist.exe".to_owned())?;
    let failure = lines
        .iter()
        .position(|line| *line == "throw \"cargo-dist archive must contain exactly one dist.exe\"")
        .ok_or_else(|| "Windows uniqueness failure must stop installation".to_owned())?;
    let copy = lines
        .iter()
        .position(|line| line.starts_with("Copy-Item -LiteralPath $binaries[0].FullName"))
        .ok_or_else(|| "Windows installer must copy the validated executable".to_owned())?;
    if !(checksum < checksum_failure
        && checksum_failure < extract
        && extract < enumerate
        && enumerate < unique
        && unique < failure
        && failure < copy)
    {
        return Err("Windows executable validation must precede installation".to_owned());
    }
    Ok(())
}

fn validate_unix_integrity_flow(installer: &str) -> Result<(), String> {
    let lines = active_lines(installer).collect::<Vec<_>>();
    let checksum = lines
        .iter()
        .position(|line| *line == "if [ \"$actual_sha256\" != \"$expected_sha256\" ]; then")
        .ok_or_else(|| "Unix checksum mismatch must enter a failing branch".to_owned())?;
    let checksum_exit = lines
        .iter()
        .enumerate()
        .skip(checksum + 1)
        .find(|(_, line)| **line == "exit 1")
        .map(|(index, _)| index)
        .ok_or_else(|| "Unix checksum mismatch must exit".to_owned())?;
    let extract = lines
        .iter()
        .position(|line| line.starts_with("tar xf \"$download\""))
        .ok_or_else(|| "Unix archive extraction must be explicit".to_owned())?;
    let uniqueness = lines
        .iter()
        .position(|line| {
            *line
                == "dist_count=\"$(find \"$extracted\" -type f -name dist -print | wc -l | tr -d ' ')\""
        })
        .ok_or_else(|| "Unix installer must count every extracted dist executable".to_owned())?;
    let uniqueness_check = lines
        .iter()
        .position(|line| {
            *line
                == "if [ \"$dist_count\" != 1 ] || [ ! -f \"$extracted/dist\" ] || [ -L \"$extracted/dist\" ]; then"
        })
        .ok_or_else(|| "Unix installer must enforce one regular non-symlink executable".to_owned())?;
    let uniqueness_exit = lines
        .iter()
        .enumerate()
        .skip(uniqueness_check + 1)
        .find(|(_, line)| **line == "exit 1")
        .map(|(index, _)| index)
        .ok_or_else(|| "Unix executable uniqueness failure must exit".to_owned())?;
    let install = lines
        .iter()
        .position(|line| line.starts_with("install -m 755 \"$extracted/dist\""))
        .ok_or_else(|| "Unix validated executable installation must be explicit".to_owned())?;
    if !(checksum < checksum_exit
        && checksum_exit < extract
        && extract < uniqueness
        && uniqueness < uniqueness_check
        && uniqueness_check < uniqueness_exit
        && uniqueness_exit < install)
    {
        return Err("Unix checksum and uniqueness controls must precede installation".to_owned());
    }
    Ok(())
}

fn validate_installer_invocations(workflow: &str) -> Result<(), String> {
    let lines = active_lines(workflow).collect::<Vec<_>>();
    let unix = lines
        .iter()
        .filter(|line| **line == "run: sh .github/scripts/install-cargo-dist.sh")
        .count();
    let windows = lines
        .iter()
        .filter(|line| **line == "run: .github/scripts/install-cargo-dist.ps1")
        .count();
    if unix != 2 || windows != 1 {
        return Err("verified cargo-dist installers must be active on every host".to_owned());
    }
    Ok(())
}

fn validate_homebrew_style_is_unconditional(step: &str, style_command: &str) -> Result<(), String> {
    let lines = active_lines(step).collect::<Vec<_>>();
    if lines.iter().any(|line| line.starts_with("if:")) {
        return Err("Homebrew validation step must not have a workflow condition".to_owned());
    }
    let style = lines
        .iter()
        .position(|line| *line == style_command)
        .ok_or_else(|| "Homebrew style must be an active standalone command".to_owned())?;
    let release_loop = lines
        .iter()
        .position(|line| *line == BREW_RELEASE_LOOP)
        .ok_or_else(|| "Homebrew validation must iterate every formula release".to_owned())?;
    if release_loop >= style {
        return Err("Homebrew release iteration must contain style validation".to_owned());
    }
    if lines[..style]
        .iter()
        .any(|line| line.starts_with("if ") || line.starts_with("while "))
    {
        return Err("Homebrew style must not be hidden behind shell control flow".to_owned());
    }
    Ok(())
}

#[test]
fn cargo_dist_archives_are_verified_before_extraction() {
    let expected = [
        (
            "DIST_LINUX_GNU_AARCH64_SHA256",
            "cargo-dist-aarch64-unknown-linux-gnu.tar.xz",
            "d29bcffeb3f8b0c517b4ce0dd2470926ed5cb0bb29d78c6bdd5f88d76ee14a6a",
        ),
        (
            "DIST_LINUX_GNU_X86_64_SHA256",
            "cargo-dist-x86_64-unknown-linux-gnu.tar.xz",
            "eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946",
        ),
        (
            "DIST_LINUX_MUSL_AARCH64_SHA256",
            "cargo-dist-aarch64-unknown-linux-musl.tar.xz",
            "16d4394af9b91366ca92cb4601a72dd0a209a49301ef535749e2141039e26ed6",
        ),
        (
            "DIST_LINUX_MUSL_X86_64_SHA256",
            "cargo-dist-x86_64-unknown-linux-musl.tar.xz",
            "0d9dc001b0e937e9cc18e0dc11784aa7a3fd566656b07828d5e1d10ce1c1c48c",
        ),
        (
            "DIST_MACOS_AARCH64_SHA256",
            "cargo-dist-aarch64-apple-darwin.tar.xz",
            "aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7",
        ),
        (
            "DIST_MACOS_X86_64_SHA256",
            "cargo-dist-x86_64-apple-darwin.tar.xz",
            "6243464a8389e006b9256ee548bc795638f1a17113c1b6669c0e05ce89fd05c5",
        ),
    ];
    for (variable, _archive, hash) in expected {
        assert!(
            RELEASE_WORKFLOW.contains(&format!(r#"{variable}: "{hash}""#)),
            "missing pinned value for {variable}"
        );
    }
    let mut actual_pairs = unix_archive_hash_pairs(UNIX_DIST_INSTALLER)
        .expect("Unix archive/hash assignments must parse");
    actual_pairs.sort_unstable();
    let mut expected_pairs = expected
        .map(|(variable, archive, _)| (archive.to_owned(), variable.to_owned()))
        .to_vec();
    expected_pairs.sort_unstable();
    assert_eq!(actual_pairs, expected_pairs);
    let windows_hash = "26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3";
    assert!(RELEASE_WORKFLOW.contains(&format!(r#"DIST_WINDOWS_X86_64_SHA256: "{windows_hash}""#)));
    assert!(WINDOWS_DIST_INSTALLER.contains("cargo-dist-x86_64-pc-windows-msvc.zip"));
    assert!(WINDOWS_DIST_INSTALLER.contains("DIST_WINDOWS_X86_64_SHA256"));
    assert!(!RELEASE_WORKFLOW.contains("cargo-dist-installer.sh"));
    assert!(!RELEASE_WORKFLOW.contains("cargo-dist-installer.ps1"));
    validate_installer_invocations(RELEASE_WORKFLOW)
        .expect("verified cargo-dist installers must be active workflow commands");
    validate_unix_integrity_flow(UNIX_DIST_INSTALLER)
        .expect("Unix checksum and executable selection must fail closed");

    let unix_check = UNIX_DIST_INSTALLER
        .find("actual_sha256\" != \"$expected_sha256")
        .expect("Unix archive checksum comparison");
    let unix_extract = UNIX_DIST_INSTALLER
        .find("tar xf")
        .expect("Unix archive extraction");
    assert!(unix_check < unix_extract);
    let unix_uniqueness = UNIX_DIST_INSTALLER
        .find("dist_count=")
        .expect("Unix executable uniqueness check");
    let unix_install = UNIX_DIST_INSTALLER
        .find("install -m 755")
        .expect("Unix executable installation");
    assert!(unix_extract < unix_uniqueness);
    assert!(unix_uniqueness < unix_install);

    let windows_check = WINDOWS_DIST_INSTALLER
        .find("$actualSha256 -ne $expectedSha256")
        .expect("Windows archive checksum comparison");
    let windows_extract = WINDOWS_DIST_INSTALLER
        .find("Expand-Archive")
        .expect("Windows archive extraction");
    assert!(windows_check < windows_extract);
    validate_windows_executable_selection(WINDOWS_DIST_INSTALLER)
        .expect("Windows executable selection must fail closed");
}

#[test]
fn explicit_github_tokens_are_step_scoped_and_globally_accounted_for() {
    validate_repository_token_scope(RELEASE_WORKFLOW)
        .expect("repository tokens must remain step-scoped and globally accounted for");
}

#[test]
fn homebrew_validation_fails_closed_and_pat_exists_only_for_push() {
    const TAP_TOKEN: &str = "GH_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}";

    let workflow = normalized_workflow();
    validate_checkout_credentials(&workflow)
        .expect("every checkout must explicitly disable persisted credentials");
    assert!(!workflow.contains("token: ${{ secrets.HOMEBREW_TAP_TOKEN }}"));
    assert_eq!(
        workflow
            .matches("${{ secrets.HOMEBREW_TAP_TOKEN }}")
            .count(),
        1,
        "the tap PAT must have exactly one workflow reference"
    );

    let homebrew_job = workflow
        .split("  publish-homebrew-formula:\n")
        .nth(1)
        .and_then(|rest| rest.split("  announce:\n").next())
        .expect("Homebrew publication job");

    assert!(homebrew_job.contains("permissions:\n      contents: read"));
    assert!(!homebrew_job.contains("${{ secrets.GITHUB_TOKEN }}"));
    assert_eq!(homebrew_job.matches(TAP_TOKEN).count(), 1);

    let validation_step = homebrew_job
        .split("      - name: Commit formula files\n")
        .nth(1)
        .and_then(|rest| rest.split("      - name: Push formula files\n").next())
        .expect("credential-free Homebrew validation and commit step");

    assert!(validation_step.contains("shell: bash"));
    assert!(validation_step.contains("set -euo pipefail"));
    assert!(validation_step.contains("brew update"));
    assert!(
        validation_step
            .lines()
            .any(|line| line.trim() == BREW_STYLE),
        "brew style must be a standalone fail-closed command"
    );
    assert!(
        !validation_step
            .lines()
            .any(|line| line.contains("brew style") && line.contains("|| true")),
        "Homebrew validation failures must never be suppressed"
    );
    assert!(!validation_step.contains("continue-on-error"));
    assert!(!validation_step.contains("GH_TOKEN"));
    assert!(!validation_step.contains("HOMEBREW_TAP_TOKEN"));
    assert!(!validation_step.contains("secrets."));
    validate_homebrew_style_is_unconditional(validation_step, BREW_STYLE)
        .expect("Homebrew style must run unconditionally");

    let style = validation_step
        .find("brew style")
        .expect("Homebrew style command");
    let stage = validation_step
        .find("git add")
        .expect("formula staging command");
    let commit = validation_step
        .find("git diff --cached --quiet || git commit")
        .expect("formula commit command");
    assert!(style < stage);
    assert!(stage < commit);

    let push_step = homebrew_job
        .split("      - name: Push formula files\n")
        .nth(1)
        .expect("Homebrew push step");

    assert_eq!(push_step.matches(TAP_TOKEN).count(), 1);
    assert!(push_step.contains("gh auth setup-git"));
    assert!(push_step.contains("git push"));
    assert!(!push_step.contains("brew update"));
    assert!(!push_step.contains("brew style"));
}

#[test]
fn release_security_validators_reject_removed_or_miswired_controls() {
    let workflow = normalized_workflow();
    let missing_checkout_control =
        workflow.replacen("          persist-credentials: false\n", "", 1);
    assert!(validate_checkout_credentials(&missing_checkout_control).is_err());
    let commented_checkout_control = workflow.replacen(
        "          persist-credentials: false",
        "          # persist-credentials: false",
        1,
    );
    assert!(validate_checkout_credentials(&commented_checkout_control).is_err());

    let token_alias = format!(
        "{workflow}\n      - name: Forbidden token alias\n        env:\n          RELEASE_TOKEN: ${{{{ github[ 'token' ] }}}}\n"
    );
    assert!(validate_repository_token_scope(&token_alias).is_err());
    let misplaced_token = workflow
        .replacen("          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n", "", 1)
        .replacen(
            "      - name: Cache dist\n",
            "      - name: Cache dist\n        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
            1,
        );
    assert!(validate_repository_token_scope(&misplaced_token).is_err());
    let dynamic_token = format!(
        "{workflow}\n      - name: Forbidden dynamic token\n        env:\n          TOKEN_NAME: GITHUB_TOKEN\n          RELEASE_TOKEN: ${{{{ secrets[env.TOKEN_NAME] }}}}\n"
    );
    assert!(validate_repository_token_scope(&dynamic_token).is_err());

    let commented_installer = workflow.replacen(
        "        run: sh .github/scripts/install-cargo-dist.sh",
        "        run: cargo install cargo-dist # sh .github/scripts/install-cargo-dist.sh",
        1,
    );
    assert!(validate_installer_invocations(&commented_installer).is_err());
    let conditional_homebrew = workflow.replacen(
        "      - name: Commit formula files\n        shell: bash",
        "      - name: Commit formula files\n        if: ${{ false }}\n        shell: bash",
        1,
    );
    let conditional_step = conditional_homebrew
        .split("      - name: Commit formula files\n")
        .nth(1)
        .and_then(|rest| rest.split("      - name: Push formula files\n").next())
        .expect("mutated Homebrew validation step");
    assert!(validate_homebrew_style_is_unconditional(conditional_step, BREW_STYLE).is_err());
    let empty_homebrew_loop = workflow.replace(BREW_RELEASE_LOOP, "for release in; do");
    let empty_loop_step = empty_homebrew_loop
        .split("      - name: Commit formula files\n")
        .nth(1)
        .and_then(|rest| rest.split("      - name: Push formula files\n").next())
        .expect("mutated Homebrew validation loop");
    assert!(validate_homebrew_style_is_unconditional(empty_loop_step, BREW_STYLE).is_err());

    let swapped_hash = UNIX_DIST_INSTALLER
        .replacen("DIST_MACOS_AARCH64_SHA256", "DIST_TEMPORARY_SHA256", 1)
        .replacen("DIST_MACOS_X86_64_SHA256", "DIST_MACOS_AARCH64_SHA256", 1)
        .replacen("DIST_TEMPORARY_SHA256", "DIST_MACOS_X86_64_SHA256", 1);
    let mut actual_pairs = unix_archive_hash_pairs(&swapped_hash)
        .expect("mutated Unix archive/hash assignments must remain parseable");
    actual_pairs.sort_unstable();
    let mut expected_pairs = unix_archive_hash_pairs(UNIX_DIST_INSTALLER)
        .expect("current Unix archive/hash assignments must parse");
    expected_pairs.sort_unstable();
    assert_ne!(actual_pairs, expected_pairs);

    let missing_windows_uniqueness =
        WINDOWS_DIST_INSTALLER.replace("if ($binaries.Count -ne 1)", "if ($false)");
    assert!(validate_windows_executable_selection(&missing_windows_uniqueness).is_err());
    let commented_windows_uniqueness = WINDOWS_DIST_INSTALLER.replace(
        "    if ($binaries.Count -ne 1) {",
        "    # if ($binaries.Count -ne 1) {\n    if ($false) {",
    );
    assert!(validate_windows_executable_selection(&commented_windows_uniqueness).is_err());

    let disabled_unix_checksum = UNIX_DIST_INSTALLER.replace(
        "if [ \"$actual_sha256\" != \"$expected_sha256\" ]; then",
        "if false; then # [ \"$actual_sha256\" != \"$expected_sha256\" ]; then",
    );
    assert!(validate_unix_integrity_flow(&disabled_unix_checksum).is_err());
    let weakened_unix_uniqueness = UNIX_DIST_INSTALLER.replace(
        "dist_count=\"$(find \"$extracted\" -type f -name dist -print | wc -l | tr -d ' ')\"",
        "dist_count=1",
    );
    assert!(validate_unix_integrity_flow(&weakened_unix_uniqueness).is_err());
    let disabled_unix_uniqueness = UNIX_DIST_INSTALLER.replace(
        "if [ \"$dist_count\" != 1 ] || [ ! -f \"$extracted/dist\" ] || [ -L \"$extracted/dist\" ]; then",
        "if false; then # uniqueness disabled",
    );
    assert!(validate_unix_integrity_flow(&disabled_unix_uniqueness).is_err());

    let weakened_windows_uniqueness = WINDOWS_DIST_INSTALLER.replace(
        "$binaries = @(Get-ChildItem -Path $extracted -Filter \"dist.exe\" -File -Recurse)",
        "$binaries = @(Get-ChildItem -Path $extracted -Filter \"dist.exe\" -File -Recurse | Select-Object -First 1)",
    );
    assert!(validate_windows_executable_selection(&weakened_windows_uniqueness).is_err());
    let disabled_windows_checksum = WINDOWS_DIST_INSTALLER.replace(
        "if ($actualSha256 -ne $expectedSha256) {",
        "if ($false -and ($actualSha256 -ne $expectedSha256)) {",
    );
    assert!(validate_windows_executable_selection(&disabled_windows_checksum).is_err());
}

#[test]
fn release_plan_installer_has_no_repository_token() {
    let workflow = normalized_workflow();
    let plan_job = workflow
        .split("  plan:\n")
        .nth(1)
        .and_then(|rest| rest.split("  build-local-artifacts:\n").next())
        .expect("plan job block");
    assert!(plan_job.contains("permissions:\n      contents: read"));

    let install_step = plan_job
        .split("      - name: Install dist\n")
        .nth(1)
        .and_then(|rest| rest.split("      - name: Cache dist\n").next())
        .expect("plan installer step");
    assert!(!install_step.contains("GH_TOKEN"));
    assert!(!install_step.contains("GITHUB_TOKEN"));

    let plan_step = plan_job
        .split("      - id: plan\n")
        .nth(1)
        .expect("dist plan step");
    assert!(plan_step.contains("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"));
}

#[test]
fn explicit_release_token_is_scoped_to_publication_commands() {
    let workflow = normalized_workflow();
    let host_job = workflow
        .split("  host:\n")
        .nth(1)
        .and_then(|rest| rest.split("  publish-homebrew-formula:\n").next())
        .expect("host job block");
    assert!(host_job.contains("permissions:\n      contents: write"));
    assert!(!host_job.contains("\n    env:\n      GH_TOKEN:"));
    assert_eq!(
        host_job
            .matches("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}")
            .count(),
        2
    );

    let setup = host_job
        .split("      - id: host\n")
        .next()
        .expect("host setup steps");
    assert!(!setup.contains("GH_TOKEN"));
    let host_step = host_job
        .split("      - id: host\n")
        .nth(1)
        .and_then(|rest| {
            rest.split("      - name: \"Upload dist-manifest.json\"\n")
                .next()
        })
        .expect("dist host step");
    assert!(host_step.contains("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"));
    let release_step = host_job
        .split("      - name: Create GitHub Release\n")
        .nth(1)
        .expect("GitHub release step");
    assert!(release_step.contains("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"));
}
