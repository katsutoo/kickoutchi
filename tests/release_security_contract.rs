const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
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

fn workflow_job<'a>(workflow: &'a str, name: &str, next: Option<&str>) -> Result<&'a str, String> {
    let start = format!("  {name}:\n");
    let job = workflow
        .split(&start)
        .nth(1)
        .ok_or_else(|| format!("workflow is missing job {name}"))?;
    match next {
        Some(next) => job
            .split(&format!("\n  {next}:\n"))
            .next()
            .ok_or_else(|| format!("workflow job {name} has no boundary")),
        None => Ok(job),
    }
}

fn validate_native_ci_policy(workflow: &str) -> Result<(), String> {
    const REQUIRED: [&str; 5] = [
        "run: cargo fmt --all --check",
        "run: cargo clippy --locked --all-targets --all-features -- -D warnings",
        "run: cargo test --locked --all-features --doc",
        "run: cargo build --locked --release --all-features --bin kickoutchi --bin kick",
        "run: cargo test --locked --all-features --test cli_contract",
    ];
    if active_lines(workflow)
        .filter(|line| *line == "RUST_VERSION: 1.95.0")
        .count()
        != 1
    {
        return Err("native CI must pin the approved Rust toolchain exactly once".to_owned());
    }
    for (name, next) in [
        ("linux", Some("windows")),
        ("windows", Some("macos")),
        ("macos", None),
    ] {
        let job = workflow_job(workflow, name, next)?;
        let lines = active_lines(job).collect::<Vec<_>>();
        if !lines.contains(&"needs: supply-chain") {
            return Err(format!(
                "native job {name} must depend on the supply-chain gate"
            ));
        }
        for command in REQUIRED {
            if !lines.contains(&command) {
                return Err(format!("native job {name} is missing {command}"));
            }
        }
        let ordinary_test = if name == "linux" {
            "run: KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features"
        } else {
            "run: cargo test --locked --all-features"
        };
        if !lines.contains(&ordinary_test)
            || lines
                .iter()
                .filter(|line| **line == "KICKOUTCHI_RELEASE_E2E_REQUIRED: \"1\"")
                .count()
                != 1
        {
            return Err(format!(
                "native job {name} must execute journeys against explicit release binaries"
            ));
        }
        let expected_paths = if name == "windows" {
            [
                "KICKOUTCHI_E2E_KICKOUTCHI: ${{ github.workspace }}\\target\\release\\kickoutchi.exe",
                "KICKOUTCHI_E2E_KICK: ${{ github.workspace }}\\target\\release\\kick.exe",
            ]
        } else {
            [
                "KICKOUTCHI_E2E_KICKOUTCHI: ${{ github.workspace }}/target/release/kickoutchi",
                "KICKOUTCHI_E2E_KICK: ${{ github.workspace }}/target/release/kick",
            ]
        };
        if !expected_paths.iter().all(|line| lines.contains(line)) {
            return Err(format!(
                "native job {name} must use release-profile binary paths"
            ));
        }
        if !job.contains("persist-credentials: false")
            || job.contains("continue-on-error:")
            || job.contains("||")
            || lines.iter().any(|line| line.starts_with("if:"))
        {
            return Err(format!("native job {name} must fail closed"));
        }
    }
    let linux = workflow_job(workflow, "linux", Some("windows"))?;
    if linux
        .matches("KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES: \"1\"")
        .count()
        != 1
        || !linux.contains(
            "run: KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features",
        )
    {
        return Err("Linux native capabilities must be required for both test passes".to_owned());
    }
    let supply_chain = workflow_job(workflow, "supply-chain", Some("linux"))?;
    let supply_chain_lines = active_lines(supply_chain).collect::<Vec<_>>();
    if !supply_chain.contains("persist-credentials: false")
        || !supply_chain.contains("run: python3 .github/scripts/test_validate_release_artifact.py")
        || !supply_chain.contains("run: cargo deny check")
        || supply_chain.contains("continue-on-error:")
        || supply_chain_lines.iter().any(|line| {
            line.starts_with("if:") || (line.starts_with("run:") && line.contains("||"))
        })
    {
        return Err(
            "supply-chain policy must run the validator and cargo-deny fail closed".to_owned(),
        );
    }
    Ok(())
}

fn validate_artifact_dependencies_and_tag(workflow: &str, local_job: &str) -> Result<(), String> {
    let local_needs = local_job
        .split("    needs:\n")
        .nth(1)
        .and_then(|needs| needs.split("\n    if:").next())
        .ok_or_else(|| "local artifact job must declare bounded dependencies".to_owned())?;
    if active_lines(local_needs).collect::<Vec<_>>() != ["- plan", "- verify"] {
        return Err(
            "local artifacts must depend on planning and exact-commit verification".to_owned(),
        );
    }
    let build_step = local_job
        .split("      - name: Build artifacts\n")
        .nth(1)
        .and_then(|step| step.split("      - id: cargo-dist\n").next())
        .ok_or_else(|| "local artifact build step must be bounded".to_owned())?;
    let build_lines = active_lines(build_step).collect::<Vec<_>>();
    if !build_lines.contains(&"shell: bash")
        || !build_lines.contains(&"TAG_FLAG: ${{ needs.plan.outputs.tag-flag }}")
        || !build_lines.contains(
            &"dist build $TAG_FLAG --print=linkage --output-format=json ${{ matrix.dist_args }} > dist-manifest.json",
        )
        || build_lines.iter().any(|line| line.starts_with("if:"))
    {
        return Err(
            "local artifact builds must propagate the release tag through explicit Bash"
                .to_owned(),
        );
    }
    let global = workflow_job(workflow, "build-global-artifacts", Some("host"))?;
    let global_needs = global
        .split("    needs:\n")
        .nth(1)
        .and_then(|needs| needs.split("\n    runs-on:").next())
        .ok_or_else(|| "global artifact job must declare bounded dependencies".to_owned())?;
    if active_lines(global_needs).collect::<Vec<_>>()
        != ["- plan", "- verify", "- build-local-artifacts"]
    {
        return Err(
            "global artifacts must depend on planning, verification, and native artifacts"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_release_archive_gate(workflow: &str) -> Result<(), String> {
    let job = workflow_job(
        workflow,
        "build-local-artifacts",
        Some("build-global-artifacts"),
    )?;
    validate_artifact_dependencies_and_tag(workflow, job)?;
    let build = job
        .find("      - name: Build artifacts\n")
        .ok_or_else(|| "release workflow must build local artifacts".to_owned())?;
    let unix = job
        .find("      - name: Validate native release archive (Unix)\n")
        .ok_or_else(|| "release workflow must validate Unix archives".to_owned())?;
    let windows = job
        .find("      - name: Validate native release archive (Windows)\n")
        .ok_or_else(|| "release workflow must validate Windows archives".to_owned())?;
    let upload = job
        .find("      - name: \"Upload artifacts\"\n")
        .ok_or_else(|| "release workflow must upload validated artifacts".to_owned())?;
    if !(build < unix && unix < windows && windows < upload) {
        return Err("native archive validation must run after build and before upload".to_owned());
    }
    if job
        .matches(".github/scripts/validate-release-artifact.py")
        .count()
        != 2
        || !job.contains("--targets-json")
        || !job.contains("--runner-os")
        || !job.contains("--runner-arch")
    {
        return Err("native archive validators must receive explicit matrix identity".to_owned());
    }
    let unix_step = job
        .split("      - name: Validate native release archive (Unix)\n")
        .nth(1)
        .and_then(|step| {
            step.split("      - name: Validate native release archive (Windows)\n")
                .next()
        })
        .ok_or_else(|| "Unix archive validation step must be bounded".to_owned())?;
    let windows_step = job
        .split("      - name: Validate native release archive (Windows)\n")
        .nth(1)
        .and_then(|step| step.split("      - name: \"Upload artifacts\"\n").next())
        .ok_or_else(|| "Windows archive validation step must be bounded".to_owned())?;
    for (step, condition, interpreter) in [
        (unix_step, "if: runner.os != 'Windows'", "python3"),
        (windows_step, "if: runner.os == 'Windows'", "python"),
    ] {
        let conditions = active_lines(step)
            .filter(|line| line.starts_with("if:"))
            .collect::<Vec<_>>();
        if conditions != [condition]
            || !step.contains("TARGETS_JSON: ${{ toJSON(matrix.targets) }}")
            || !step.contains("--runner-os \"${{ runner.os }}\"")
            || !step.contains("--runner-arch \"${{ runner.arch }}\"")
            || !step.contains(&format!(
                "{interpreter} .github/scripts/validate-release-artifact.py"
            ))
        {
            return Err("native archive validator wiring must remain exact".to_owned());
        }
    }
    if job.contains("continue-on-error:") || job.contains("|| true") {
        return Err("native archive validation must fail closed".to_owned());
    }
    let host = workflow_job(workflow, "host", Some("publish-homebrew-formula"))?;
    if !host.contains("needs.build-global-artifacts.result == 'success'")
        || !host.contains("needs.build-local-artifacts.result == 'success'")
        || host.contains("needs.build-global-artifacts.result == 'skipped'")
        || host.contains("needs.build-local-artifacts.result == 'skipped'")
    {
        return Err("publication must require successful artifact builds".to_owned());
    }
    Ok(())
}

fn validate_release_verify_matrix(workflow: &str, verify: &str) -> Result<(), String> {
    if active_lines(workflow)
        .filter(|line| *line == "RUST_VERSION: \"1.95.0\"")
        .count()
        != 1
    {
        return Err("release verification must pin the approved Rust toolchain".to_owned());
    }
    let matrix = verify
        .split("      matrix:\n")
        .nth(1)
        .and_then(|matrix| matrix.split("\n    runs-on:").next())
        .ok_or_else(|| "release verification matrix must be bounded".to_owned())?;
    let expected_matrix = [
        "include:",
        "- name: Linux",
        "runner: ubuntu-latest",
        "- name: Windows",
        "runner: windows-latest",
        "- name: macOS",
        "runner: macos-latest",
        "- name: Supply Chain",
        "runner: ubuntu-latest",
    ];
    if active_lines(matrix).collect::<Vec<_>>() != expected_matrix {
        return Err(
            "release verification must contain the exact native and supply-chain matrix".to_owned(),
        );
    }
    Ok(())
}

fn validate_release_verify_policy(workflow: &str) -> Result<(), String> {
    let verify = workflow_job(workflow, "verify", Some("plan"))?;
    validate_release_verify_matrix(workflow, verify)?;
    let lines = active_lines(verify).collect::<Vec<_>>();
    for command in [
        "run: cargo fmt --all --check",
        "run: cargo clippy --locked --all-targets --all-features -- -D warnings",
        "run: KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features",
        "run: cargo test --locked --all-features",
        "run: cargo test --locked --all-features --doc",
        "run: cargo build --locked --release --all-features --bin kickoutchi --bin kick",
        "run: cargo test --locked --all-features --test cli_contract",
        "run: python3 .github/scripts/test_validate_release_artifact.py",
        "run: cargo deny check",
    ] {
        if !lines.contains(&command) {
            return Err(format!("release verification is missing {command}"));
        }
    }
    for path in [
        "KICKOUTCHI_E2E_KICKOUTCHI: ${{ github.workspace }}/target/release/kickoutchi",
        "KICKOUTCHI_E2E_KICK: ${{ github.workspace }}/target/release/kick",
        "KICKOUTCHI_E2E_KICKOUTCHI: ${{ github.workspace }}\\target\\release\\kickoutchi.exe",
        "KICKOUTCHI_E2E_KICK: ${{ github.workspace }}\\target\\release\\kick.exe",
    ] {
        if !verify.contains(path) {
            return Err("release verification must use release-profile binaries".to_owned());
        }
    }
    for (name, condition) in [
        (
            "Enable unprivileged user namespaces",
            "if: matrix.name == 'Linux'",
        ),
        ("Check formatting", "if: matrix.name != 'Supply Chain'"),
        ("Run strict Clippy", "if: matrix.name != 'Supply Chain'"),
        (
            "Run tests (Linux capabilities required)",
            "if: matrix.name == 'Linux'",
        ),
        (
            "Run tests",
            "if: matrix.name == 'Windows' || matrix.name == 'macOS'",
        ),
        ("Run doctests", "if: matrix.name != 'Supply Chain'"),
        (
            "Build release binaries",
            "if: matrix.name != 'Supply Chain'",
        ),
        (
            "Run release binary journeys (Linux)",
            "if: matrix.name == 'Linux'",
        ),
        (
            "Run release binary journeys (Windows)",
            "if: matrix.name == 'Windows'",
        ),
        (
            "Run release binary journeys (macOS)",
            "if: matrix.name == 'macOS'",
        ),
        (
            "Test release artifact validator",
            "if: matrix.name == 'Supply Chain'",
        ),
        (
            "Run supply-chain policy",
            "if: matrix.name == 'Supply Chain'",
        ),
    ] {
        let step = verify
            .split(&format!("      - name: {name}\n"))
            .nth(1)
            .and_then(|step| step.split("      - name:").next())
            .ok_or_else(|| format!("release verification is missing step {name}"))?;
        let conditions = active_lines(step)
            .filter(|line| line.starts_with("if:"))
            .collect::<Vec<_>>();
        if conditions != [condition] {
            return Err(format!(
                "release verification step {name} has the wrong condition"
            ));
        }
    }
    if verify.contains("continue-on-error:")
        || active_lines(verify).any(|line| line.starts_with("run:") && line.contains("||"))
    {
        return Err("release verification must fail closed".to_owned());
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
fn native_ci_and_release_archives_fail_closed() {
    validate_native_ci_policy(CI_WORKFLOW)
        .expect("every native CI job must run the complete release-candidate policy");
    validate_release_archive_gate(RELEASE_WORKFLOW)
        .expect("cargo-dist archives must pass native E2E before upload");
    validate_release_verify_policy(RELEASE_WORKFLOW)
        .expect("release workflow must repeat the native policy on its exact commit");
}

#[test]
fn native_ci_policy_rejects_removed_or_bypassed_gates() {
    let missing_doctest = CI_WORKFLOW.replacen(
        "      - name: Run doctests\n        run: cargo test --locked --all-features --doc\n",
        "",
        1,
    );
    assert!(validate_native_ci_policy(&missing_doctest).is_err());
    let unpinned_ci_toolchain =
        CI_WORKFLOW.replacen("RUST_VERSION: 1.95.0", "RUST_VERSION: stable", 1);
    assert!(validate_native_ci_policy(&unpinned_ci_toolchain).is_err());
    let missing_supply_chain_dependency = CI_WORKFLOW.replacen("    needs: supply-chain\n", "", 1);
    assert!(validate_native_ci_policy(&missing_supply_chain_dependency).is_err());
    let disabled_supply_chain = CI_WORKFLOW.replacen(
        "  supply-chain:\n    name: Supply Chain\n",
        "  supply-chain:\n    name: Supply Chain\n    if: ${{ false }}\n",
        1,
    );
    assert!(validate_native_ci_policy(&disabled_supply_chain).is_err());
    let weakened_build = CI_WORKFLOW.replacen(
        "cargo build --locked --release --all-features --bin kickoutchi --bin kick",
        "cargo build --locked --release --bin kickoutchi",
        1,
    );
    assert!(validate_native_ci_policy(&weakened_build).is_err());
    let missing_artifact_paths =
        CI_WORKFLOW.replacen("          KICKOUTCHI_RELEASE_E2E_REQUIRED: \"1\"\n", "", 1);
    assert!(validate_native_ci_policy(&missing_artifact_paths).is_err());
    let tolerated_failure = CI_WORKFLOW.replacen(
        "      - name: Run release binary journeys\n",
        "      - name: Run release binary journeys\n        continue-on-error: true\n",
        1,
    );
    assert!(validate_native_ci_policy(&tolerated_failure).is_err());
    let hidden_command = CI_WORKFLOW.replacen(
        "        run: cargo test --locked --all-features --doc",
        "        run: true || cargo test --locked --all-features --doc",
        1,
    );
    assert!(validate_native_ci_policy(&hidden_command).is_err());
    let debug_artifact =
        CI_WORKFLOW.replacen("target/release/kickoutchi", "target/debug/kickoutchi", 1);
    assert!(validate_native_ci_policy(&debug_artifact).is_err());
    let disabled_native_job = CI_WORKFLOW.replacen(
        "  linux:\n    name: Linux\n",
        "  linux:\n    name: Linux\n    if: ${{ false }}\n",
        1,
    );
    assert!(validate_native_ci_policy(&disabled_native_job).is_err());
}

#[test]
fn release_archive_policy_rejects_removed_or_bypassed_gates() {
    let missing_unix_validation = RELEASE_WORKFLOW.replacen(
        "      - name: Validate native release archive (Unix)\n",
        "      - name: Removed native release archive validation (Unix)\n",
        1,
    );
    assert!(validate_release_archive_gate(&missing_unix_validation).is_err());
    let missing_local_verification_dependency = RELEASE_WORKFLOW.replacen(
        "      - plan\n      - verify\n    if:",
        "      - plan\n    if:",
        1,
    );
    assert!(validate_release_archive_gate(&missing_local_verification_dependency).is_err());
    let missing_global_verification_dependency = RELEASE_WORKFLOW.replacen(
        "      - plan\n      - verify\n      - build-local-artifacts\n    runs-on:",
        "      - plan\n      - build-local-artifacts\n    runs-on:",
        1,
    );
    assert!(validate_release_archive_gate(&missing_global_verification_dependency).is_err());
    let implicit_windows_build_shell = RELEASE_WORKFLOW.replacen(
        "      - name: Build artifacts\n        shell: bash\n",
        "      - name: Build artifacts\n",
        1,
    );
    assert!(validate_release_archive_gate(&implicit_windows_build_shell).is_err());
    let validation_after_upload = RELEASE_WORKFLOW
        .replacen(
            "      - name: Validate native release archive (Unix)\n",
            "      - name: Deferred native release archive validation (Unix)\n",
            1,
        )
        .replacen(
            "      - name: \"Upload artifacts\"\n",
            "      - name: \"Upload artifacts\"\n      - name: Validate native release archive (Unix)\n",
            1,
        );
    assert!(validate_release_archive_gate(&validation_after_upload).is_err());
    let disabled_archive_validation = RELEASE_WORKFLOW.replacen(
        "      - name: Validate native release archive (Unix)\n        if: runner.os != 'Windows'",
        "      - name: Validate native release archive (Unix)\n        if: ${{ false }}",
        1,
    );
    assert!(validate_release_archive_gate(&disabled_archive_validation).is_err());
    let skipped_artifact_publication = RELEASE_WORKFLOW.replacen(
        "needs.build-local-artifacts.result == 'success'",
        "(needs.build-local-artifacts.result == 'skipped' || needs.build-local-artifacts.result == 'success')",
        1,
    );
    assert!(validate_release_archive_gate(&skipped_artifact_publication).is_err());
}

#[test]
fn release_verify_policy_rejects_removed_or_bypassed_gates() {
    let missing_release_doctest = RELEASE_WORKFLOW.replacen(
        "        run: cargo test --locked --all-features --doc\n",
        "        run: cargo test --locked --all-features --lib\n",
        1,
    );
    assert!(validate_release_verify_policy(&missing_release_doctest).is_err());
    let unpinned_release_toolchain =
        RELEASE_WORKFLOW.replacen("RUST_VERSION: \"1.95.0\"", "RUST_VERSION: stable", 1);
    assert!(validate_release_verify_policy(&unpinned_release_toolchain).is_err());
    let missing_macos_verification = RELEASE_WORKFLOW.replacen(
        "          - name: macOS\n            runner: macos-latest\n",
        "",
        1,
    );
    assert!(validate_release_verify_policy(&missing_macos_verification).is_err());
    let bypassed_release_doctest = RELEASE_WORKFLOW.replacen(
        "        run: cargo test --locked --all-features --doc\n",
        "        run: true || cargo test --locked --all-features --doc\n",
        1,
    );
    assert!(validate_release_verify_policy(&bypassed_release_doctest).is_err());
    let disabled_release_build = RELEASE_WORKFLOW.replacen(
        "      - name: Build release binaries\n        if: matrix.name != 'Supply Chain'",
        "      - name: Build release binaries\n        if: ${{ false }}",
        1,
    );
    assert!(validate_release_verify_policy(&disabled_release_build).is_err());
    let disabled_release_linux_tests = RELEASE_WORKFLOW.replacen(
        "      - name: Run tests (Linux capabilities required)\n        if: matrix.name == 'Linux'",
        "      - name: Run tests (Linux capabilities required)\n        if: ${{ false }}",
        1,
    );
    assert!(validate_release_verify_policy(&disabled_release_linux_tests).is_err());
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
