const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const UNIX_DIST_INSTALLER: &str = include_str!("../.github/scripts/install-cargo-dist.sh");
const WINDOWS_DIST_INSTALLER: &str = include_str!("../.github/scripts/install-cargo-dist.ps1");

fn normalized_workflow() -> String {
    RELEASE_WORKFLOW.replace("\r\n", "\n")
}

#[test]
fn cargo_dist_archives_are_verified_before_extraction() {
    for (variable, archive, hash) in [
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
    ] {
        assert!(
            RELEASE_WORKFLOW.contains(&format!(r#"{variable}: "{hash}""#)),
            "missing pinned value for {variable}"
        );
        assert!(UNIX_DIST_INSTALLER.contains(archive));
        assert!(UNIX_DIST_INSTALLER.contains(variable));
    }
    let windows_hash = "26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3";
    assert!(RELEASE_WORKFLOW.contains(&format!(r#"DIST_WINDOWS_X86_64_SHA256: "{windows_hash}""#)));
    assert!(WINDOWS_DIST_INSTALLER.contains("cargo-dist-x86_64-pc-windows-msvc.zip"));
    assert!(WINDOWS_DIST_INSTALLER.contains("DIST_WINDOWS_X86_64_SHA256"));
    assert!(!RELEASE_WORKFLOW.contains("cargo-dist-installer.sh"));
    assert!(!RELEASE_WORKFLOW.contains("cargo-dist-installer.ps1"));
    assert_eq!(
        RELEASE_WORKFLOW
            .matches("sh .github/scripts/install-cargo-dist.sh")
            .count(),
        2
    );
    assert_eq!(
        RELEASE_WORKFLOW
            .matches(".github/scripts/install-cargo-dist.ps1")
            .count(),
        1
    );

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
}

#[test]
fn explicit_github_tokens_are_step_scoped_and_globally_accounted_for() {
    const TOKEN: &str = "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}";

    assert_eq!(
        RELEASE_WORKFLOW.matches(TOKEN).count(),
        3,
        "only plan, dist host, and GitHub release creation need explicit GH_TOKEN"
    );

    for line in RELEASE_WORKFLOW.lines().filter(|line| line.trim() == TOKEN) {
        assert_eq!(
            line,
            format!("          {TOKEN}"),
            "GH_TOKEN must be nested under a step-level env block"
        );
    }
}

#[test]
fn homebrew_validation_fails_closed_and_pat_exists_only_for_push() {
    const TAP_TOKEN: &str = "GH_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}";
    const BREW_STYLE: &str = r#"brew style --except-cops FormulaAudit/Homepage,FormulaAudit/Desc,FormulaAuditStrict --fix "Formula/${filename}""#;

    let workflow = normalized_workflow();
    assert!(!workflow.contains("persist-credentials: true"));
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
