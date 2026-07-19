# Security Policy

## Supported Versions

Security fixes are provided for the latest published release. Upgrade to the
newest GitHub Release before reporting behavior that may already be fixed.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory form for this repository:

<https://github.com/nuggocto/kickoutchi/security/advisories/new>

Include the affected version and platform, the required local permissions,
reproduction steps, impact, and the least sensitive evidence needed to explain
the issue. Do not include credentials, personal command lines, or another
user's process metadata.

You should receive an acknowledgement within seven days. No testing against
third-party or production systems is authorized by this policy.

## Sensitive Output

`list --json` is a compatibility interface and can include process names,
executable paths, and command lines. Command lines may contain tokens or other
secrets. Treat structured output as sensitive, avoid publishing it unchanged,
and redact it before attaching it to reports.

Kickoutchi does not require elevated privileges for ordinary use. Do not run it
as root or Administrator merely to obtain more metadata unless you understand
the expanded process visibility and termination authority.
