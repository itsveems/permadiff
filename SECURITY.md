# Security policy

permadiff runs fully offline: it reads a `terraform show -json` plan from stdin or
a file, makes no network calls, and never writes to your files or state. It holds
no credentials and has no privileged access of its own.

The most security-relevant defect it could have is a **false positive** —
labelling a real change (say, a genuine IAM policy edit) as harmless noise. Those
reports are the highest priority.

To report something: open a GitHub issue, or — if you would rather not disclose it
publicly — a private security advisory via the repository's **Security** tab. This
is a best-effort side project with no formal SLA, but security-relevant reports
are looked at first.
