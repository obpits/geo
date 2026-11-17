# geo: working context for Claude Code

A Go service behind a five-stage GitHub Actions pipeline, now being extended with a vulnerability
remediation agent. Design lives in AGENT_DESIGN.md. Read it before changing anything under cmd/remediate
or .github/workflows.

## INVARIANTS. These are not preferences.

- **The agent binary must never import or call a GitHub client, and must never read GITHUB_TOKEN.**
  It reads findings and source from disk and writes result.json, patch.diff and trace.jsonl to disk.
  Publishing is a separate job. If a change requires the agent to talk to GitHub, the change is wrong.
- **The agent-remediate job keeps `permissions: contents: read`.** It never gains write access, in any
  phase. `pull-requests: write` belongs only to the publish job, which contains no model call.
- **`.github/**` is denied to every file-reading and file-writing tool the agent exposes.** An agent that
  can edit the workflow constraining it has no constraints.
- **Agent-authored pull requests target the originating feature branch, never main.** The branch name is
  constructed in the publish step from the PR number and SHA, never supplied by the model.
- **Verification attempts are bounded at three, with a token ceiling and a wall-clock timeout.**
- **Every model request and response is written to trace.jsonl and uploaded as an artifact.**
- **Scanner output, dependency metadata, code comments and commit messages are untrusted input.**
  Mitigation is architectural, not a better prompt.

## Conventions

- Go version comes from go.mod. Do not pin it separately anywhere.
- Parse Snyk output against real captured fixtures, never against the documented schema.
- Say nothing on a pull request when there are no findings.
- Record model identifier, prompt version, tokens, cost and duration on every run.