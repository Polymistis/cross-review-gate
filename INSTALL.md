# INSTALL — cross-review-gate

The gate is installed once per machine as a central runtime and reached by each
project through the central launcher. The operator procedure, with every
command and parameter, is [Central deployment v1](docs/central-deployment-v1.md);
this guide summarises it and adds the reviewer configuration a machine needs.

## Prerequisites

- Windows PowerShell 5.1 (`powershell.exe`).
- Git for Windows 2.41 or later. Source publication probes Git's global
  `--attr-source=<tree>` option, with `check-attr` and with
  `hash-object --path --stdin`, and refuses when either probe fails.
- The reviewer CLIs the attached projects use: Codex CLI, Claude Code 2.1.248
  or later, or both (configuration below). Grok fallback is enabled per project
  through reviewed project configuration.
- An absolute machine-local runtime store outside source repositories, project
  Git metadata and extracted release input, whose parent folder exists.

## Installation outline

Each step names the section of `docs/central-deployment-v1.md` that holds the
procedure.

1. **Prepare the operator session** ("Prepare the operator session"): clear the
   Git selector variables `bootstrap.ps1` refuses, and copy the approved
   `bootstrap.ps1`, or the portable archive, that the chosen procedure names
   into a private working folder before checking its hash.
2. **Publish or import one approved release** ("Publish a normally reviewed
   source revision", or "Import a portable package without source Git
   metadata"). `bootstrap.ps1 -PublishRuntime` stores the release under
   `releases/<release-id>` in the store and reports the release ID; it does not
   activate the release or change any project.
3. **Install the stable launcher once, then activate** ("Install the stable
   launcher once, then activate"): `-InstallRuntimeLauncher` for a new store,
   or `-UpgradeRuntimeLauncher` for the explicit migration of an existing
   store, then `-ActivateRuntime`. An ABI 3 store migrates once to ABI 4, in
   the maintenance window that section describes; an ABI 2 store migrates to
   ABI 3 with an approved ABI 3 release, then to ABI 4.
4. **Attach each project** ("Prepare the first project attachment"): prepare
   `.crg-project/project.conf`, `CROSS-REVIEW-VALUES.md`, the discovery section
   in `AGENTS.md` and `CLAUDE.md`, the private plan that section names, and
   `PROJECT-MODE.md` as that section describes, then run the launcher's
   `-Attach`, which performs the first complete review.
5. **Work through the launcher** ("Ordinary work and interrupted publication"):
   `-Open`, `-Stage`, `-Commit` and `-Resume`. Native `git commit` is refused.

Later compatible upgrades and rollback publish or import a release and run the
same `-ActivateRuntime` command once ("Upgrade and rollback"); attached
projects need no per-project step. Sandboxed agent sessions need no permission
exception ("Agent sessions and sandboxes").

Record the completion evidence that the "Completion evidence" section lists.

## Configure Codex (if a project uses the Codex reviewer)

The wrapper passes `-s read-only -c approval_policy="never"` to Codex
PER-INVOCATION. That means you do NOT need to lock down sandbox or
approval in your global `~/.codex/config.toml` — the wrapper handles
it for the review session only, and your interactive Codex sessions
keep their normal capabilities.

Minimum required `~/.codex/config.toml` contents (configure once on
the machine):

```toml
model = "gpt-6-sol"
model_reasoning_effort = "xhigh"
```

(Adjust `model` / effort as needed; the gate was originally tuned
against `gpt-5.5`. With a ChatGPT account, `gpt-6-sol` requires Codex
CLI 0.156 or later; 0.154 rejects it with HTTP 400. `xhigh` is the recommended effort for adversarial
review.)

Do NOT add sandbox or approval pinning here — the wrapper supplies
those per-invocation.

## Configure Claude auth (if a project uses the Claude reviewer)

Install Claude Code 2.1.248 or later. The wrapper parses `claude --version`
and fails closed before review launch when the executable is absent, older, or
does not return the supported version format.

**Default path (recommended)**: log in to Claude Code interactively
once on the machine:

```powershell
claude
```

Complete the login flow. The wrapper then picks up your credentials
via keychain on subsequent runs. No further configuration needed.

**API-key fallback (NOT recommended — significantly more expensive)**:
Claude Code takes the key from `ANTHROPIC_API_KEY`, or the wrapper passes
Claude Code the settings JSON named by `CLAUDE_REVIEW_SETTINGS`, whose
`apiKeyHelper` command prints the key. Reviews run in the installed launcher
host, which accepts no environment from the calling session, so set either
variable in the user environment the host starts with.
