# Design: `zig-tool` — ecosystem tooling source of truth

- **Date:** 2026-06-12
- **Status:** Approved (pending spec review)
- **Author:** Benji Vesterby (with Claude)

## Problem

The diamond-dependency tooling — `detect_diamond_deps.py` (a `detect-diamond-deps`
pre-commit gate on `build.zig.zon`), `sync_diamond_deps.py` (the cascade
resolver), and `sync_diamond_deps.sh` (a thin wrapper) — is **vendored under
`scripts/` in every repo**. Across the ~54 `devnw/zig` + geode repos the copies
have **drifted**: a recent resilience fix to `sync_diamond_deps.py` (force-push
the throwaway staging branch; skip already-converged consumers) exists only in
`dns`, and the scan found `detect_diamond_deps.py` divergent in 8 repos and
missing in 5, with `sync_diamond_deps.py` present in only ~9. Manually copying
the files into every repo *is the very drift problem we want to eliminate*.

## Goals

- A single source of truth for the diamond-deps scripts that every repo consumes.
- "Pull latest from GitLab" is a first-class, low-friction operation.
- Remove the vendored `scripts/*diamond*` copies from every repo.
- Extensible: the home can hold **more than diamond scripts** over time.

## Non-Goals

- Re-running any dependency cascade (the `dns` v0.1.11 convergence is already done).
- Changing the *behaviour* of the detect gate or the cascade beyond what is needed
  to package them (the rc==2 cache-skip logic moves location, not meaning).
- Wiring the gate into repos that do not already have a `.pre-commit-config.yaml`
  (all 54 targets already do).

## Decision Summary

| Decision | Choice |
|---|---|
| Home repo | `gitlab.com/devnw/zig/zig-tool` — a general ecosystem tool repo |
| Distribution | **pre-commit remote hook repo** (each repo references it by URL + `rev`) |
| Detect gate | `language: python` pre-commit hook `detect-diamond-deps` |
| Cascade tool | `zig-tool sync-diamond …` CLI, run via **`uvx` zero-install** |
| "Pull latest" | `pre-commit autoupdate` bumps the pinned `rev` to the newest tag |
| Migration | **all-at-once** sweep of all 54 repos after `zig-tool` is published |
| Vendored copies | **deleted** from every consuming repo |

## Architecture

### The `zig-tool` repository

A small, stdlib-only Python package that is *also* a pre-commit hook repo.

```text
zig-tool/
  pyproject.toml              # package "zig_tool"; console scripts; version
  .pre-commit-hooks.yaml      # hook ids consuming repos reference
  src/zig_tool/
    __init__.py               # __version__
    detect_diamond_deps.py    # the gate (ported from dns scripts/)
    sync_diamond_deps.py      # the cascade (imports .detect_diamond_deps)
    cli.py                    # `zig-tool` argparse CLI with subcommands
  tests/
    test_detect.py            # fixture build.zig.zon -> clean / diamond / cache-miss
    test_sync_plan.py         # dry-run cascade plan on a fixture graph
  README.md                   # consume + autoupdate + uvx cascade instructions
  .pre-commit-config.yaml     # zig-tool's OWN dev hooks (ruff, etc.)
```

- **Packaging:** `language: python` means pre-commit builds an isolated venv from
  the cloned tag and installs `zig_tool`. The package is **stdlib-only**, so the
  install is effectively free. `zig` is invoked as a subprocess and is found on
  the system PATH (unchanged from today).
- **Console scripts** (pyproject `[project.scripts]`):
  - `detect-diamond-deps = zig_tool.detect_diamond_deps:main`
  - `zig-tool = zig_tool.cli:main` (subcommands: `detect-diamond`, `sync-diamond`)
- **Versioning:** semver tags (`v0.1.0`, …). `src/zig_tool/__init__.py.__version__`
  and the tag move together.

### `.pre-commit-hooks.yaml`

```yaml
- id: detect-diamond-deps
  name: detect diamond deps in build.zig.zon
  entry: detect-diamond-deps
  language: python
  files: ^build\.zig\.zon$
  pass_filenames: false
```

The current bash wrapper's `rc==2 -> "cache not populated; skipping" -> exit 0`
behaviour moves **into `detect_diamond_deps.main()`**: when the package cache is
not yet populated it prints the notice and exits 0, so the hook entry needs no
shell glue.

### The two tools and their distribution

1. **`detect-diamond-deps` (automatic gate).** Distributed *as a pre-commit hook*.
   Each consuming repo references `zig-tool` by URL + `rev`; pre-commit clones,
   caches, and installs it. Behaviour is identical to today: runs on
   `build.zig.zon` changes, exit 1 on a diamond, exit 0 (with notice) on cache
   miss.

2. **`sync-diamond` (manual cascade).** A maintainer CLI with rich arguments
   (`--cascade --apply --target NAME=vX.Y.Z#sha --base-from .`). Clunky as a
   pre-commit hook, so it is run **ad-hoc, zero-install**:

   ```text
   uvx --from git+https://gitlab.com/devnw/zig/zig-tool zig-tool sync-diamond \
       --cascade --apply --target thread_pool=v0.2.5#<sha> --base-from .
   ```

   `uvx` fetches the latest `zig-tool` and runs it without a persistent install.
   The detect gate's failure message and the README point at this command.
   This CLI carries the two resilience fixes already proven in the `dns`
   convergence (force-push the throwaway staging branch; skip already-converged
   consumers, reusing the tag that points at the converged base commit).

### What changes in each of the 54 consuming repos

`.pre-commit-config.yaml`: the ~14-line local `detect-diamond-deps` block is
replaced by a remote reference:

```yaml
- repo: https://gitlab.com/devnw/zig/zig-tool
  rev: v0.1.0
  hooks:
    - id: detect-diamond-deps
```

and the vendored files are **deleted**:
`scripts/detect_diamond_deps.py`, `scripts/sync_diamond_deps.py`,
`scripts/sync_diamond_deps.sh` (whichever exist).

One commit per repo: `chore(ci): consume diamond-deps gate from zig-tool`.

## Migration Plan

**Phase 1 — Build & publish `zig-tool`.**
Port the three scripts into the package, add `pyproject.toml`,
`.pre-commit-hooks.yaml`, tests, and README. Run `zig-tool`'s own pre-commit +
tests green. Create the GitLab project `devnw/zig/zig-tool` via `glab`, push,
tag `v0.1.0`. Smoke-test the published hook once against a scratch checkout
(`pre-commit try-repo` or a temp consuming config) to confirm it fires and
correctly flags a diamond and passes a clean `build.zig.zon`.

**Phase 2 — All-at-once sweep of the 54 repos.**
For each repo: rewrite the `detect-diamond-deps` block to the remote reference,
delete the vendored copies, `pre-commit run detect-diamond-deps` (or at least
`pre-commit validate-config`), commit, and push. Pushes run each repo's existing
pre-push hooks (`zig build`/`test`); **failures are reported, not forced past**.
A summary table lists per-repo: rewired / pushed / skipped-unchanged / FAILED+reason.

**Phase 3 — Docs.**
Update the gate failure message + any READMEs that referenced
`scripts/sync_diamond_deps.sh` to the `uvx … sync-diamond` form.

## "Pull latest" workflow (steady state)

- Bump a tool in `zig-tool`, tag a new version, push.
- In any consuming repo: `pre-commit autoupdate --repo https://gitlab.com/devnw/zig/zig-tool`
  bumps the pinned `rev`. (Ecosystem-wide bump = the same one-line edit across
  repos, or a tiny loop — but now it's a *one-line rev change*, not a file copy.)

## Adding future tools

A new tool = a new module under `src/zig_tool/`, a new `[project.scripts]` entry,
and a new hook id in `.pre-commit-hooks.yaml`. Consuming repos opt in by adding
the hook id under the same `- repo` block. No structural change.

## Testing

- `zig-tool` unit tests (pytest) for detect (clean / diamond / cache-miss exit
  codes) and the cascade planner (dry-run plan on a fixture dep graph).
- Phase-1 smoke test of the *published* hook via `pre-commit try-repo`.
- Phase-2: each rewired repo's `.pre-commit-config.yaml` validated before push.

## Risks & Rollback

- **Bad hook lands in all 54 (all-at-once).** Mitigated by the Phase-1 smoke test
  before the sweep. Rollback = revert the one-line config commit per repo
  (and/or `pre-commit autoupdate` to a fixed older tag).
- **Push failures across many repos** (pre-push `zig build` on broken/untrusted
  repos, e.g. mise-trust). Reported per repo; not forced. Re-runnable.
- **uvx/uv not installed** for a maintainer running the cascade. README documents
  the `uv` install one-liner; `pipx install git+…/zig-tool` is the fallback.
- **pre-commit cannot reach gitlab.com** (offline CI). Same constraint as any
  remote hook; documented. Tags are immutable, so cached installs are stable.

## Open Questions

None blocking. Repo name (`zig-tool`), group (`devnw/zig`), mechanism (pre-commit
remote hook), cascade access (uvx), and rollout (all-at-once) are decided.
