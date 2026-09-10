# Example: project-hazards section from a real project

This file shows the project-specific hazards section that was used in the
gate's reference install — a Rust + Bevy 0.15 + lightyear 0.19 game project.
It is included as an EXAMPLE of what a well-tuned hazards list looks like,
not as content to use verbatim.

Use this as a template for the `## Project hazards` section of your own
`scripts/codex/review-prompt-template.md`. Each entry follows the same
pattern: short name + sub-forms + diff-level red flag + why it matters.

The 11 hazards below were all derived from actual past incidents in the
reference project. Every entry corresponds to a real defect that shipped at
least once before being added to the list. Build YOUR list the same way:
when a real defect ships, capture it here so the gate catches the next
instance.

---

## Project context (the reference project's filled-in section)

- **Stack**: Rust 1.83+, Bevy 0.15 ECS, lightyear 0.19 networking,
  Mixamo-rigged GLBs, procedural animation
- **Crate boundary direction**: `sc_app -> sc_ui -> sc_gameplay ->
  sc_world -> sc_ecs -> sc_core`. `sc_render`, `sc_physics`, `sc_network`,
  `sc_audio`, `sc_save` are leaf-ish service crates.
- **PLAN.md** describes the milestone plan. **History.md** logs significant
  state changes. **docs/codex-playability-backlog-2026-05-10.md** is the
  source-of-truth backlog.
- **Status vocabulary**:
  - `Observed` = manual or automated runtime evidence proved the
    player-facing path
  - `Code` = implementation + tests exist; live proof missing
  - `Hook` = scaffolding/event/component/placeholder
  - `Missing` = no complete implementation
- **AGENTS.md** documents subagent contract. **CLAUDE.md (global)** has
  behavioral and code-quality rules. Both apply.

---

## Project hazards (the reference project's 11 entries)

1. **Predicted/Confirmed marker filter split**. Gameplay systems filter
   `With<Predicted>`. UI systems filter `With<Confirmed>`. Local-only
   player spawn must attach BOTH markers explicitly because lightyear's
   auto-attach only fires in a real client-server topology. Diff-level red
   flag: any new player-related query, spawn, or filter expression — check
   the marker set against both producer and consumer schedules.

2. **Transform vs GlobalTransform across parent-child entities**.
   `Transform` is parent-relative. `GlobalTransform` is world-space.
   Resource nodes are children of chunk entities; the player is a root
   entity. Diff-level red flag: any new system that compares positions
   across entities at different hierarchy depths — both sides must use
   `GlobalTransform`, or distances are wrong.

3. **Asset path walk-up assumption**. Helpers like
   `assets_root_from_manifest_dir` historically walked up from
   `CARGO_MANIFEST_DIR` assuming `<project>/crates/<crate>/`. Manual
   launchers that pass the workspace root break this. Correct precedence:
   `BEVY_ASSET_ROOT` env var → direct `<dir>/assets` probe → walk-up
   fallback. Diff-level red flag: any new helper or new caller in the
   asset-resolution path — confirm the precedence and that duplicate
   copies have not drifted.

4. **UI stub render systems**. A UI panel can register systems that look
   complete (helpers, events, click handlers) but the actual render system
   clears descendants and exits, or emits no events. Diff-level red flag:
   any new `sc_ui` panel where the render system body is shorter than the
   helper module, or where a stale TODO claims a crate-dependency
   restriction that has since been lifted.

5. **Spawn-vs-consume plugin wiring drift**. A producer plugin registers a
   resource or events; a consumer system in another crate panics at
   startup because the producer plugin was never added to the appropriate
   `Sc*Plugin`. Diff-level red flag: any new resource introduced by a new
   plugin — its `add_plugins(...)` line must show in the diff or be
   reachable from a plugin already added.

6. **PLAN.md drift**. Cross-reference graph rot (a milestone tag
   referenced but never defined); range claims that do not match the
   actual numbered items present (`M19.0-M19.7` with `M19.5` missing);
   missing `Deps:` / `Tag:` / `Status:` fields on touched milestones.
   Diff-level red flag: any PLAN.md edit that touches a single milestone
   in isolation without sweeping references; every spot-fix to PLAN.md
   without a full reference sweep tends to ship at least one drift. If
   `./CODEX_REVIEW_EVIDENCE/PLAN-CONSISTENCY.txt` is present in the
   bundle, read it first. A `PLAN-CONSISTENCY-FINDING:` row in a well-formed
   `PLAN-CONSISTENCY-STATE: v1 produced` envelope is documentary drift and
   reports as `QUALITY:` under `PLAN-DRIFT`; valid skip states are non-findings.
   Required evidence that is indeterminate, absent, unreadable, malformed, or
   unterminated is a `BLOCKER:` under `SILENT-FAILURE`.
   (Checkbox-vs-body sentiment scanning and summary-status-table drift
   are NOT covered by the precompute — PLAN.md documents checkbox state
   as advisory and the summary table mixes top-level and submilestone
   tags in row prose, both of which make those checks false-positive-prone
   at this layer. Flag those classes manually only when the diff itself
   clearly demonstrates the drift; do not infer from the bundle's
   absence.)

7. **Silent failure on the mutation path**. State changes that are
   silently dropped or no-oped when a precondition is missing, instead of
   producing a stable diagnostic. (See the cross-cutting hazards section
   in the main template — kept here only as a project-specific anchor
   point for the SILENT-FAILURE category.) Project-specific sub-form: a
   recipe lookup whose miss path is `return;` without a stable
   `warn!(target="recipes", ...)` line. Diff-level red flag: every new
   `return;`, `Ok(())`, `let _ =`, or `unwrap_or_default()` on a
   state-mutation, validation, or asset-write path.

8. **Removed-code tombstones & empty-quarantine shims**. (See
   cross-cutting hazards.) Project-specific anchor: legacy
   `WorldSaveLegacy` shim was kept far longer than needed; future
   tombstones in `sc_save` are BLOCKERs.

9. **Cross-crate contract drift**. (See cross-cutting hazards.)
   Project-specific anchor: `place_piece` validity gate in `sc_gameplay`
   vs the network-replicated event shape in `sc_network_protocol_plugin`
   — historically the gate accepted shapes the protocol rejected.

10. **Loader-safe asset edges (GLB / IBM / asset-root)**. Asset processing
    that silently converts an unrecoverable input into "successful"
    output. Recurring sub-forms: a binary-format parser that validates
    magic/version but does not check declared-length-in-header against
    actual buffer length (truncation passes the validator but the runtime
    loader rejects it); an `unwrap_or_else(identity)` or
    `unwrap_or_default()` on a matrix-inversion, accessor-lookup, or
    skinning-required computation; an env-var-driven asset resolver that
    mixes "env var unset" and "env var set but invalid" into the same
    fallback branch (a mispointed packaged asset root falls through to the
    checkout tree, and the validator passes the wrong tree). Diff-level
    red flag: any binary-format parse without a declared-length equality
    assertion; any `unwrap_or_else(identity)`/`unwrap_or_default()` in
    asset processing; any env-driven path resolver whose unset and
    misconfigured branches are not visibly separated.

11. **Asset-env / `BEVY_ASSET_ROOT` fall-through (the conventional form)**.
    When `BEVY_ASSET_ROOT` is set but the configured location lacks the
    expected subtree, the resolver MUST return `None`/error for that root,
    not fall through to cwd/manifest as if the env var were unset.
    Hazard 10 already lists this as a sub-form; called out separately
    here because the pattern recurs whenever a new env-var-driven asset
    resolver is added. Diff-level red flag: any new asset resolver that
    mixes "env var unset" and "env var set but invalid" into the same
    fallback branch.

## Project framework hazards (Bevy 0.15)

- **Required Components**: spawning an entity with a `Mesh3d` does not
  auto-include `MeshMaterial3d`. The diff must spawn the full
  required-component set or rely on a known `#[require(...)]` macro.
- **Hierarchy components**: a hidden child does not inherit `Visibility`
  automatically. `Visibility`, `InheritedVisibility`, `ViewVisibility`
  are the trio. New spawn paths that produce visible scenes must include
  them or use a parent component that requires them.
- **System order**: `Update` vs `FixedUpdate` matters for input vs
  simulation. Anything that reads `ButtonInput<...>` should be `Update`.
  Anything mutating `Transform` of physics-driven entities is usually
  `FixedUpdate`.
- **EventReader buffer**: Bevy events are double-buffered for 2 frames.
  A system that runs less often than every frame will miss events. Check
  that consumer system schedule frequency >= producer.
- **Asset handles**: a `Handle<T>` dropped without a `StrongHandle`
  reference will cause the asset to be evicted. New asset loads must
  store the handle in a `Resource` or `Component`.

## Project framework hazards (lightyear 0.19)

- **Server authority**: state mutations (inventory, health, placement)
  must flow Client → server-request-event → server-validated mutation →
  replicate → client UI. A diff that mutates server-replicated state from
  a client-side system is wrong even if tests pass in single-process.
- **Replication groups**: components on the same entity that should
  replicate together must share a replication group. Mismatched groups
  can produce torn state.

## Project conventions (the reference project's CLAUDE.md / AGENTS.md)

- **No backwards-compat shims for removed code**. No renamed-to-underscore
  unused vars, no re-exports for moved types, no `// removed` comments.
- **Don't comment mechanics**. Comments explain *why* this approach over
  alternatives, what constraints, what invariants. Not what the line does.
- **Validate at boundaries**. User input, external APIs, file reads, agent
  output, asset registry lookups — all return Option/Result. Unwrap or
  panic at boundaries is wrong.
- **Complete fallback paths**. If a primary path and a fallback exist,
  both must handle all cases fully. Silent drop on fallback is a bug.
- **No silent failure**. Missing icon, missing recipe, missing audio cue,
  missing asset — must produce a diagnostic visible in launch-log scanner
  output. Logging at `info` or `warn` with a stable target.
- **Match existing patterns**. Crate boundaries, system sets, registries,
  resources, events — extend rather than parallel-create.
- **Error handling for impossible scenarios is wrong**. A `match` arm or
  `if` branch handling a case the type system already excludes is a
  `BLOCKER:` finding under CONVENTION-ADHERENCE.
