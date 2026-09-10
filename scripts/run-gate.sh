#!/usr/bin/env bash
# Stable, parameterized gate-firing entry point.
#
# WHY A STABLE PATH: firing the gate from a freshly-named scratch script per
# branch makes every run a new permission prompt, and a prompt stalls an
# unattended session indefinitely (and kills a background worker outright,
# since workers never see the prompt UI). A stable allow-listed path
# removes that whole class -- the worktree, message, backend, and pass count
# vary as ARGUMENTS, which the allowlisted stable path covers.
#
# Usage: run-gate.sh <worktree-path> <commit-message-file> <review-backend codex|claude> [review-passes]
#
# The BACKEND names the preferred initial REVIEWER for this commit
# (cross-review: choose the backend that did NOT author the change). Pass count defaults to 1 -- the
# package-neutral default; a consumer wanting more passes says so per call.
set -u
# An inherited CDPATH would redirect every relative `cd` below to a
# matching directory elsewhere AND print the selection to stdout,
# corrupting the $(cd ... && pwd -P) canonicalizations into multiline
# values -- ambient environment must never steer path resolution here
# (the GIT_* override refusal below is the same invariant).
unset CDPATH

# Git replacement refs rewrite commit/tree/blob reads without changing the
# object IDs printed by callers. Windows process blocks can carry multiple
# case-variant spellings, so named assignment cannot establish which value a
# native Git child consumes. Remove every raw spelling, install one canonical
# entry, and verify the raw block before the first Git command. Raw entries
# remain inside the pipe parser; only matching variable names cross into the
# parent shell, and no environment snapshot reaches disk.
crg_no_replace_environment() {
  env -0
}
crg_no_replace_stream() {
  crg_no_replace_environment
  _crg_nro_stream_status=$?
  printf '__CRG_NRO_ENUM_STATUS_%s\0' "$_crg_nro_stream_status"
}
crg_no_replace_parse() {
  _crg_nro_action=$1
  case "$_crg_nro_action" in
    names|verify) ;;
    *) return 1 ;;
  esac
  crg_no_replace_stream | (
    _crg_nro_seen_status=0
    _crg_nro_count=0
    _crg_nro_canonical=0
    while :; do
      _crg_nro_entry=
      IFS= read -r -d '' _crg_nro_entry
      _crg_nro_read_status=$?
      if [ "$_crg_nro_read_status" -ne 0 ]; then
        [ -z "$_crg_nro_entry" ] || exit 1
        break
      fi
      case "$_crg_nro_entry" in
        *=*)
          [ "$_crg_nro_seen_status" -eq 0 ] || exit 1
          _crg_nro_name=${_crg_nro_entry%%=*}
          case "$_crg_nro_name" in
            [Gg][Ii][Tt]_[Nn][Oo]_[Rr][Ee][Pp][Ll][Aa][Cc][Ee]_[Oo][Bb][Jj][Ee][Cc][Tt][Ss])
              _crg_nro_count=$((_crg_nro_count + 1))
              if [ "$_crg_nro_entry" = "GIT_NO_REPLACE_OBJECTS=1" ]; then
                _crg_nro_canonical=$((_crg_nro_canonical + 1))
              fi
              if [ "$_crg_nro_action" = "names" ]; then
                printf '%s\n' "$_crg_nro_name" || exit 1
              fi
              ;;
          esac
          ;;
        __CRG_NRO_ENUM_STATUS_0)
          [ "$_crg_nro_seen_status" -eq 0 ] || exit 1
          _crg_nro_seen_status=1
          ;;
        __CRG_NRO_ENUM_STATUS_*)
          exit 1
          ;;
        *)
          exit 1
          ;;
      esac
    done
    [ "$_crg_nro_seen_status" -eq 1 ] || exit 1
    if [ "$_crg_nro_action" = "verify" ]; then
      [ "$_crg_nro_count" -eq 1 ] && [ "$_crg_nro_canonical" -eq 1 ] || exit 1
    fi
    exit 0
  )
  _crg_nro_parse_status=$?
  unset _crg_nro_action
  return "$_crg_nro_parse_status"
}
crg_set_no_replace_singleton() {
  if ! _crg_nro_names=$(crg_no_replace_parse names); then return 1; fi
  unset GIT_NO_REPLACE_OBJECTS || return 1
  _crg_nro_saved_ifs=$IFS
  IFS='
'
  for _crg_nro_name in $_crg_nro_names; do
    case "$_crg_nro_name" in
      [Gg][Ii][Tt]_[Nn][Oo]_[Rr][Ee][Pp][Ll][Aa][Cc][Ee]_[Oo][Bb][Jj][Ee][Cc][Tt][Ss])
        unset "$_crg_nro_name" || {
          IFS=$_crg_nro_saved_ifs
          return 1
        }
        ;;
      *)
        IFS=$_crg_nro_saved_ifs
        return 1
        ;;
    esac
  done
  IFS=$_crg_nro_saved_ifs
  GIT_NO_REPLACE_OBJECTS=1
  export GIT_NO_REPLACE_OBJECTS || return 1
  if ! crg_no_replace_parse verify; then return 1; fi
  unset _crg_nro_names _crg_nro_name _crg_nro_saved_ifs _crg_nro_parse_status
  return 0
}
if ! crg_set_no_replace_singleton; then
  echo "run-gate: could not establish exactly one canonical GIT_NO_REPLACE_OBJECTS=1 entry before repository inspection - refusing" >&2
  exit 2
fi

# Grafts and caller-selected shallow files alter parent/range proofs even when
# replacement refs are disabled. Repository/object/ref selectors redirect the
# target domain, attribute selectors rewrite diff semantics, and GIT_CONFIG
# carriers inject configuration before the effective hooksPath proof. Parse
# NUL-framed environment records so an unrelated multiline value cannot forge
# a variable name; mixed-case and empty prohibited selectors still refuse.
crg_git_selector_stream() {
  env -0 2>/dev/null
  _crg_gs_stream_status=$?
  printf '__CRG_GS_ENUM_STATUS_%s\0' "$_crg_gs_stream_status"
}
crg_git_selector_state() {
  crg_git_selector_stream | (
    _crg_gs_seen_status=0
    _crg_gs_found=0
    while :; do
      _crg_gs_entry=
      IFS= read -r -d '' _crg_gs_entry
      _crg_gs_read_status=$?
      if [ "$_crg_gs_read_status" -ne 0 ]; then
        [ -z "$_crg_gs_entry" ] || exit 2
        break
      fi
      case "$_crg_gs_entry" in
        *=*)
          [ "$_crg_gs_seen_status" -eq 0 ] || exit 2
          _crg_gs_name=${_crg_gs_entry%%=*}
          case "$_crg_gs_name" in
            [Gg][Ii][Tt]_[Gg][Rr][Aa][Ff][Tt]_[Ff][Ii][Ll][Ee]| \
            [Gg][Ii][Tt]_[Ss][Hh][Aa][Ll][Ll][Oo][Ww]_[Ff][Ii][Ll][Ee]| \
            [Gg][Ii][Tt]_[Aa][Tt][Tt][Rr]_[Ss][Oo][Uu][Rr][Cc][Ee]| \
            [Gg][Ii][Tt]_[Aa][Tt][Tt][Rr]_[Nn][Oo][Ss][Yy][Ss][Tt][Ee][Mm]| \
            [Gg][Ii][Tt]_[Dd][Ii][Rr]| \
            [Gg][Ii][Tt]_[Ww][Oo][Rr][Kk]_[Tt][Rr][Ee][Ee]| \
            [Gg][Ii][Tt]_[Ii][Nn][Dd][Ee][Xx]_[Ff][Ii][Ll][Ee]| \
            [Gg][Ii][Tt]_[Cc][Oo][Mm][Mm][Oo][Nn]_[Dd][Ii][Rr]| \
            [Gg][Ii][Tt]_[Oo][Bb][Jj][Ee][Cc][Tt]_[Dd][Ii][Rr][Ee][Cc][Tt][Oo][Rr][Yy]| \
            [Gg][Ii][Tt]_[Aa][Ll][Tt][Ee][Rr][Nn][Aa][Tt][Ee]_[Oo][Bb][Jj][Ee][Cc][Tt]_[Dd][Ii][Rr][Ee][Cc][Tt][Oo][Rr][Ii][Ee][Ss]| \
            [Gg][Ii][Tt]_[Nn][Aa][Mm][Ee][Ss][Pp][Aa][Cc][Ee]| \
            [Gg][Ii][Tt]_[Rr][Ee][Ff][Ee][Rr][Ee][Nn][Cc][Ee]_[Bb][Aa][Cc][Kk][Ee][Nn][Dd]| \
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]| \
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Gg][Ll][Oo][Bb][Aa][Ll]| \
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Ss][Yy][Ss][Tt][Ee][Mm]| \
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Nn][Oo][Ss][Yy][Ss][Tt][Ee][Mm]| \
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Pp][Aa][Rr][Aa][Mm][Ee][Tt][Ee][Rr][Ss]| \
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Cc][Oo][Uu][Nn][Tt])
              _crg_gs_found=1
              ;;
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Kk][Ee][Yy]_*)
              _crg_gs_suffix=${_crg_gs_name#*[Kk][Ee][Yy]_}
              case "$_crg_gs_suffix" in ''|*[!0-9]*) ;; *) _crg_gs_found=1 ;; esac
              ;;
            [Gg][Ii][Tt]_[Cc][Oo][Nn][Ff][Ii][Gg]_[Vv][Aa][Ll][Uu][Ee]_*)
              _crg_gs_suffix=${_crg_gs_name#*[Vv][Aa][Ll][Uu][Ee]_}
              case "$_crg_gs_suffix" in ''|*[!0-9]*) ;; *) _crg_gs_found=1 ;; esac
              ;;
          esac
          ;;
        __CRG_GS_ENUM_STATUS_0)
          [ "$_crg_gs_seen_status" -eq 0 ] || exit 2
          _crg_gs_seen_status=1
          ;;
        __CRG_GS_ENUM_STATUS_*)
          exit 2
          ;;
        *)
          exit 2
          ;;
      esac
    done
    [ "$_crg_gs_seen_status" -eq 1 ] || exit 2
    [ "$_crg_gs_found" -eq 0 ] || exit 0
    exit 1
  )
}
crg_git_selector_state
_crg_gs_rc=$?
if [ "$_crg_gs_rc" -eq 0 ]; then
  echo "run-gate: an ambient Git selector is present (repository/object/ref/index, history, attribute, or config-override family; case-insensitive, including empty values) - refusing before repository inspection" >&2
  exit 2
fi
if [ "$_crg_gs_rc" -ne 1 ]; then
  echo "run-gate: the process environment could not be enumerated while checking ambient Git selectors - refusing before repository inspection" >&2
  exit 2
fi
unset _crg_gs_rc _crg_gs_stream_status

# Retired project-mode authorization is inert. Remove every exported ASCII
# case variant and verify absence before any child can inherit old authority.
crg_retired_mode_stream() {
  env -0 2>/dev/null
  _crg_rme_stream_status=$?
  printf '__CRG_RME_ENUM_STATUS_%s\0' "$_crg_rme_stream_status"
}
crg_retired_mode_names() {
  crg_retired_mode_stream | (
    _crg_rme_seen_status=0
    while :; do
      _crg_rme_entry=
      IFS= read -r -d '' _crg_rme_entry
      _crg_rme_read_status=$?
      if [ "$_crg_rme_read_status" -ne 0 ]; then
        [ -z "$_crg_rme_entry" ] || exit 1
        break
      fi
      case "$_crg_rme_entry" in
        *=*)
          [ "$_crg_rme_seen_status" -eq 0 ] || exit 1
          _crg_rme_name=${_crg_rme_entry%%=*}
          case "$_crg_rme_name" in
            [Cc][Rr][Oo][Ss][Ss]_[Rr][Ee][Vv][Ii][Ee][Ww]_[Aa][Ll][Ll][Oo][Ww]_[Mm][Oo][Dd][Ee]_[Cc][Hh][Aa][Nn][Gg][Ee])
              printf '%s\n' "$_crg_rme_name" || exit 1
              ;;
          esac
          ;;
        __CRG_RME_ENUM_STATUS_0)
          [ "$_crg_rme_seen_status" -eq 0 ] || exit 1
          _crg_rme_seen_status=1
          ;;
        __CRG_RME_ENUM_STATUS_*)
          exit 1
          ;;
        *)
          exit 1
          ;;
      esac
    done
    [ "$_crg_rme_seen_status" -eq 1 ] || exit 1
    exit 0
  )
}
crg_clear_retired_mode_env() {
  if ! _crg_rme_names=$(crg_retired_mode_names); then return 1; fi
  unset CROSS_REVIEW_ALLOW_MODE_CHANGE || return 1
  _crg_rme_saved_ifs=$IFS
  IFS='
'
  for _crg_rme_name in $_crg_rme_names; do
    case "$_crg_rme_name" in
      [Cc][Rr][Oo][Ss][Ss]_[Rr][Ee][Vv][Ii][Ee][Ww]_[Aa][Ll][Ll][Oo][Ww]_[Mm][Oo][Dd][Ee]_[Cc][Hh][Aa][Nn][Gg][Ee])
        unset "$_crg_rme_name" || {
          IFS=$_crg_rme_saved_ifs
          return 1
        }
        ;;
      *)
        IFS=$_crg_rme_saved_ifs
        return 1
        ;;
    esac
  done
  IFS=$_crg_rme_saved_ifs
  if ! _crg_rme_left=$(crg_retired_mode_names); then return 1; fi
  [ -z "$_crg_rme_left" ] || return 1
  unset _crg_rme_names _crg_rme_name _crg_rme_left _crg_rme_saved_ifs _crg_rme_stream_status
  return 0
}
if ! crg_clear_retired_mode_env; then
  echo "run-gate: could not clear every case variant of the retired project-mode authorization variable - refusing before child execution" >&2
  exit 2
fi


# The producer and parser stay separate so Git's status cannot be replaced by
# a pipeline consumer's status. NUL framing is required because Git pathnames
# may contain newlines; an empty record or an unterminated tail is malformed.
crg_write_staged_set() {
  git diff --cached --no-color --no-ext-diff --no-textconv --no-renames --ignore-submodules=none --name-only -z -- > "$1" 2>/dev/null
}
crg_count_staged_set() {
  _crg_ss_path=$1
  [ -f "$_crg_ss_path" ] && [ ! -L "$_crg_ss_path" ] || return 2
  _crg_ss_count=0
  while :; do
    _crg_ss_entry=
    IFS= read -r -d '' _crg_ss_entry
    _crg_ss_read_status=$?
    if [ "$_crg_ss_read_status" -ne 0 ]; then
      [ -z "$_crg_ss_entry" ] || return 2
      break
    fi
    [ -n "$_crg_ss_entry" ] || return 2
    _crg_ss_count=$((_crg_ss_count + 1))
  done < "$_crg_ss_path"
  printf '%s\n' "$_crg_ss_count"
}
crg_probe_staged_set() {
  _crg_ss_tmp=$(umask 077 && { mktemp 2>/dev/null || mktemp -t crg-run-gate-stage 2>/dev/null; }) || _crg_ss_tmp=''
  case "$_crg_ss_tmp" in
    /?*) ;;
    *) _crg_ss_tmp='' ;;
  esac
  if [ -z "$_crg_ss_tmp" ] || [ ! -f "$_crg_ss_tmp" ] || [ -L "$_crg_ss_tmp" ]; then
    [ -n "$_crg_ss_tmp" ] && rm -f -- "$_crg_ss_tmp" 2>/dev/null
    return 2
  fi
  crg_cleanup_staged_set() {
    [ -n "${_crg_ss_tmp:-}" ] || return 0
    rm -f -- "$_crg_ss_tmp" 2>/dev/null || return 1
    [ ! -e "$_crg_ss_tmp" ] && [ ! -L "$_crg_ss_tmp" ] || return 1
    _crg_ss_tmp=''
    return 0
  }
  trap 'crg_cleanup_staged_set; exit 2' HUP INT TERM
  trap 'crg_cleanup_staged_set' EXIT
  crg_write_staged_set "$_crg_ss_tmp"
  _crg_ss_write_status=$?
  if [ "$_crg_ss_write_status" -ne 0 ]; then
    crg_cleanup_staged_set || return 4
    trap - EXIT HUP INT TERM
    return 2
  fi
  _crg_ss_result=$(crg_count_staged_set "$_crg_ss_tmp")
  _crg_ss_parse_status=$?
  if [ "$_crg_ss_parse_status" -ne 0 ]; then
    crg_cleanup_staged_set || return 4
    trap - EXIT HUP INT TERM
    return 3
  fi
  crg_cleanup_staged_set || return 4
  trap - EXIT HUP INT TERM
  printf '%s\n' "$_crg_ss_result"
}


WT="${1:-}"
MSGFILE="${2:-}"
BACKEND="${3:-}"
PASSES="${4:-1}"

# EXACT argument count before anything mutates: a surplus argument is a
# caller error (a mis-pasted commit option, a forgotten quote) that MUST NOT
# be silently discarded on the way into a commit.
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: run-gate.sh <worktree-path> <commit-message-file> <review-backend codex|claude> [review-passes]" >&2
  [ "$#" -gt 4 ] && echo "run-gate: surplus arguments refused (got $#)" >&2
  exit 2
fi
if [ -z "$WT" ] || [ -z "$MSGFILE" ] || [ -z "$BACKEND" ]; then
  echo "usage: run-gate.sh <worktree-path> <commit-message-file> <review-backend codex|claude> [review-passes]" >&2
  exit 2
fi
# Native Windows paths reach this git-bash script with backslash
# separators that dirname/basename do not split on -- a PowerShell
# caller's C:\...\msg.txt would pass the existence check and then
# decompose wrong. Normalize to the POSIX form first (cygpath where
# present, else a separator translation).
# Every producer here reports by its OWN status: cygpath output is used
# only on exit 0 (a conversion that fails after partial output is not a
# path), and the fallback translation is an awk command reading
# the value from its environment (no pipeline, whose status would be the
# last stage's; no -v, which processes backslash escapes in the very
# bytes being translated). The function's status is the producer's, and
# the callers refuse on failure.
crg_norm_path() {
  if command -v cygpath >/dev/null 2>&1; then
    if crg_np=$(cygpath -u "$1" 2>/dev/null) && [ -n "$crg_np" ]; then printf '%s' "$crg_np"; return 0; fi
  fi
  CRG_NP_IN="$1" LC_ALL=C awk 'BEGIN{s=ENVIRON["CRG_NP_IN"]; gsub(/\\/,"/",s); printf "%s",s}'
}
# An option-like relative path (a worktree literally named '-P') would
# read as an OPTION to cd/cygpath/dirname/basename, redirecting them to
# defaults such as $HOME -- and a $HOME that is itself a repository root
# would then pass the identity check as the wrong repository. Anchor
# such names explicitly before any path utility sees them.
case "$WT" in -*) WT=./$WT ;; esac
case "$MSGFILE" in -*) MSGFILE=./$MSGFILE ;; esac
WT=$(crg_norm_path "$WT") || { echo "run-gate: could not normalize the worktree path argument (path translation failed)" >&2; exit 2; }
MSGFILE=$(crg_norm_path "$MSGFILE") || { echo "run-gate: could not normalize the commit message path argument (path translation failed)" >&2; exit 2; }
if [ ! -d "$WT" ]; then
  echo "run-gate: worktree not found: $WT" >&2
  exit 2
fi
if [ ! -f "$MSGFILE" ]; then
  echo "run-gate: commit message file not found: $MSGFILE" >&2
  exit 2
fi
# ABSOLUTE message path BEFORE the cd: a caller-relative path validated here
# would re-resolve inside the worktree after the cd, going missing or --
# worse -- hitting a different file there and committing the wrong message.
# The directory resolves in its OWN checked step: folding it into the
# final substitution would turn a failed cd into an empty prefix, and
# "/<basename>" could then silently select a matching root-level file.
MSGFILE_DIRNAME=$(dirname -- "$MSGFILE") || MSGFILE_DIRNAME=''
if [ -z "$MSGFILE_DIRNAME" ]; then
  echo "run-gate: could not split the commit message path into its directory: $MSGFILE" >&2
  exit 2
fi
MSGFILE_DIR=$(cd -- "$MSGFILE_DIRNAME" 2>/dev/null && pwd -P) || MSGFILE_DIR=''
if [ -z "$MSGFILE_DIR" ]; then
  echo "run-gate: could not resolve the commit message file's directory to an absolute path: $MSGFILE" >&2
  exit 2
fi
MSGFILE_BASE=$(basename -- "$MSGFILE") || MSGFILE_BASE=''
if [ -z "$MSGFILE_BASE" ]; then
  echo "run-gate: could not split the commit message path into its file name: $MSGFILE" >&2
  exit 2
fi
MSGFILE_ABS=$MSGFILE_DIR/$MSGFILE_BASE
if [ ! -f "$MSGFILE_ABS" ]; then
  echo "run-gate: could not resolve the commit message file to an absolute path: $MSGFILE" >&2
  exit 2
fi
# Case-folded by pattern, not by a producer: the accept set is closed,
# so no external command's output (or laundered status) decides it.
case "$BACKEND" in
  [Cc][Oo][Dd][Ee][Xx]) BACKEND_NORM=codex ;;
  [Cc][Ll][Aa][Uu][Dd][Ee]) BACKEND_NORM=claude ;;
  *)
    echo "run-gate: review-backend must be codex or claude: $BACKEND" >&2
    exit 2
    ;;
esac
case "$PASSES" in
  ''|*[!0-9]*) echo "run-gate: review-passes must be digits: $PASSES" >&2; exit 2 ;;
esac
# The range bound is LEXICAL, never arithmetic: `[` returns status 2 for
# a digit string past the shell integer range, and both -lt/-gt arms
# would read that as false -- an oversized count would sail through the
# bound it exists to enforce. The closed lexical set also refuses a
# zero-padded count.
case "$PASSES" in
  [1-9]|10) ;;
  *)
    echo "run-gate: review-passes out of range 1..10: $PASSES" >&2
    exit 2
    ;;
esac
# The pass knob is CODEX-side: the codex wrapper consumes
# CROSS_REVIEW_PASSES, while the hook invokes the claude wrapper as a single
# review. Accepting a claude pass count above that would REPORT passes that
# never run -- refuse rather than advertise phantom coverage.
if [ "$BACKEND_NORM" = "claude" ] && [ "$PASSES" -ne 1 ]; then
  echo "run-gate: the claude backend runs a single review (CROSS_REVIEW_PASSES is consumed by the codex wrapper only) - omit the pass count or pass 1" >&2
  exit 2
fi

# REPOSITORY IDENTITY before anything probes or mutates: `cd` alone proves
# nothing about which repository git will act on. A GIT_DIR/GIT_WORK_TREE
# style override, or a requested directory that is merely a subdirectory of
# some other repository, would aim every guard probe and the commit itself
# at a different repo while diagnostics still name $WT. The overrides are
# rejected by raw, case-insensitive NAME presence at direct entry (including
# empty values), and the resolved git toplevel must be exactly the canonicalized
# requested root.
# The gate-FIRING entry point never commits under a skip or sanction variable.
# An inherited skip would turn the nominal gated path into an audited bypass.
# Sanctioned commits require a deliberate, hand-set invocation of their own;
# a stale caller environment must refuse here, before repository operations.
if [ -n "${CROSS_REVIEW_SKIP:-}${CROSS_REVIEW_SKIP_AUTHOR_LINT:-}${CROSS_REVIEW_ALLOW_GATE_UNTRACK:-}${CROSS_REVIEW_ALLOW_SEAL:-}" ]; then
  echo "run-gate: a review skip/sanction variable is set (CROSS_REVIEW_SKIP / CROSS_REVIEW_SKIP_AUTHOR_LINT / CROSS_REVIEW_ALLOW_GATE_UNTRACK / CROSS_REVIEW_ALLOW_SEAL) - this entry point only FIRES the gate; unset it, or make the audited skip an explicit git commit of its own; refusing" >&2
  exit 2
fi
WT_CANON=$(cd -- "$WT" 2>/dev/null && pwd -P) || WT_CANON=''
if [ -z "$WT_CANON" ]; then
  echo "run-gate: could not canonicalize the worktree path: $WT" >&2
  exit 2
fi
cd -- "$WT_CANON" || exit 2
TOPLEVEL=$(git rev-parse --show-toplevel 2>/dev/null) || TOPLEVEL=''
if [ -z "$TOPLEVEL" ]; then
  echo "run-gate: $WT_CANON is not inside a git working tree - refusing" >&2
  exit 2
fi
TOP_CANON=$(cd "$TOPLEVEL" 2>/dev/null && pwd -P) || TOP_CANON=''
if [ -z "$TOP_CANON" ] || [ "$TOP_CANON" != "$WT_CANON" ]; then
  echo "run-gate: the git toplevel ($TOP_CANON) is not the requested worktree root ($WT_CANON) - a subdirectory or foreign repository would be mutated under the requested name; refusing" >&2
  exit 2
fi

# EFFECTIVE core.hooksPath must be unset, mirroring the commit wrappers'
# fail-closed configuration check: a configured hooks path (any scope)
# redirects `git commit` away from the per-clone dispatcher entirely, so a
# valid dispatcher at the default path proves nothing while it is set.
# Classification is by EXIT STATUS, never stdout: `git config --get`
# reports a set-but-EMPTY value with exit 0 and empty output (the commit
# wrappers classify that state as configured), and any other status is an
# indeterminate config read that must not be laundered as unset.
HOOKS_CFG=$(git config --get core.hooksPath 2>/dev/null)
HOOKS_RC=$?
if [ "$HOOKS_RC" -eq 0 ]; then
  echo "run-gate: core.hooksPath is configured ('$HOOKS_CFG'; a set-but-empty value counts), which redirects git away from the per-clone dispatcher - refusing to commit un-gated. Re-run bootstrap.ps1 (it reconciles legacy core.hooksPath), or unset it." >&2
  exit 2
elif [ "$HOOKS_RC" -ne 1 ]; then
  echo "run-gate: could not classify core.hooksPath (git config exited $HOOKS_RC) - refusing to commit rather than guessing the hooks routing" >&2
  exit 2
fi

# DISPATCHER-IDENTITY check, so a missing, disarmed, or FOREIGN per-clone
# hook fails LOUD here instead of `git commit` landing an un-gated commit:
# hooks are machine state a clone does not carry. An ARMED dispatcher begins
# with a shebang (the in-place refresh protocol's disarmed byte makes git
# unable to spawn it), and a shebang alone is not identity -- any no-op
# script passes it -- so the dispatcher's own capability marker is required
# too, matching the local-authorization arming requirement.
HOOK_PATH=$(git rev-parse --git-path hooks/pre-commit 2>/dev/null) || HOOK_PATH=''
if [ -z "$HOOK_PATH" ] || [ ! -f "$HOOK_PATH" ]; then
  echo "run-gate: no pre-commit dispatcher at the hooks path ($HOOK_PATH) - refusing to commit un-gated. Install it: bootstrap.ps1 -DispatcherOnly (tracked shape) or a full bootstrap (local shape)." >&2
  exit 2
fi
HOOK_HEAD=$(head -c 2 "$HOOK_PATH" 2>/dev/null) || HOOK_HEAD=''
if [ "$HOOK_HEAD" != "#!" ]; then
  echo "run-gate: the dispatcher at $HOOK_PATH does not begin with a shebang (disarmed or foreign bytes) - refusing to commit un-gated. Re-run bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi
if ! grep -q 'crg-gate-untrack-guard-v1' "$HOOK_PATH" 2>/dev/null; then
  echo "run-gate: the file at $HOOK_PATH does not carry the dispatcher capability marker (crg-gate-untrack-guard-v1) - a foreign or pre-guard hook occupies the hooks path; refusing to commit un-gated. Re-run bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi
# The marker is a publicly copyable substring, so the digest sidecar
# carries the stronger check: bootstrap records the verified dispatcher's
# sha256 beside the hook at install and removes it (best-effort, loudly
# on failure) around every mutation and sentinel, so a mismatch means
# drift, a stale or foreign hook, or a partial install. Like every driver
# guard in this package the check is DETECTIVE -- loud on
# misconfiguration and drift, never a security boundary against a
# principal who can write the hooks path (that principal can rewrite any
# local record, and nothing pins the hook between this probe and git's
# own hook spawn); the authoritative enforcement is the dispatcher chain
# itself plus the gate review routing-driver edits are forced through
# (the audited exceptions: the commit wrappers' documented
# broken-wrapper skip recovery, and a driver ADDED with no HEAD baseline
# riding the bootstrap-commit skip).
HOOK_DIGEST_FILE="$HOOK_PATH.crg-sha256"
if [ ! -f "$HOOK_DIGEST_FILE" ]; then
  echo "run-gate: no dispatcher attestation at $HOOK_DIGEST_FILE - bootstrap records the verified dispatcher digest there at install; refusing to commit un-gated. Re-run bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi
# The record grammar is BYTE-EXACT and shared with bootstrap's writer
# and clearing (one accept set everywhere): exactly two LF-terminated
# lines, the versioned ownership header then one lowercase 64-hex
# digest, no CR bytes, no missing final LF -- a looser reader here
# would accept sidecars the producer never writes and turn the promised
# drift refusal into acceptance.
# CR presence is a BYTE question answered in the byte domain: text-mode
# grep/awk on this platform strip CR on read (the hook's
# crg_followup_has_cr documents the same hazard), so a line-mode probe
# would wave through a CRLF sidecar that bootstrap's clearing refuses.
# Raw and CR-stripped byte counts are compared instead, each stage
# checked on its own (piped into wc, tr's status is invisible and a
# truncated strip miscounts); every indeterminate stage refuses.
CRG_DIG_RAW=$(wc -c < "$HOOK_DIGEST_FILE" 2>/dev/null) || CRG_DIG_RAW=''
# wc's count is validated as EXACTLY one whitespace-delimited field of
# digits via word splitting -- never through a normalizing pipeline,
# whose stripped fragment (and invisible tr status) would launder a
# malformed count into a plausible number. (The positional parameters
# were consumed into named variables at the top; `set --` is free here.)
set -- $CRG_DIG_RAW
if [ "$#" -eq 1 ]; then CRG_DIG_RAW=$1; else CRG_DIG_RAW=''; fi
case "$CRG_DIG_RAW" in ''|*[!0-9]*) CRG_DIG_RAW='' ;; esac
if [ -z "$CRG_DIG_RAW" ]; then
  echo "run-gate: could not measure the dispatcher attestation at $HOOK_DIGEST_FILE (indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
CRG_DIG_TMP=$(mktemp 2>/dev/null || mktemp -t crg-run-gate-cr) || CRG_DIG_TMP=''
if [ -z "$CRG_DIG_TMP" ]; then
  echo "run-gate: could not stage the attestation CR probe (indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
if ! tr -d '\r' < "$HOOK_DIGEST_FILE" > "$CRG_DIG_TMP" 2>/dev/null; then
  rm -f "$CRG_DIG_TMP"
  echo "run-gate: could not measure the dispatcher attestation at $HOOK_DIGEST_FILE (indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
CRG_DIG_BARE=$(wc -c < "$CRG_DIG_TMP" 2>/dev/null) || CRG_DIG_BARE=''
set -- $CRG_DIG_BARE
if [ "$#" -eq 1 ]; then CRG_DIG_BARE=$1; else CRG_DIG_BARE=''; fi
case "$CRG_DIG_BARE" in ''|*[!0-9]*) CRG_DIG_BARE='' ;; esac
rm -f "$CRG_DIG_TMP"
if [ -z "$CRG_DIG_BARE" ]; then
  echo "run-gate: could not measure the dispatcher attestation at $HOOK_DIGEST_FILE (indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
if [ "$CRG_DIG_RAW" -ne "$CRG_DIG_BARE" ]; then
  echo "run-gate: the dispatcher attestation at $HOOK_DIGEST_FILE carries CR bytes the LF-only record grammar refuses - refusing to commit un-gated. Re-run bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi
HOOK_TAIL=$(tail -c 1 "$HOOK_DIGEST_FILE" 2>/dev/null) || HOOK_TAIL='x'
if [ -n "$HOOK_TAIL" ]; then
  echo "run-gate: the dispatcher attestation at $HOOK_DIGEST_FILE does not end in the record grammar's final LF - refusing to commit un-gated. Re-run bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi
HOOK_WANT=$(LC_ALL=C awk 'NR==1{if($0!="crg-dispatcher-digest v1")bad=1;next} NR==2{if(length($0)!=64||$0~/[^0-9a-f]/)bad=1;else hex=$0;next} {bad=1} END{if(bad||NR!=2||hex=="")exit 1;printf "%s",hex}' "$HOOK_DIGEST_FILE" 2>/dev/null) || HOOK_WANT=''
if [ -z "$HOOK_WANT" ]; then
  echo "run-gate: the dispatcher attestation at $HOOK_DIGEST_FILE is not a bootstrap-written attestation record (versioned header plus one lowercase sha256 line) - refusing to commit un-gated. Re-run bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi
# The hasher's output is captured ALONE so its own status decides (a
# `hasher | cut | tr` pipeline reports the last stage's status, and a
# digest line emitted before a nonzero exit would compare equal); the
# digest field is split off by parameter expansion (no glob expansion
# over the path, no further producer), validated as 64 hex, and
# case-folded by a checked awk stage.
if command -v sha256sum >/dev/null 2>&1; then
  HOOK_RAW=$(sha256sum "$HOOK_PATH" 2>/dev/null) || HOOK_RAW=''
elif command -v shasum >/dev/null 2>&1; then
  HOOK_RAW=$(shasum -a 256 "$HOOK_PATH" 2>/dev/null) || HOOK_RAW=''
else
  echo "run-gate: no sha256 tool available (sha256sum/shasum) to verify the dispatcher attestation - refusing to commit un-gated." >&2
  exit 2
fi
if [ -z "$HOOK_RAW" ]; then
  echo "run-gate: could not hash the dispatcher at $HOOK_PATH (the hasher failed; indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
HOOK_HEX=${HOOK_RAW%%[[:space:]]*}
case "$HOOK_HEX" in
  ????????????????????????????????????????????????????????????????) ;;
  *) HOOK_HEX='' ;;
esac
case "$HOOK_HEX" in *[!0-9a-fA-F]*) HOOK_HEX='' ;; esac
if [ -z "$HOOK_HEX" ]; then
  echo "run-gate: the hasher's output for $HOOK_PATH is not a sha256 digest line (indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
HOOK_GOT=$(CRG_HEX_IN="$HOOK_HEX" LC_ALL=C awk 'BEGIN{printf "%s", tolower(ENVIRON["CRG_HEX_IN"])}') || HOOK_GOT=''
# An indeterminate fold is named as such: folding it into the mismatch
# refusal would send the operator into a hook-substitution incident that
# never happened.
if [ -z "$HOOK_GOT" ]; then
  echo "run-gate: could not case-fold the dispatcher digest (the awk stage failed; indeterminate refuses) - refusing to commit un-gated." >&2
  exit 2
fi
if [ "$HOOK_GOT" != "$HOOK_WANT" ]; then
  echo "run-gate: the dispatcher at $HOOK_PATH does not hash to its bootstrap-recorded digest - foreign or stale hook bytes; refusing to commit un-gated. INVESTIGATE the mismatch first (docs/audit-protocol.md, the run-gate audit step: a mismatch is an incident, not noise); repair afterwards via bootstrap.ps1 -DispatcherOnly." >&2
  exit 2
fi

# Preserve Git's status out of band from the NUL-framed pathname stream. A
# partial producer failure, empty record, or unterminated record is not stage
# evidence and refuses before the commit boundary.
staged=$(crg_probe_staged_set)
STAGED_RC=$?
case "$STAGED_RC" in
  0) ;;
  2)
    echo "run-gate: the staged-set probe (git diff --cached --name-only -z) failed or could not be allocated in $WT - refusing to fire the gate on an indeterminate stage" >&2
    exit 2
    ;;
  3)
    echo "run-gate: the staged-set probe returned malformed NUL framing - refusing to fire the gate on an indeterminate stage" >&2
    exit 2
    ;;
  *)
    echo "run-gate: the private staged-set probe could not be cleaned up - refusing before commit" >&2
    exit 2
    ;;
esac
if [ "$staged" -eq 0 ]; then
  echo "run-gate: nothing staged in $WT -- refusing to fire the gate" >&2
  exit 2
fi
echo "run-gate: worktree=$WT staged_files=$staged backend=$BACKEND_NORM passes=$PASSES"

export CROSS_REVIEW_PASSES="$PASSES"
export REVIEW_BACKEND="$BACKEND_NORM"

git commit -F "$MSGFILE_ABS"
rc=$?
echo "run-gate: commit rc=$rc"
# The landed-commit line prints only on success: on a rejected attempt it
# would show the unrelated PREVIOUS commit, a misleading tail for an
# unattended transcript.
if [ "$rc" -eq 0 ]; then
  git log --oneline -1
fi
exit $rc
