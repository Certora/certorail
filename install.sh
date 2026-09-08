#!/bin/sh
# certorail installer
#
#   ./install.sh                     put `certorail` on your PATH
#   ./install.sh --with-claude-pack  and install the Claude Code pack
#   ./install.sh --uninstall         undo it
#
# There is no `curl ... | sh` form. certorail publishes no release artifact, so there is
# nothing to download and nothing to checksum: this script installs the checkout it sits in.
#
# It picks the first of uv, pipx or a plain venv that is available. uv and pipx own their
# own install location; only the venv fallback uses CERTORAIL_INSTALL_DIR.
#
# Environment overrides:
#   CERTORAIL_SOURCE       the checkout to install (default: the directory holding this script)
#   CERTORAIL_INSTALLER    force one of: uv, pipx, venv
#   CERTORAIL_INSTALL_DIR  where the venv fallback links the entry point
#                          (default: /usr/local/bin if writable, else ~/.local/bin)
#   CERTORAIL_VENV         where the venv fallback builds its environment
#                          (default: ~/.local/share/certorail/venv)

set -eu

err()  { printf 'error: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Every mutating step goes through run(), so --dry-run is the same code path with the doing
# taken out, rather than a second description of it that can drift.
run() {
  if [ "$dry_run" = yes ]; then
    printf '  would: %s\n' "$*" >&2
  else
    "$@"
  fi
}

usage() {
  sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# --- arguments ---------------------------------------------------------------
with_pack=no
uninstall=no
dry_run=no

for arg in "$@"; do
  case "$arg" in
    --with-claude-pack) with_pack=yes ;;
    --uninstall)        uninstall=yes ;;
    --dry-run)          dry_run=yes ;;
    -h|--help)          usage ;;
    *) err "unknown argument: $arg (try --help)" ;;
  esac
done

# --- locate the source -------------------------------------------------------
here="$(cd "$(dirname "$0")" && pwd)"
source_dir="${CERTORAIL_SOURCE:-$here}"
[ -d "$source_dir" ] || err "no such directory: $source_dir"
grep -q '^name = "certorail"$' "$source_dir/pyproject.toml" 2>/dev/null \
  || err "$source_dir is not a certorail checkout (no pyproject.toml naming it)"

# --- choose an installer -----------------------------------------------------
# uv first: it resolves its own interpreter, so it is the one path that works on a machine
# whose default python3 is older than certorail requires.
installer="${CERTORAIL_INSTALLER:-}"
if [ -z "$installer" ]; then
  if   have uv;   then installer=uv
  elif have pipx; then installer=pipx
  else                 installer=venv
  fi
fi

venv="${CERTORAIL_VENV:-$HOME/.local/share/certorail/venv}"

install_dir="${CERTORAIL_INSTALL_DIR:-}"
if [ -z "$install_dir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    install_dir="/usr/local/bin"
  else
    install_dir="$HOME/.local/bin"
  fi
fi

case "$installer" in
  uv)   have uv   || err "CERTORAIL_INSTALLER=uv but uv is not on the PATH" ;;
  pipx) have pipx || err "CERTORAIL_INSTALLER=pipx but pipx is not on the PATH" ;;
  venv)
    have python3 || err "no uv, no pipx, and no python3: nothing here can install certorail"
    python3 - <<'PY' || err "certorail needs Python 3.12 or newer; python3 is older than that"
import sys
sys.exit(0 if sys.version_info >= (3, 12) else 1)
PY
    ;;
  *) err "CERTORAIL_INSTALLER must be uv, pipx or venv (got: $installer)" ;;
esac

# --- uninstall ---------------------------------------------------------------
# The pack installer has a --dry-run of its own, so a dry run here describes both halves.
pack_flags=""
[ "$dry_run" = yes ] && pack_flags="--dry-run"

if [ "$uninstall" = yes ]; then
  if [ "$with_pack" = yes ]; then
    python3 "$source_dir/examples/claude-code-pack/install.py" --uninstall $pack_flags
  fi
  case "$installer" in
    uv)   run uv tool uninstall certorail ;;
    pipx) run pipx uninstall certorail ;;
    venv)
      # Guarded: only ever a path this script builds, never a directory a stray override names.
      case "$venv" in
        */certorail/venv) run rm -rf "$venv" ;;
        *) kept_venv=yes ;;
      esac
      run rm -f "$install_dir/certorail"
      ;;
  esac
  info ""
  if [ "${kept_venv:-no}" = yes ]; then
    info "Entry point removed. $venv was left alone: it is not a path this installer creates,"
    info "so remove it yourself if you meant to."
  else
    info "certorail removed."
  fi
  exit 0
fi

# --- install -----------------------------------------------------------------
info "Installing certorail from $source_dir (via $installer)..."

bin=""
case "$installer" in
  uv)
    run uv tool install --force "$source_dir"
    bin="certorail"
    ;;
  pipx)
    run pipx install --force "$source_dir"
    bin="certorail"
    ;;
  venv)
    run mkdir -p "$(dirname "$venv")" "$install_dir"
    run python3 -m venv "$venv"
    run "$venv/bin/python" -m pip install --quiet --upgrade pip
    run "$venv/bin/python" -m pip install --quiet "$source_dir"
    run ln -sf "$venv/bin/certorail" "$install_dir/certorail"
    bin="$install_dir/certorail"
    ;;
esac

if [ "$dry_run" = yes ]; then
  if [ "$with_pack" = yes ]; then
    info ""
    python3 "$source_dir/examples/claude-code-pack/install.py" --dry-run
  fi
  info ""
  info "Dry run: nothing was installed."
  exit 0
fi

# --- verify ------------------------------------------------------------------
# A version string would only prove the entry point exists. Analysing a program proves the
# thing you actually installed certorail to do.
have "$bin" || [ -x "$bin" ] || err "installed, but '$bin' is not runnable"

probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT INT TERM

"$bin" -c 'print("ok")' --check --root "$probe" >/dev/null 2>&1 \
  || err "'$bin' is installed but could not analyse a trivial program"
"$bin" explain -c 'print("ok")' --root "$probe" >/dev/null 2>&1 \
  || err "'$bin' is installed but 'certorail explain' does not work"

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$source_dir/pyproject.toml" | head -1)"
info ""
info "✓ certorail ${version:-?} installed, and it analyses and explains."

# --- the Claude Code pack ----------------------------------------------------
if [ "$with_pack" = yes ]; then
  info ""
  python3 "$source_dir/examples/claude-code-pack/install.py"
fi

# --- PATH --------------------------------------------------------------------
case "$installer" in
  venv) path_dir="$install_dir" ;;
  *)    path_dir="$(dirname "$(command -v certorail 2>/dev/null || echo "$HOME/.local/bin/certorail")")" ;;
esac
case ":$PATH:" in
  *":$path_dir:"*) ;;
  *)
    info ""
    info "  $path_dir is not on your PATH. Add it with:"
    info "    export PATH=\"$path_dir:\$PATH\""
    ;;
esac

info ""
info "Get started:  certorail explain your_program.py --root ."
