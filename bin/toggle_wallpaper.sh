#!/usr/bin/env bash
set -euo pipefail

# 强制 Wayland：不允许程序看到 X11
unset DISPLAY
unset XAUTHORITY
export SDL_VIDEODRIVER=wayland

WP_HDMI="3538114558"
WP_EDP="3146507587"

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

# 如果 WAYLAND_DISPLAY 没给，自动探测一个可用的 wayland-*
if [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
  for s in "$XDG_RUNTIME_DIR"/wayland-*; do
    [[ -S "$s" ]] || continue
    export WAYLAND_DISPLAY="$(basename "$s")"
    break
  done
fi

# 等 Wayland socket 就绪
for _ in {1..80}; do
  if [[ -n "${WAYLAND_DISPLAY:-}" && -S "${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}" ]]; then
    break
  fi
  sleep 1
done

if [[ -z "${WAYLAND_DISPLAY:-}" || ! -S "${XDG_RUNTIME_DIR}/${WAYLAND_DISPLAY}" ]]; then
  echo "Wayland socket not ready: XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-<unset>}" >&2
  exit 1
fi

# 软杀旧进程（可选）
pkill -u "$USER" -x linux-wallpaperengine 2>/dev/null || true
sleep 0.2

exec linux-wallpaperengine \
  --silent \
  --screen-root "HDMI-A-3" --bg "$WP_HDMI" \
  --screen-root "eDP-1" --bg "$WP_EDP"
