#!/usr/bin/env bash
# Hyprland + xdg-desktop-portal init (wait + retry)
set -u

log() { printf '[portal-init] %s\n' "$*"; }

wait_user_systemd() {
  # 等 systemd --user 可用（running 或 degraded）
  for _ in {1..60}; do
    state="$(systemctl --user is-system-running 2>/dev/null || true)"
    [[ "$state" == "running" || "$state" == "degraded" ]] && return 0
    sleep 0.1
  done
  return 1
}

wait_user_dbus() {
  # 等用户 D-Bus 可用
  for _ in {1..60}; do
    busctl --user --list >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

wait_wayland_socket() {
  # 等 wayland socket 出现
  local sock="${XDG_RUNTIME_DIR:-}/"
  local disp="${WAYLAND_DISPLAY:-}"
  [[ -n "$sock" && -n "$disp" ]] || return 1
  sock="${sock%/}/$disp"
  for _ in {1..80}; do
    [[ -S "$sock" ]] && return 0
    sleep 0.1
  done
  return 1
}

# 0) 等“会话基础设施”就绪
wait_user_systemd || {
  log "systemd --user 仍未就绪，跳过"
  exit 0
}
wait_user_dbus || {
  log "user dbus 仍未就绪，跳过"
  exit 0
}
wait_wayland_socket || {
  log "wayland socket 未就绪，跳过"
  exit 0
}

# 1) 导入环境到 systemd --user
log "import env..."
dbus-update-activation-environment --systemd --all >/dev/null 2>&1 || true
systemctl --user import-environment \
  WAYLAND_DISPLAY XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP XDG_SESSION_TYPE HYPRLAND_INSTANCE_SIGNATURE \
  >/dev/null 2>&1 || true

# 2) 清理失败/残留（允许重复执行）
log "cleanup..."
systemctl --user reset-failed xdg-desktop-portal.service xdg-desktop-portal-hyprland.service >/dev/null 2>&1 || true
systemctl --user stop xdg-desktop-portal.service xdg-desktop-portal-hyprland.service >/dev/null 2>&1 || true
pkill -u "$USER" -f 'xdg-desktop-portal-hyprland' >/dev/null 2>&1 || true
pkill -u "$USER" -f '/usr/lib/xdg-desktop-portal($| )' >/dev/null 2>&1 || true

# 3) 再等一小下，让 compositor/seat 稳定
sleep 1

# 4) 启动（带重试，避免偶发抢跑）
log "start portals..."
for _ in {1..10}; do
  systemctl --user start xdg-desktop-portal-hyprland.service >/dev/null 2>&1 || true
  systemctl --user start xdg-desktop-portal.service >/dev/null 2>&1 || true
  systemctl --user is-active xdg-desktop-portal.service >/dev/null 2>&1 && break
  sleep 0.2
done

systemctl --user --no-pager --full status xdg-desktop-portal-hyprland.service 2>/dev/null | sed -n '1,8p' || true
