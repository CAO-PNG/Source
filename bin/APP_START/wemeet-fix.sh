#!/bin/bash
# 腾讯会议(Wemeet) 在 Hyprland 下的启动和修复脚本 (Xwayland 稳定模式 + NVIDIA MESA 兼容性)

# ==========================================
# 1. 强制 Xwayland/X11 平台 (避免 Wayland 原生 Bug)
# ==========================================
export XDG_SESSION_TYPE="x11"
export QT_QPA_PLATFORM="xcb"
export WAYLAND_DISPLAY=""

# ==========================================
# 2. NVIDIA 兼容性修复 (解决绿色/黑色窗口)
# ==========================================
# 强制使用 Mesa EGL 库来处理 EGL/Vulkan 渲染 (解决 NVIDIA 驱动黑屏/绿屏，用户建议)
export __EGL_VENDOR_LIBRARY_FILENAMES="/usr/share/glvnd/egl_vendor.d/50_mesa.json"

# 强制禁用 Pipewire 对 Xwayland/X11 共享的硬件加速（DMABUF），使用 CPU 转换
# 这是解决 Xwayland 共享绿屏/黑屏最有效的手段之一
export XDG_DESKTOP_PORTAL_WLR_USE_DMABUF=0

# ==========================================
# 3. 其他配置
# ==========================================
export WEMEET_USE_NATIVE_WINDOW=1
export GTK_IM_MODULE=fcitx
export QT_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx

# ==========================================
# 4. 启动腾讯会议
# ==========================================
exec /usr/bin/wemeet "$@"
