#!/bin/bash
#export GTK_IM_MODULE=fcitx
#export QT_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx
# 强制使用 XWayland 作为后端
export ELECTRON_OZONE_PLATFORM_HINT=auto
# 或者可以显式指定为 x11
# export ELECTRON_OZONE_PLATFORM_HINT=x11
exec /usr/bin/typora "$@"
