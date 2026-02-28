# This is some setting from zsh
typeset -U path PATH

# alias
# alias vim=nvim
alias tl=tldr
alias yz=yazi
alias discord='discord --proxy-server="socks5://127.0.0.1:7897"'
alias check_ptrace='cat /proc/sys/kernel/yama/ptrace_scope'
alias ptrace_on='echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope'
alias ptrace_off='echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope'
alias ptrace_disable='echo 2 | sudo tee /proc/sys/kernel/yama/ptrace_scope'
alias ptrace_cap='echo 3 | sudo tee /proc/sys/kernel/yama/ptrace_scope'
alias aslr_off='sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"'
alias wslon='sudo ~/bin/wsl-mount.sh mount'
alias wsloff='sudo ~/bin/wsl-mount.sh umount'
alias steam++='~/tools/Steam++/Steam++.sh'
alias ty="setsid typora --enable-features=UseOzonePlatform --ozone-platform=wayland --enable-wayland-ime "$@" > /dev/null 2>&1"
alias deepseek="ollama run deepseek-r1:7b-qwen-distill-q4_K_M"
alias qwen="ollama run qwen2.5-coder:7b"
alias feishin="feishin --ozone-platform-hint=auto --enable-features=WaylandWindowDecorations --disable-gpu-memory-buffer-video-frames"
alias cle="clear"
alias conda_start="source /opt/miniforge/etc/profile.d/conda.sh"
alias sage_start="conda activate sage"
# Start Tun / mihomo
alias restart-mihomo="sudo setcap cap_net_admin,cap_net_bind_service=+ep $(which mihomo) && systemctl --user restart mihomo && lsmod | grep tun"

alias kill_pacman_lock="sudo rm -rf sudo rm -rf  /var/lib/pacman/db.lck"
# Some file Folder alias
hash -d ctf_tools=$HOME/CTF_PWN/tools
hash -d ctf_project=$HOME/CTF_PWN/PROJECT
hash -d download=$HOME/下载/
# pot_start
pot(){
  setsid "/home/source/.local/bin/pot" "$@" > /dev/null 2>&1

}
# gdb-addtch
attach(){
  $HOME/bin/gdb-attach.sh "$@"
}
# IDA-Pro-9.3 /home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida
ida(){
    setsid "/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida" "$@" > /dev/null 2>&1
}
# IDA path=/home/source/CTF_PWN/tools/IDA/IDA Pro 9.1/IDA-9.1/ida
ida9-1(){
    setsid "/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.1/IDA-9.1/ida" "$@" > /dev/null 2>&1
}

# pwn python venv
ctf(){
    source /home/source/CTF_PWN/CTF/bin/activate
}

# pwninit
pwninit(){
  "/home/source/bin/pwninit.sh" "$@"
}

# Clibc
# clibc(){
#   "/home/source/bin/clibc.sh" "$@"
# }

# blog
blog(){
  "/home/source/bin/blog.sh" "$@"
}

# Gemini AI key
export GEMINI_API_KEY="AIzaSyB0vA2bsXIMJV8Zl3OhpM9p52XKDWtRKH8"
# proxy setting
export http_proxy="http://127.0.0.1:7897"
export https_proxy="http://127.0.0.1:7897"
export all_proxy="socks5://127.0.0.1:7897"

# [!] ================= [ * env * ] ===================== [!]

# enovim
export EDITOR=nvim
export VISUAL=nvim
export SUDO_EDITOR=nvim

# pyenv ---> virtualenv-init
export PYENV_VIRTUALENV_DISABLE_PROMPT=1
eval "$(pyenv virtualenv-init -)"

#export PATH="$PATH:$(npm config get prefix)/bin"
export PATH=$PATH:$HOME/.local/share/npm-global/bin
if command -v ruby &> /dev/null; then
    # 获取 gem 的安装路径
    GEM_PATH=$(ruby -e "puts Gem.user_dir" 2>/dev/null)
    if [ -n "$GEM_PATH" ] && [ -d "$GEM_PATH/bin" ]; then
        export PATH="$GEM_PATH/bin:$PATH"
    else
        # 使用默认路径作为备选
        export PATH="$HOME/.local/share/gem/ruby/3.4.0/bin:$PATH"
    fi
fi

# This is pyenv setting :
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
