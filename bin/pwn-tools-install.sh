#!/bin/bash

# ===========================================
# CTF PWN 工具精简安装脚本 for Arch Linux
# ===========================================

set -e # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否是 Arch Linux
check_distro() {
  if [ ! -f /etc/arch-release ]; then
    log_error "这个脚本只支持 Arch Linux!"
    exit 1
  fi
}

# 提前获取 sudo 权限，避免多次输入密码
get_sudo_access() {
  log_info "请求 sudo 权限..."
  sudo -v
  # 保持 sudo 权限
  while true; do
    sudo -n true
    sleep 60
    kill -0 "$$" 2>/dev/null || exit
  done 2>/dev/null &
  SUDO_PID=$!
  log_success "sudo 权限已获取"
}

# 清理 sudo 进程
cleanup() {
  if [ -n "$SUDO_PID" ]; then
    kill $SUDO_PID 2>/dev/null
  fi
  exit 0
}

# 设置 trap 以在脚本退出时清理
trap cleanup EXIT INT TERM

# 安全安装函数 - 如果包不存在也不会退出
safe_install() {
  local pkg="$1"
  log_info "尝试安装: $pkg"

  # 检查包是否存在
  if pacman -Si "$pkg" &>/dev/null; then
    sudo pacman -S --noconfirm "$pkg" || {
      log_warning "安装 $pkg 时出错，跳过..."
    }
  else
    log_warning "包 $pkg 在仓库中不存在，跳过..."
  fi
}

# 检查并安装 yay
install_yay() {
  if ! command -v yay &>/dev/null; then
    log_info "安装 yay..."
    sudo pacman -S --noconfirm git base-devel
    git clone https://aur.archlinux.org/yay.git /tmp/yay
    cd /tmp/yay
    makepkg -si --noconfirm || {
      log_warning "安装 yay 失败，可能影响后续安装"
    }
    cd -
  fi
}

# 安装系统包
install_system_packages() {
  log_info "安装系统包..."

  # 更新系统
  sudo pacman -Syu --noconfirm

  # 安装基础工具
  sudo pacman -S --noconfirm --needed \
    vim \
    git \
    gcc \
    python \
    python-pip \
    python-virtualenv \
    qemu-full \
    gdb \
    patchelf

  log_success "系统包安装完成"
}

# 安装交叉编译工具链
install_cross_compilers() {
  log_info "安装交叉编译工具链..."

  # 定义要安装的工具链数组
  local cross_compilers=(
    arm-linux-gnueabihf-gcc
    aarch64-linux-gnu-gcc
    mips-linux-gnu-gcc
    mipsel-linux-gnu-gcc
    mips64-linux-gnuabi64-gcc
    mips64el-linux-gnuabi64-gcc
  )

  for compiler in "${cross_compilers[@]}"; do
    safe_install "$compiler"
  done

  log_success "交叉编译工具链安装完成"
}

# 创建目录结构
create_directories() {
  log_info "创建目录结构..."

  mkdir -p ~/CTF_PWN/tools
  mkdir -p ~/CTF_PWN/{challenges,scripts,binaries}

  log_success "目录创建完成"
}

# 创建 Python 虚拟环境并安装工具
setup_python_tools() {
  log_info "设置 Python 虚拟环境..."

  # 创建虚拟环境
  python -m venv ~/CTF_PWN/venv

  # 激活虚拟环境
  source ~/CTF_PWN/venv/bin/activate

  # 升级 pip
  pip install --upgrade pip setuptools wheel

  # 安装 pwntools
  log_info "安装 pwntools..."
  pip install pwntools

  log_success "Python 虚拟环境设置完成"
}

# 安装克隆工具到 ~/CTF_PWN/tools
install_cloned_tools() {
  log_info "安装克隆工具..."

  # LibcSearcher
  log_info "克隆 LibcSearcher..."
  git clone https://github.com/lieanu/LibcSearcher.git ~/CTF_PWN/tools/LibcSearcher || {
    log_warning "克隆 LibcSearcher 失败，跳过..."
  }

  if [ -d ~/CTF_PWN/tools/LibcSearcher ]; then
    cd ~/CTF_PWN/tools/LibcSearcher
    pip install . || log_warning "安装 LibcSearcher 失败"
    cd -
  fi

  # ROPgadget
  log_info "克隆 ROPgadget..."
  git clone https://github.com/JonathanSalwan/ROPgadget.git ~/CTF_PWN/tools/ROPgadget || {
    log_warning "克隆 ROPgadget 失败，跳过..."
  }

  if [ -d ~/CTF_PWN/tools/ROPgadget ]; then
    cd ~/CTF_PWN/tools/ROPgadget
    pip install . || log_warning "安装 ROPgadget 失败"
    cd -
  fi

  log_success "克隆工具安装完成"
}

# 安装 GDB 插件
install_gdb_plugins() {
  log_info "安装 GDB 插件..."

  # 创建插件目录
  mkdir -p ~/CTF_PWN/tools/gdb-plugins

  # 安装 pwndbg
  log_info "安装 pwndbg..."
  git clone https://github.com/pwndbg/pwndbg.git ~/CTF_PWN/tools/gdb-plugins/pwndbg || {
    log_warning "克隆 pwndbg 失败，跳过..."
  }

  if [ -d ~/CTF_PWN/tools/gdb-plugins/pwndbg ]; then
    cd ~/CTF_PWN/tools/gdb-plugins/pwndbg
    ./setup.sh || log_warning "安装 pwndbg 失败"
    cd -
  fi

  # 安装 peda
  log_info "安装 peda..."
  git clone https://github.com/longld/peda.git ~/CTF_PWN/tools/gdb-plugins/peda || {
    log_warning "克隆 peda 失败，跳过..."
  }

  # 安装 gef
  log_info "安装 gef..."
  git clone https://github.com/hugsy/gef.git ~/CTF_PWN/tools/gdb-plugins/gef || {
    log_warning "克隆 gef 失败，跳过..."
  }

  if [ -d ~/CTF_PWN/tools/gdb-plugins/gef ]; then
    wget -O ~/.gdbinit-gef.py https://raw.githubusercontent.com/hugsy/gef/master/gef.py || {
      log_warning "下载 gef.py 失败，跳过..."
    }
  fi

  # 配置 ~/.gdbinit (默认使用 pwndbg)
  if [ -f ~/CTF_PWN/tools/gdb-plugins/pwndbg/gdbinit.py ]; then
    cat >~/.gdbinit <<'EOF'
# 使用 pwndbg
source ~/CTF_PWN/tools/gdb-plugins/pwndbg/gdbinit.py

# 通用设置
set disassembly-flavor intel
set pagination off
set history save on
set history filename ~/.gdb_history
EOF
  else
    log_warning "pwndbg 未安装，跳过创建 .gdbinit 文件"
  fi

  log_success "GDB 插件安装完成"
}

# 安装 Ruby gem 工具
install_gem_tools() {
  log_info "安装 Ruby gem 工具..."

  # 检查 ruby 是否已安装
  if ! command -v gem &>/dev/null; then
    log_warning "gem 未找到，跳过安装 Ruby gem 工具"
    return
  fi

  # 安装 one_gadget
  log_info "安装 one_gadget..."
  gem install one_gadget || log_warning "安装 one_gadget 失败"

  # 安装 seccomp-tools
  log_info "安装 seccomp-tools..."
  gem install seccomp-tools || log_warning "安装 seccomp-tools 失败"

  log_success "Ruby gem 工具安装完成"
}

# 安装 gdb-multiarch (来自 AUR)
install_gdb_multiarch() {
  log_info "安装 gdb-multiarch..."

  # 检查 yay 是否可用
  if command -v yay &>/dev/null; then
    yay -S --noconfirm gdb-multiarch || {
      log_warning "安装 gdb-multiarch 失败，跳过..."
    }
  else
    log_warning "yay 未安装，跳过安装 gdb-multiarch"
  fi

  log_success "gdb-multiarch 安装完成"
}

# 创建基础配置脚本
create_basic_config() {
  log_info "创建基础配置..."

  # 创建简单的启动脚本
  cat >~/CTF_PWN/scripts/start_ctf.sh <<'EOF'
#!/bin/bash
# 启动 CTF 环境
source ~/CTF_PWN/venv/bin/activate
echo "CTF 环境已启动"
echo "Python 虚拟环境: $(python --version 2>/dev/null)"
EOF

  chmod +x ~/CTF_PWN/scripts/start_ctf.sh

  log_success "基础配置创建完成"
}

# 显示安装总结
show_summary() {
  echo ""
  echo "========== 安装总结 =========="
  echo "已安装/配置的工具:"
  echo "  ✓ 系统包: vim, git, gcc, python, pip, qemu, gdb, patchelf"
  echo "  ✓ 交叉编译工具链 (部分可能未安装)"
  echo "  ✓ Python 虚拟环境 (~/CTF_PWN/venv)"
  echo "  ✓ pwntools (在虚拟环境中)"
  echo "  ✓ ROPgadget (~/CTF_PWN/tools)"
  echo "  ✓ LibcSearcher (~/CTF_PWN/tools)"
  echo "  ✓ one_gadget 和 seccomp-tools (gem)"
  echo "  ✓ GDB 插件: pwndbg, peda, gef"
  echo "  ✓ gdb-multiarch (如果 yay 可用)"
  echo ""
  echo "========== 目录结构 =========="
  echo "~/CTF_PWN/"
  echo "├── venv/           # Python 虚拟环境"
  echo "├── tools/          # 工具目录"
  echo "│   ├── LibcSearcher/"
  echo "│   ├── ROPgadget/"
  echo "│   └── gdb-plugins/"
  echo "├── scripts/"
  echo "├── challenges/"
  echo "└── binaries/"
  echo ""
  echo "========== 使用方法 =========="
  echo "1. 启动虚拟环境: source ~/CTF_PWN/venv/bin/activate"
  echo "2. 使用 pwntools: python -c 'from pwn import *'"
  echo "3. 启动 GDB: gdb"
  echo "4. 查看 ~/.gdbinit 配置"
  echo "=================================="
}

# 主安装函数
main_install() {
  log_info "开始安装 CTF PWN 工具..."

  check_distro
  get_sudo_access
  install_yay
  install_system_packages
  install_cross_compilers
  create_directories
  setup_python_tools
  install_cloned_tools
  install_gdb_plugins
  install_gem_tools
  install_gdb_multiarch
  create_basic_config

  log_success "安装过程完成！"
  show_summary
}

# 运行安装
main_install
chmod +x ./fix_gem_path.sh
./fix_gem_path.sh
