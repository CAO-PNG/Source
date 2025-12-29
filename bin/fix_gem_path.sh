#!/bin/bash

# 修复 gem 路径脚本

echo "=== 修复 gem 路径问题 ==="

# 获取 gem 路径
GEM_PATH=$(ruby -e "puts Gem.user_dir" 2>/dev/null)

if [ -z "$GEM_PATH" ]; then
  echo "错误: 无法获取 gem 路径"
  echo "尝试使用默认路径..."
  GEM_PATH="$HOME/.local/share/gem/ruby/3.4.0"
fi

echo "检测到的 gem 路径: $GEM_PATH"

# 检查路径是否存在
if [ ! -d "$GEM_PATH/bin" ]; then
  echo "警告: $GEM_PATH/bin 目录不存在"
  echo "尝试创建目录..."
  mkdir -p "$GEM_PATH/bin" 2>/dev/null
fi

# 更新 ~/.zshrc
echo "更新 ~/.zshrc..."
if ! grep -q "Gem.user_dir" ~/.zshrc; then
  cat >>~/.zshrc <<'EOF'

# ======================
# Ruby gem 路径配置
# ======================
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
EOF
  echo "✓ 已将 gem 路径配置添加到 ~/.zshrc"
else
  echo "✓ gem 路径配置已存在于 ~/.zshrc"
fi

# 更新 ~/.oh-my-zsh/custom/App_start.zsh
if [ -f ~/.oh-my-zsh/custom/App_start.zsh ]; then
  echo "更新 ~/.oh-my-zsh/custom/App_start.zsh..."

  if ! grep -q "Gem.user_dir" ~/.oh-my-zsh/custom/App_start.zsh; then
    cat >>~/.oh-my-zsh/custom/App_start.zsh <<'EOF'

# ======================
# Ruby gem 工具配置
# ======================
if command -v ruby &> /dev/null; then
    # 获取 gem 的安装路径
    GEM_PATH=$(ruby -e "puts Gem.user_dir" 2>/dev/null)
    if [ -n "$GEM_PATH" ] && [ -d "$GEM_PATH/bin" ]; then
        export PATH="$GEM_PATH/bin:$PATH"
        echo "Ruby gem 工具路径已添加: $GEM_PATH/bin"
    fi
fi
EOF
    echo "✓ 已将 gem 路径配置添加到 App_start.zsh"
  else
    echo "✓ gem 路径配置已存在于 App_start.zsh"
  fi
fi

# 立即应用配置
echo "立即应用配置..."
if command -v ruby &>/dev/null; then
  GEM_PATH=$(ruby -e "puts Gem.user_dir" 2>/dev/null)
  if [ -n "$GEM_PATH" ] && [ -d "$GEM_PATH/bin" ]; then
    export PATH="$GEM_PATH/bin:$PATH"
    echo "当前会话 PATH 已更新"
  else
    export PATH="$HOME/.local/share/gem/ruby/3.4.0/bin:$PATH"
    echo "使用默认路径更新当前会话 PATH"
  fi
fi

# 验证安装
echo ""
echo "=== 验证安装 ==="
echo "当前 PATH 中的 gem 相关路径:"
echo "$PATH" | tr ':' '\n' | grep -E "(gem|ruby)" | sort -u

echo ""
echo "检查 gem 可执行文件:"
if command -v one_gadget &>/dev/null; then
  echo "✓ one_gadget: $(one_gadget --version 2>/dev/null || echo '已安装')"
else
  echo "✗ one_gadget: 未找到，尝试直接路径调用..."
  if [ -f "$GEM_PATH/bin/one_gadget" ]; then
    echo "  找到文件: $GEM_PATH/bin/one_gadget"
    "$GEM_PATH/bin/one_gadget" --version 2>&1 | head -1
  fi
fi

if command -v seccomp-tools &>/dev/null; then
  echo "✓ seccomp-tools: $(seccomp-tools --version 2>/dev/null || echo '已安装')"
else
  echo "✗ seccomp-tools: 未找到，尝试直接路径调用..."
  if [ -f "$GEM_PATH/bin/seccomp-tools" ]; then
    echo "  找到文件: $GEM_PATH/bin/seccomp-tools"
    "$GEM_PATH/bin/seccomp-tools" --version 2>&1 | head -1
  fi
fi

echo ""
echo "=== gem 环境信息 ==="
gem env | grep -E "(USER INSTALLATION DIRECTORY|EXECUTABLE DIRECTORY|PATH)"

echo ""
echo "修复完成！请重新打开终端或运行: source ~/.zshrc"
echo "如果仍然有问题，请检查 ~/.zshrc 和 ~/.oh-my-zsh/custom/App_start.zsh 中的配置"
