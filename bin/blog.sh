#!/bin/zsh

# 智能博客发布脚本 - 支持自动分类
# 使用方法: 
#   1. blog name.zip (直接发布压缩包)
#   2. blog name.md img (打包markdown和图片后发布)

# 配置 - 更新为正确的博客目录
BLOG_ROOT="/home/source/blog_MY"
BLOG_POSTS_DIR="$BLOG_ROOT/source/_posts"
TEMP_DIR="/tmp/blog_upload_$$"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 定义分类映射
declare -A CATEGORY_MAP=(
  ["二进制安全"]="binary-security"
  ["知识库"]="college"
  ["赛题复现"]="writeup"
  ["工具资源"]="tools"
)

# 分类图标映射
declare -A CATEGORY_ICONS=(
  ["二进制安全"]="🛡️"
  ["知识库"]="🔥"
  ["赛题复现"]="📚"
  ["工具资源"]="🛠️"
)

# 检查必要命令
check_commands() {
  local missing=()
  
  if ! command -v unzip &>/dev/null; then
    missing+=("unzip")
  fi
  
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}错误: 缺少必要命令: ${missing[@]}${NC}"
    echo -e "${YELLOW}请安装: sudo apt-get install ${missing[@]}${NC}"
    return 1
  fi
  return 0
}

# 清理函数
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

show_help() {
  echo "博客发布脚本 - 自动分类版"
  echo "用法:"
  echo "  1. blog <压缩包文件>"
  echo "  2. blog <markdown文件> [图片文件夹]"
  echo ""
  echo "支持的分类:"
  echo "  🛡️  二进制安全 -> /categories/binary-security/"
  echo "  🔥 知识库      -> /categories/college/"
  echo "  📚 赛题复现    -> /categories/writeup/"
  echo "  🛠️  工具资源    -> /categories/tools/"
  echo ""
  echo "示例:"
  echo "  blog my-article.zip"
  echo "  blog my-article.md"
  echo "  blog my-article.md img"
  echo "  blog CISCN_2021_初赛_silverwolf.zip"
}

# 智能分类检测函数
detect_category() {
  local title="$1"
  local filename="$2"

  # 关键词映射
  case "${title} ${filename}" in
  *"PWN"* | *"pwn"* | *"二进制"* | *"漏洞"* | *"溢出"* | *"逆向"* | *"RE"* | *"reverse"*)
    echo "二进制安全"
    ;;
  *"CTF"* | *"ctf"* | *"writeup"* | *"Writeup"* | *"WP"* | *"题解"* | *"复现"* | *"赛题"*)
    echo "赛题复现"
    ;;
  *"工具"* | *"工具"* | *"resource"* | *"资源"* | *"配置"* | *"安装"*)
    echo "工具资源"
    ;;
  *"笔记"* | *"学习"* | *"总结"* | *"原理"* | *"基础"* | *"知识"*)
    echo "知识库"
    ;;
  *)
    echo ""
    ;;
  esac
}

# 显示分类选项
show_category_menu() {
  echo -e "${CYAN}=== 请选择文章分类 ===${NC}"
  echo "1. 🛡️  二进制安全 - PWN、逆向、漏洞分析等"
  echo "2. 🔥 知识库      - 学习笔记、技术总结"
  echo "3. 📚 赛题复现    - CTF题目解析和复现"
  echo "4. 🛠️  工具资源    - 工具使用、资源分享"
  echo "5. 手动输入分类"
  echo -e "${YELLOW}请选择 (1-5):${NC}"
}

# 检查命令
if ! check_commands; then
  exit 1
fi

# 检查参数
if [[ $# -eq 0 ]]; then
  echo -e "${RED}错误: 请提供文件参数${NC}"
  show_help
  exit 1
fi

# 创建临时目录
mkdir -p "$TEMP_DIR"

# 判断使用模式：zip文件还是md文件
if [[ "$1" == *.zip ]]; then
  # 模式1: 直接处理zip文件
  ZIP_FILE="$1"
  
  # 处理文件路径
  if [[ "$ZIP_FILE" != /* ]]; then
    ZIP_FILE="$(pwd)/$ZIP_FILE"
  fi

  if [[ ! -f "$ZIP_FILE" ]]; then
    echo -e "${RED}错误: 压缩包 '$ZIP_FILE' 不存在${NC}"
    echo -e "${YELLOW}当前目录: $(pwd)${NC}"
    ls -la *.zip 2>/dev/null || echo "没有找到 .zip 文件"
    exit 1
  fi

  echo -e "${CYAN}=== 智能博客发布开始 ===${NC}"
  echo -e "${BLUE}博客目录: $BLOG_ROOT${NC}"
  echo -e "${BLUE}处理压缩包: $(basename "$ZIP_FILE")${NC}"

  # 解压文件
  echo -e "${BLUE}解压压缩包...${NC}"
  unzip -q "$ZIP_FILE" -d "$TEMP_DIR"

  if [[ $? -ne 0 ]]; then
    echo -e "${RED}错误: 解压失败${NC}"
    exit 1
  fi

elif [[ "$1" == *.md ]] || [[ "$1" == *.markdown ]]; then
  # 模式2: 处理md文件（可能带图片文件夹）
  MD_FILE="$1"
  
  # 处理文件路径
  if [[ "$MD_FILE" != /* ]]; then
    MD_FILE="$(pwd)/$MD_FILE"
  fi

  if [[ ! -f "$MD_FILE" ]]; then
    echo -e "${RED}错误: Markdown文件 '$MD_FILE' 不存在${NC}"
    echo -e "${YELLOW}当前目录: $(pwd)${NC}"
    ls -la *.md *.markdown 2>/dev/null || echo "没有找到 .md 或 .markdown 文件"
    exit 1
  fi

  echo -e "${CYAN}=== 智能博客发布开始 ===${NC}"
  echo -e "${BLUE}博客目录: $BLOG_ROOT${NC}"
  echo -e "${BLUE}处理Markdown文件: $(basename "$MD_FILE")${NC}"

  # 复制md文件到临时目录
  cp "$MD_FILE" "$TEMP_DIR/$(basename "$MD_FILE")"
  
  # 更新MD_FILE路径为临时目录中的文件
  MD_FILE="$TEMP_DIR/$(basename "$MD_FILE")"
  
  # 检查是否有图片文件夹参数
  if [[ $# -ge 2 ]] && [[ -d "$2" ]]; then
    IMG_SOURCE_DIR="$2"
    
    # 处理图片文件夹路径
    if [[ "$IMG_SOURCE_DIR" != /* ]]; then
      IMG_SOURCE_DIR="$(pwd)/$IMG_SOURCE_DIR"
    fi
    
    echo -e "${BLUE}找到图片文件夹: $(basename "$IMG_SOURCE_DIR")${NC}"
    
    # 复制图片文件夹到临时目录
    mkdir -p "$TEMP_DIR/img"
    cp -r "$IMG_SOURCE_DIR"/* "$TEMP_DIR/img/" 2>/dev/null
  elif [[ $# -ge 2 ]] && [[ ! -d "$2" ]]; then
    echo -e "${YELLOW}警告: 第二个参数 '$2' 不是目录，忽略图片文件夹${NC}"
  fi

  # 检查临时目录中是否有img文件夹
  if [[ -d "$TEMP_DIR/img" ]]; then
    echo -e "${GREEN}找到图片文件夹${NC}"
    echo "包含图片:"
    find "$TEMP_DIR/img" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" -o -name "*.jpeg" \) 2>/dev/null | while read img; do
      echo "  - $(basename "$img")"
    done
  else
    # 尝试查找同级目录下的img文件夹
    ORIG_MD_DIR=$(dirname "$1")
    if [[ -d "$ORIG_MD_DIR/img" ]]; then
      echo -e "${GREEN}找到同目录下的图片文件夹${NC}"
      mkdir -p "$TEMP_DIR/img"
      cp -r "$ORIG_MD_DIR/img"/* "$TEMP_DIR/img/" 2>/dev/null
      
      echo "包含图片:"
      find "$TEMP_DIR/img" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" -o -name "*.jpeg" \) 2>/dev/null | while read img; do
        echo "  - $(basename "$img")"
      done
    else
      echo -e "${YELLOW}未找到图片文件夹${NC}"
    fi
  fi
else
  echo -e "${RED}错误: 不支持的文件格式${NC}"
  echo -e "${YELLOW}请提供 .zip 或 .md/.markdown 文件${NC}"
  show_help
  exit 1
fi

# 检查博客目录
if [[ ! -d "$BLOG_ROOT" ]]; then
  echo -e "${RED}错误: 博客目录 '$BLOG_ROOT' 不存在${NC}"
  exit 1
fi

cd "$BLOG_ROOT"

# 查找 markdown 文件
MD_FILES=($(find "$TEMP_DIR" -name "*.md" -o -name "*.markdown" 2>/dev/null))

if [[ ${#MD_FILES[@]} -eq 0 ]]; then
  echo -e "${RED}错误: 未找到 markdown 文件${NC}"
  find "$TEMP_DIR" -type f 2>/dev/null | while read file; do
    echo "  - $(basename "$file")"
  done
  exit 1
fi

if [[ ${#MD_FILES[@]} -gt 1 ]]; then
  echo -e "${YELLOW}找到多个 markdown 文件:${NC}"
  for i in "${!MD_FILES[@]}"; do
    echo "  $((i + 1)). $(basename "${MD_FILES[$i]}")"
  done
  echo -e "${YELLOW}请选择要发布的文件 (1-${#MD_FILES[@]}):${NC}"
  read choice
  if [[ $choice -ge 1 && $choice -le ${#MD_FILES[@]} ]]; then
    MD_FILE="${MD_FILES[$((choice - 1))]}"
  else
    echo -e "${RED}错误: 无效的选择${NC}"
    exit 1
  fi
else
  MD_FILE="${MD_FILES[1]}"
fi

echo -e "${GREEN}找到 markdown 文件: $(basename "$MD_FILE")${NC}"

# 检查图片文件夹
IMG_DIR=""
if [[ -d "$TEMP_DIR/img" ]]; then
  IMG_DIR="$TEMP_DIR/img"
elif [[ -d "$(dirname "$MD_FILE")/img" ]]; then
  IMG_DIR="$(dirname "$MD_FILE")/img"
fi

if [[ -n "$IMG_DIR" && -d "$IMG_DIR" ]]; then
  echo -e "${GREEN}找到图片文件夹${NC}"
else
  echo -e "${YELLOW}未找到图片文件夹${NC}"
fi

# 获取文章基本信息
ARTICLE_NAME=$(basename "$MD_FILE" .md)
ARTICLE_NAME=$(basename "$ARTICLE_NAME" .markdown)
CURRENT_DATE=$(date +"%Y-%m-%d")

# 智能分类检测
echo -e "${CYAN}=== 智能分类检测 ===${NC}"
AUTO_CATEGORY=$(detect_category "$ARTICLE_NAME" "$ARTICLE_NAME")

if [[ -n "$AUTO_CATEGORY" ]]; then
  echo -e "${GREEN}检测到分类: ${CATEGORY_ICONS[$AUTO_CATEGORY]} $AUTO_CATEGORY${NC}"
  echo -e "${YELLOW}是否使用检测到的分类? (Y/n):${NC}"
  read use_auto
  if [[ ! $use_auto =~ ^[Nn]$ ]]; then
    SELECTED_CATEGORY="$AUTO_CATEGORY"
  else
    AUTO_CATEGORY=""
  fi
fi

# 分类选择
if [[ -z "$SELECTED_CATEGORY" ]]; then
  show_category_menu
  read category_choice

  case $category_choice in
  1) SELECTED_CATEGORY="二进制安全" ;;
  2) SELECTED_CATEGORY="知识库" ;;
  3) SELECTED_CATEGORY="赛题复现" ;;
  4) SELECTED_CATEGORY="工具资源" ;;
  5)
    echo -e "${YELLOW}请输入自定义分类:${NC}"
    read SELECTED_CATEGORY
    ;;
  *)
    echo -e "${RED}错误: 无效的选择${NC}"
    exit 1
    ;;
  esac
fi

echo -e "${GREEN}选定分类: ${CATEGORY_ICONS[$SELECTED_CATEGORY]} $SELECTED_CATEGORY${NC}"

# 交互式配置 Front-matter
echo -e "${CYAN}=== 文章配置 ===${NC}"

# 标题（带分类图标）
DEFAULT_TITLE="${CATEGORY_ICONS[$SELECTED_CATEGORY]} $ARTICLE_NAME"
echo -e "${YELLOW}请输入文章标题 (默认: $DEFAULT_TITLE):${NC}"
read TITLE
[[ -z "$TITLE" ]] && TITLE="$DEFAULT_TITLE"

# 自动生成相关标签
case "$SELECTED_CATEGORY" in
"二进制安全")
  DEFAULT_TAGS="PWN,二进制安全,CTF"
  ;;
"知识库")
  DEFAULT_TAGS="学习笔记,知识总结,技术"
  ;;
"赛题复现")
  DEFAULT_TAGS="CTF,Writeup,题解"
  ;;
"工具资源")
  DEFAULT_TAGS="工具,资源,配置"
  ;;
*)
  DEFAULT_TAGS=""
  ;;
esac

echo -e "${YELLOW}请输入文章标签 (用逗号分隔，默认: $DEFAULT_TAGS):${NC}"
read TAGS_INPUT
[[ -z "$TAGS_INPUT" ]] && TAGS_INPUT="$DEFAULT_TAGS"

IFS=',' read -rA TAGS <<<"$TAGS_INPUT"

# 描述
echo -e "${YELLOW}请输入文章描述 (直接回车使用自动生成):${NC}"
read DESCRIPTION
if [[ -z "$DESCRIPTION" ]]; then
  case "$SELECTED_CATEGORY" in
  "二进制安全")
    DESCRIPTION="本文深入探讨二进制安全技术，包含详细的漏洞分析和利用方法"
    ;;
  "知识库")
    DESCRIPTION="技术知识总结和学习笔记，帮助系统化掌握相关技能"
    ;;
  "赛题复现")
    DESCRIPTION="CTF赛题详细复现，包含解题思路和完整操作步骤"
    ;;
  "工具资源")
    DESCRIPTION="实用工具和资源分享，提升工作效率和技术能力"
    ;;
  *)
    DESCRIPTION="技术文章分享"
    ;;
  esac
fi

# 高级选项
echo -e "${YELLOW}是否配置高级选项? (y/N):${NC}"
read CONFIGURE_ADVANCED

if [[ $CONFIGURE_ADVANCED =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}输入文章顶部图片 URL (直接回车跳过):${NC}"
  read TOP_IMG

  echo -e "${YELLOW}输入文章缩略图 URL (直接回车跳过):${NC}"
  read COVER

  echo -e "${YELLOW}是否显示目录? (Y/n):${NC}"
  read TOC_INPUT
  [[ -z "$TOC_INPUT" ]] && TOC_INPUT="true"

  echo -e "${YELLOW}是否显示评论? (Y/n):${NC}"
  read COMMENTS_INPUT
  [[ -z "$COMMENTS_INPUT" ]] && COMMENTS_INPUT="true"

  echo -e "${YELLOW}是否显示版权信息? (Y/n):${NC}"
  read COPYRIGHT_INPUT
  [[ -z "$COPYRIGHT_INPUT" ]] && COPYRIGHT_INPUT="true"
fi

# 生成目标文件名和路径
CATEGORY_DIR="${CATEGORY_MAP[$SELECTED_CATEGORY]}"
if [[ -n "$CATEGORY_DIR" ]]; then
  # 创建分类目录
  mkdir -p "$BLOG_POSTS_DIR/$CATEGORY_DIR"
  TARGET_FILENAME="${CURRENT_DATE}-${ARTICLE_NAME}.md"
  TARGET_PATH="$BLOG_POSTS_DIR/$CATEGORY_DIR/$TARGET_FILENAME"
  RESOURCE_DIR="$BLOG_POSTS_DIR/$CATEGORY_DIR/${CURRENT_DATE}-${ARTICLE_NAME}"
else
  TARGET_FILENAME="${CURRENT_DATE}-${ARTICLE_NAME}.md"
  TARGET_PATH="$BLOG_POSTS_DIR/$TARGET_FILENAME"
  RESOURCE_DIR="$BLOG_POSTS_DIR/${CURRENT_DATE}-${ARTICLE_NAME}"
fi

# 处理重名文件
COUNTER=1
while [[ -f "$TARGET_PATH" ]]; do
  TARGET_FILENAME="${CURRENT_DATE}-${ARTICLE_NAME}-${COUNTER}.md"
  if [[ -n "$CATEGORY_DIR" ]]; then
    TARGET_PATH="$BLOG_POSTS_DIR/$CATEGORY_DIR/$TARGET_FILENAME"
    RESOURCE_DIR="$BLOG_POSTS_DIR/$CATEGORY_DIR/${CURRENT_DATE}-${ARTICLE_NAME}-${COUNTER}"
  else
    TARGET_PATH="$BLOG_POSTS_DIR/$TARGET_FILENAME"
    RESOURCE_DIR="$BLOG_POSTS_DIR/${CURRENT_DATE}-${ARTICLE_NAME}-${COUNTER}"
  fi
  ((COUNTER++))
done

if [[ $COUNTER -gt 1 ]]; then
  echo -e "${YELLOW}文件已存在，使用新名称: $TARGET_FILENAME${NC}"
fi

# 处理图片
if [[ -n "$IMG_DIR" && -d "$IMG_DIR" ]]; then
  echo -e "${BLUE}创建资源文件夹并处理图片...${NC}"
  mkdir -p "$RESOURCE_DIR"

  # 复制图片文件
  cp -r "$IMG_DIR"/* "$RESOURCE_DIR/" 2>/dev/null
  echo -e "${GREEN}✓ 图片已复制到资源文件夹${NC}"

  # 处理图片引用
  echo -e "${BLUE}更新图片引用...${NC}"
  TEMP_MD="$TEMP_DIR/processed.md"

  cp "$MD_FILE" "$TEMP_MD"

  # 处理所有图片引用格式
  sed -i "s|!\[\([^]]*\)\](\./img/\([^)]*\))|{% asset_img \2 \1 %}|g" "$TEMP_MD"
  sed -i "s|!\[\([^]]*\)\](/img/\([^)]*\))|{% asset_img \2 \1 %}|g" "$TEMP_MD"
  sed -i "s|!\[\([^]]*\)\](img/\([^)]*\))|{% asset_img \2 \1 %}|g" "$TEMP_MD"

  MD_FILE="$TEMP_MD"
  echo -e "${GREEN}✓ 图片引用已更新为 Hexo 资源标签${NC}"
fi

# 创建 Front-matter
echo -e "${BLUE}生成 Front-matter...${NC}"
FRONT_MATTER="---\n"
FRONT_MATTER+="title: $TITLE\n"
FRONT_MATTER+="date: $(date +'%Y-%m-%d %H:%M:%S')\n"

# 分类
FRONT_MATTER+="categories:\n"
FRONT_MATTER+="  - $SELECTED_CATEGORY\n"

# 标签
if [[ ${#TAGS[@]} -gt 0 ]]; then
  FRONT_MATTER+="tags:\n"
  for tag in "${TAGS[@]}"; do
    FRONT_MATTER+="  - ${tag# }\n"
  done
fi

# 描述
FRONT_MATTER+="description: $DESCRIPTION\n"

# 高级选项
if [[ $CONFIGURE_ADVANCED =~ ^[Yy]$ ]]; then
  [[ -n "$TOP_IMG" ]] && FRONT_MATTER+="top_img: $TOP_IMG\n"
  [[ -n "$COVER" ]] && FRONT_MATTER+="cover: $COVER\n"
  [[ -n "$TOC_INPUT" ]] && FRONT_MATTER+="toc: $TOC_INPUT\n"
  [[ -n "$COMMENTS_INPUT" ]] && FRONT_MATTER+="comments: $COMMENTS_INPUT\n"
  [[ -n "$COPYRIGHT_INPUT" ]] && FRONT_MATTER+="copyright: $COPYRIGHT_INPUT\n"
fi

FRONT_MATTER+="---\n\n"

# 显示生成的 Front-matter 预览
echo -e "${PURPLE}=== 生成的 Front-matter ===${NC}"
echo -e "${FRONT_MATTER}"

# 确认发布
read -q "REPLY?是否使用以上配置发布文章? (y/N): "
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}已取消发布${NC}"
  exit 0
fi

# 创建最终文章
echo -e "${FRONT_MATTER}$(cat "$MD_FILE")" >"$TARGET_PATH"

if [[ $? -eq 0 ]]; then
  echo -e "${GREEN}✓ 文章创建成功: $TARGET_FILENAME${NC}"
  echo -e "${BLUE}文件位置: $TARGET_PATH${NC}"
  echo -e "${GREEN}✓ 分类: ${CATEGORY_ICONS[$SELECTED_CATEGORY]} $SELECTED_CATEGORY${NC}"

  if [[ -n "$IMG_DIR" && -d "$IMG_DIR" ]]; then
    echo -e "${GREEN}✓ 图片资源文件夹: $(basename "$RESOURCE_DIR")/${NC}"
  fi
else
  echo -e "${RED}✗ 文章创建失败${NC}"
  exit 1
fi

# 自动部署
echo -e "${CYAN}=== 自动部署 ===${NC}"
echo -e "${BLUE}生成静态文件并部署...${NC}"

hexo clean && hexo g && hexo d

if [[ $? -eq 0 ]]; then
  echo -e "${GREEN}✓ 部署成功!${NC}"
  echo -e "${CYAN}文章已发布到: ${CATEGORY_ICONS[$SELECTED_CATEGORY]} $SELECTED_CATEGORY 板块${NC}"
else
  echo -e "${RED}✗ 部署失败${NC}"
  echo -e "${YELLOW}请手动运行: cd $BLOG_ROOT && hexo clean && hexo g && hexo d${NC}"
fi

echo -e "${CYAN}=== 博客发布完成 ===${NC}"
