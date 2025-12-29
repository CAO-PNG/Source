#!/bin/bash

# 1. 配置路径
SUB_URL="https://excellent.congyusub.top/sub/53409baa898ff231/clash"
HEADER_FILE="$HOME/.config/mihomo/my_header.yaml"
CONFIG_DEST="$HOME/.config/mihomo/config.yaml"
TEMP_SUB="$HOME/.config/mihomo/temp_sub.yaml"

# 2. 下载订阅到临时文件
echo "正在下载并转换订阅..."
# 注意：这里去掉了部分多余参数，让它只输出节点和规则部分
curl -L -o "$TEMP_SUB" "https://api.v1.mk/sub?target=clash&url=$SUB_URL&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online_Full.ini&emoji=true&list=false&udp=true"

if [ $? -eq 0 ]; then
  echo "下载成功，正在合并配置..."

  # 3. 核心步骤：合并自定义头部和下载的内容
  # 首先将头部写入最终文件
  cat "$HEADER_FILE" >"$CONFIG_DEST"

  # 然后追加下载内容中的 proxies, proxy-groups, rules 部分
  # 我们用 sed 删掉下载内容中自带的端口和 DNS 设置（通常在开头）
  # 简单做法是寻找第一个 'proxies:' 关键字并从那里开始截取
  sed -n '/proxies:/,$p' "$TEMP_SUB" >>"$CONFIG_DEST"

  echo "更新成功！正在重启 mihomo 服务..."
  systemctl --user restart mihomo

  # 清理临时文件
  rm "$TEMP_SUB"
  echo "全部完成。"
else
  echo "更新失败，请检查网络或链接。"
fi
