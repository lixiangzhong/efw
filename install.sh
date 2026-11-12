#!/bin/sh
# efw Linux 一键安装脚本
#
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | VERSION=v1.0.0 sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | BINDIR="$HOME/.local/bin" sh
#   wget -qO- https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#
# 仅支持 Linux（amd64 / arm64），默认安装到 /usr/local/bin/efw。
set -eu

REPO="lixiangzhong/efw"
BINDIR="${BINDIR:-/usr/local/bin}"
VERSION="${VERSION:-}"

die() {
	echo "install.sh: $*" >&2
	exit 1
}

fetch_stdout() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- "$1"
	else
		die "需要 curl 或 wget"
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	else
		wget -q "$1" -O "$2"
	fi
}

case "$(uname -s)" in
Linux) ;;
*) die "仅支持 Linux（当前: $(uname -s)）" ;;
esac

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*) die "不支持的架构: $arch（仅提供 linux/amd64、linux/arm64）" ;;
esac

if [ -z "$VERSION" ]; then
	tag="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	[ -n "$tag" ] || die "无法获取最新版本；请用 VERSION=v1.0.0 指定版本"
else
	tag="$VERSION"
	case "$tag" in
	v*) ;;
	*) tag="v$tag" ;;
	esac
fi

ver="${tag#v}"
asset="efw_${ver}_linux_${arch}"
url="https://github.com/$REPO/releases/download/$tag/$asset"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "下载 $asset（$tag）..."
download "$url" "$tmp/$asset" || die "下载失败: $url"

if download "https://github.com/$REPO/releases/download/$tag/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
	expected="$(awk -v a="$asset" '$2 == a { print $1; exit }' "$tmp/checksums.txt")"
	if [ -z "$expected" ]; then
		echo "警告: checksums.txt 中没有 $asset，跳过校验" >&2
	else
		if command -v sha256sum >/dev/null 2>&1; then
			actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
		else
			actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
		fi
		[ "$actual" = "$expected" ] || die "SHA256 校验失败"
		echo "SHA256 校验通过"
	fi
else
	echo "警告: 无法下载 checksums.txt，跳过校验" >&2
fi

chmod 0755 "$tmp/$asset"

if [ "$(id -u)" -eq 0 ]; then
	install -d "$BINDIR"
	install -m 0755 "$tmp/$asset" "$BINDIR/efw"
elif [ -w "$BINDIR" ] || { [ ! -e "$BINDIR" ] && [ -w "$(dirname "$BINDIR")" ]; }; then
	install -d "$BINDIR"
	install -m 0755 "$tmp/$asset" "$BINDIR/efw"
elif command -v sudo >/dev/null 2>&1; then
	sudo install -d "$BINDIR"
	sudo install -m 0755 "$tmp/$asset" "$BINDIR/efw"
else
	die "需要 root 权限或 sudo 才能写入 $BINDIR"
fi

echo
echo "已安装: $BINDIR/efw"
"$BINDIR/efw" version || true

cat <<'EOF'

示例 ACL（保存为 /etc/fw.sh，首行 shebang 必须是第一行）：

#!/usr/local/bin/efw apply
# 只拦截外部来源：内网/容器/回环自动放行
accept {
  # 管理白名单：全端口（含 SSH 22）
  1.2.3.4
  198.51.100.0/24

  # 对全网开放的业务端口
  * -> 80,443

  # 放行 ICMP
  icmp
}

drop

使用：
  chmod +x /etc/fw.sh
  /etc/fw.sh          # 编译 + 校验 + 原子覆盖
  # rc.local 中调用 /etc/fw.sh 即可开机重建
EOF
