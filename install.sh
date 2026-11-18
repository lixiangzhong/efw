#!/bin/sh
# efw Linux 一键安装脚本（官方 GitHub 直连）
#
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | VERSION=v1.6.0 sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | BINDIR="$HOME/.local/bin" sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | SKIP_NFT_CHECK=1 sh
#   wget -qO- https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#
# 本脚本只走 GitHub 官方地址；国内网络请用 install_cn.sh（内置镜像加速）。
# 仅支持 Linux（amd64 / arm64），默认安装到 /usr/local/bin/efw。
# 安装前会检查 nft：命令缺失直接中止，root 下还会验证内核 nf_tables；SKIP_NFT_CHECK=1 跳过该预检。
set -eu

REPO="lixiangzhong/efw"
BINDIR="${BINDIR:-/usr/local/bin}"
VERSION="${VERSION:-}"

# 官方直连的超时；连不上就报错，不自动切镜像。
NET_TIMEOUT=10

die() {
	echo "install.sh: $*" >&2
	exit 1
}

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "需要 curl 或 wget"

# 安装前预检：nft 命令必须存在；root 下再用只读的 `nft list ruleset` 验证内核 nf_tables 可用。
# 非 root 无法验证内核，仅告警；SKIP_NFT_CHECK=1 跳过全部预检。
check_nft() {
	if [ "${SKIP_NFT_CHECK:-0}" = "1" ]; then
		echo "已跳过 nft 预检（SKIP_NFT_CHECK=1）" >&2
		return 0
	fi
	# Debian 系把 nft 装在 /usr/sbin，非 root 的 PATH 常不含它，这里补查常见路径。
	nft_bin="$(PATH="$PATH:/usr/sbin:/sbin" command -v nft || true)"
	[ -n "$nft_bin" ] ||
		die "未找到 nft 命令；请先安装 nftables（Debian/Ubuntu: apt install nftables，RHEL 系: dnf install nftables），或用 SKIP_NFT_CHECK=1 跳过预检"
	if [ "$(id -u)" -ne 0 ]; then
		echo "警告: 非 root，无法验证内核 nf_tables，跳过内核检查" >&2
		return 0
	fi
	"$nft_bin" list ruleset >/dev/null 2>&1 ||
		die "无法使用 nftables（内核未启用 nf_tables，或当前命名空间缺少 CAP_NET_ADMIN）；用 SKIP_NFT_CHECK=1 可跳过预检"
}

fetch_stdout() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout "$NET_TIMEOUT" "$1"
	else
		wget -q -T "$NET_TIMEOUT" -t 1 -O - "$1"
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout "$NET_TIMEOUT" -o "$2" "$1"
	else
		wget -q -T "$NET_TIMEOUT" -t 1 -O "$2" "$1"
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
*) die "不支持的架构: ${arch}（仅提供 linux/amd64、linux/arm64）" ;;
esac

check_nft

# 解析最新版本标签：优先 GitHub API；不可用时退回 releases/latest 页面。
latest_tag() {
	_body="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest")" || _body=""
	tag="$(printf '%s\n' "$_body" |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	if [ -z "$tag" ]; then
		_body="$(fetch_stdout "https://github.com/$REPO/releases/latest")" || return 1
		tag="$(printf '%s\n' "$_body" |
			sed -n 's|.*releases/tag/\(v[^"/]*\).*|\1|p' | head -n 1)"
	fi
	[ -n "$tag" ] || return 1
	printf '%s\n' "$tag"
}

if [ -z "$VERSION" ]; then
	tag="$(latest_tag)" || die "无法获取最新版本；请用 VERSION=v1.6.0 指定版本"
else
	tag="$VERSION"
	case "$tag" in
	v*) ;;
	*) tag="v$tag" ;;
	esac
fi

# 严格校验版本格式，防止异常字符或路径穿越
case "$tag" in
v[0-9]*.[0-9]*) ;;
*) die "版本格式非法: ${tag}（期望如 v1.6.0）" ;;
esac
case "$tag" in
*[!A-Za-z0-9._-]*) die "版本包含非法字符: $tag" ;;
esac

ver="${tag#v}"
asset="efw_${ver}_linux_${arch}"
url="https://github.com/$REPO/releases/download/$tag/$asset"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "下载 ${asset}（${tag}）..."
download "$url" "$tmp/$asset" ||
	die "下载失败: ${url}（可改用 VERSION=v1.6.0 指定版本，或检查网络；国内建议改用 install_cn.sh）"

# 下载 checksums.txt 并验证二进制 SHA256，校验失败或无法获取必须中止，严禁降级静默安装。
if [ "${SKIP_CHECKSUM:-0}" = "1" ]; then
	echo "警告: 已跳过 SHA256 校验（SKIP_CHECKSUM=1）" >&2
elif download "https://github.com/$REPO/releases/download/$tag/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
	expected="$(awk -v a="$asset" '$2 == a { print $1; exit }' "$tmp/checksums.txt")"
	if [ -z "$expected" ]; then
		die "checksums.txt 中未包含 $asset 校验和，中止安装（如确需跳过可用 SKIP_CHECKSUM=1）"
	fi
	if command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
	else
		actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
	fi
	[ "$actual" = "$expected" ] || die "SHA256 校验失败（期望: ${expected}，实际: ${actual}）"
	echo "SHA256 校验通过"
else
	die "无法下载 checksums.txt，为保障安全已中止安装（如确需跳过可用 SKIP_CHECKSUM=1）"
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
