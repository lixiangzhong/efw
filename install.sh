#!/bin/sh
# efw Linux 一键安装脚本
#
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | VERSION=v1.1.0 sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | BINDIR="$HOME/.local/bin" sh
#   curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | SKIP_NFT_CHECK=1 sh
#   wget -qO- https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#
# 国内网络：官方地址连不上时自动改用下面的镜像前缀重试。
#   curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
#
# 仅支持 Linux（amd64 / arm64），默认安装到 /usr/local/bin/efw。
# 安装前会检查 nft：命令缺失直接中止，root 下还会验证内核 nf_tables；SKIP_NFT_CHECK=1 跳过该预检。
set -eu

REPO="lixiangzhong/efw"
BINDIR="${BINDIR:-/usr/local/bin}"
VERSION="${VERSION:-}"

# GitHub 加速前缀：每次下载都先试官方直连，失败后按顺序改用镜像重试。
MIRRORS="https://gh-proxy.com https://ghfast.top https://ghproxy.net \
	https://gh-proxy.org https://github.cnxiaobai.com https://gh.noki.eu.org"

# 直连被墙时通常卡在 TCP 建连阶段，超时设短一些，尽快切到镜像。
NET_TIMEOUT=6
# 能连上但被限速/阻断时，低于 MIN_SPEED 持续 STALL_SECONDS 秒即放弃当前源。
MIN_SPEED=1024
STALL_SECONDS=20

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
		curl -fsSL --connect-timeout "$NET_TIMEOUT" \
			--speed-limit "$MIN_SPEED" --speed-time "$STALL_SECONDS" "$1"
	else
		wget -q -T "$NET_TIMEOUT" -t 1 -O - "$1"
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout "$NET_TIMEOUT" \
			--speed-limit "$MIN_SPEED" --speed-time "$STALL_SECONDS" -o "$2" "$1"
	else
		wget -q -T "$NET_TIMEOUT" -t 1 -O "$2" "$1"
	fi
}

# 依次尝试官方地址与各镜像前缀，任一成功即返回 0。
#   $1 原始 URL；$2 输出文件（省略则把正文写到 stdout）；$3 正文必须匹配的正则（用于跳过镜像的错误页）
fetch_github() {
	_source_url="$1"
	_out_file="${2-}"
	_must_match="${3-}"
	for _prefix in "" $MIRRORS; do
		_prefix="${_prefix%/}"
		_url="$_source_url"
		if [ -n "$_prefix" ]; then
			_url="$_prefix/$_source_url"
			echo "镜像加速: $_prefix" >&2
		fi
		if [ -n "$_out_file" ]; then
			download "$_url" "$_out_file" || continue
		else
			_body="$(fetch_stdout "$_url")" || continue
			if [ -n "$_must_match" ] && ! printf '%s\n' "$_body" | grep -q "$_must_match"; then
				continue
			fi
			printf '%s\n' "$_body"
		fi
		return 0
	done
	return 1
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

check_nft

# 解析最新版本标签：优先 GitHub API；不可用时退回 releases/latest 页面（镜像上更常见）。
latest_tag() {
	_body="$(fetch_github "https://api.github.com/repos/$REPO/releases/latest" "" '"tag_name"')" || _body=""
	tag="$(printf '%s\n' "$_body" |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	if [ -z "$tag" ]; then
		_body="$(fetch_github "https://github.com/$REPO/releases/latest" "" 'releases/tag/v')" || return 1
		tag="$(printf '%s\n' "$_body" |
			sed -n 's|.*releases/tag/\(v[^"/]*\).*|\1|p' | head -n 1)"
	fi
	[ -n "$tag" ] || return 1
	printf '%s\n' "$tag"
}

if [ -z "$VERSION" ]; then
	tag="$(latest_tag)" || die "无法获取最新版本；请用 VERSION=v1.1.0 指定版本"
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
fetch_github "$url" "$tmp/$asset" ||
	die "下载失败: $url（可改用 VERSION=v1.1.0 指定版本，或检查网络）"

# checksums.txt 与二进制来自同一批源，SHA256 只能拦传输损坏，不能防镜像本身投毒。
if fetch_github "https://github.com/$REPO/releases/download/$tag/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
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
