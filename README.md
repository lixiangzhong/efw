# efw

把一套面向 ACL 的 DSL 编译成**完整、可直接 `nft -f` 加载**的 nftables ruleset。

- 默认纯离线编译；`efw apply` 编译后直接原子应用到内核，重复执行即覆盖。
- 覆盖入站（`input`）与 Docker 发布端口（`forward`，仅 DNAT 流量），`table inet` 双栈。
- **只拦截外部来源**：默认放行 loopback/CGNAT/link-local 与 IPv6 ULA/link-local，RFC1918 默认不放；有 Docker 时 `apply` 自动探测并放行其网段。

设计细节、错误码与验收标准见本地 SPEC.md（不纳入版本库），本文只讲怎么用。

## 安装 / 构建

Linux 一键安装（curl 或 wget 均可，默认装到 `/usr/local/bin/efw`）：

```bash
curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
# 或
wget -qO- https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
```

```bash
# 指定版本 / 安装目录
curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | VERSION=v1.0.0 sh
curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | BINDIR="$HOME/.local/bin" sh
```

脚本仅支持 Linux amd64/arm64，会校验 SHA256，安装完成后打印一份示例 ACL。安装前会检查 `nft`：命令缺失直接中止，root 下还会用 `nft list ruleset` 验证内核 nf_tables；`SKIP_NFT_CHECK=1` 可跳过预检。

### 国内网络

`install.sh` 先直连 GitHub，失败后自动按内置前缀列表重试：`gh-proxy.com`、`ghfast.top`、`ghproxy.net`、`gh-proxy.org`、`github.cnxiaobai.com`、`gh.noki.eu.org`。脚本本身也打不开时经镜像获取：

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
```

个别镜像只代理下载、不代理 `api.github.com`，版本探测失败时用 `VERSION=v1.1.0` 指定。SHA256 只能防传输损坏、无法防镜像投毒，介意请安装后与官方 Release 比对。

从源码构建：

```bash
go build -o efw ./cmd/efw
```

要求 Go 1.27+；唯一的第三方依赖是 CLI 框架 [urfave/cli v3](https://github.com/urfave/cli)，编译链路保持标准库。CLI 内置 `efw help` 与 `efw version`（等价 `--version`）。

## 快速开始

`rules.acl`：

```text
# 公司出口白名单
v6-bootstrap off

accept {
    tcp 1.1.1.0/24 -> 80
    tcp 1.1.1.0/24 -> 443
    2.2.2.2         -> 8080
    icmp            *
}

drop {
    3.3.3.3 -> 22 log
}

drop                     # 兜底：以上都不匹配的一律丢弃
```

> 没有 `default` 指令：链 `policy` 恒为 `accept`，**文件最后一条必须是匹配一切的兜底规则**，否则编译报错（E100）。`drop` 可换成 `accept` 或 `log drop`，都等价于 `verdict { * }`。
> 块外只允许文件头指令与兜底简写 `[log] accept|drop|reject`；普通规则必须写在 `accept { ... }` / `drop { ... }` / `reject { ... }` 块内。

也可以让 ACL 文件自己可执行：带 `apply` 参数直接生效，不带则只输出产物。

```text
#!/usr/local/bin/efw apply

accept {
    1.1.1.0/24 -> 22
}

drop
```

```bash
chmod +x rules.acl
./rules.acl                  # 编译 + 校验 + 原子覆盖内核规则（需要 root/CAP_NET_ADMIN）
./rules.acl --table myt      # 附加编译参数会透传给 efw
```

> `apply` 是唯一的 shebang 参数（内核只会再补脚本路径）；重复执行就是覆盖。只编译不应用用 `#!/usr/local/bin/efw`；开机重建把同一文件放进 `/etc/rc.local` 即可。

编译与加载：

```bash
efw compile rules.acl            # 产物写到 stdout
efw compile -o rules.nft rules.acl
cat rules.acl | efw compile      # 也可从 stdin 读

nft -c -f rules.nft   # 语法自检（需要 root / NET_ADMIN）
nft -f rules.nft      # 真正生效
```

## DSL 速查

```text
established auto|off               # 默认 auto：链首放行已建立连接
v6-bootstrap auto|off              # 默认 auto：兜底为 drop/reject 时放行 IPv6 NDP/DHCPv6

accept { <规则> }                  # 块内省略 action，继承块动作
drop { <规则> }                    # 同上（reject 同理）
accept { * } / drop { * }          # 兜底：匹配一切，必须最后一条（可简写为 accept / drop）
# <规则> = [proto] src [proto] -> [dst] [port]    # proto 可出现在匹配部分任意位置
```

| 字段 | 取值 |
|:--|:--|
| `src` / `dst` | IPv4/IPv6 字面量、CIDR、`*` |
| `proto` | `tcp`、`udp`、`icmp`（双栈）；`tcp4`/`tcp6`/`udp4`/`udp6`/`icmp4`/`icmp6`（单栈）；省略 = 任意协议 |
| `port` | `80`、`80-90`、`80,443`（或 `{80,443}`）、`*`；一律指目的端口 |
| `action` | 由块头决定；块内 `log` 是修饰（log + 块动作），无单独 log |

常见简写（完整列表与边界见 [DSL 参考](guide/dsl.md)）：

```text
accept {
    1.1.1.2                  # 该来源全部流量
    1.1.1.4 -> 8080          # 指定端口
    1.1.1.5 -> {80, 443}     # 端口列表
    tcp4 1.1.1.11 -> 80      # 仅 IPv4 TCP
    tcp4 80                  # = * -> tcp4 80（所有 IPv4 来源）
}
```

IPv6 带端口写成 `[2001:db8::1]:443`；纯数字一律视为端口（`-> 2001` 是端口 2001）。

## 安全默认

efw 在 input/forward 两条链的**最前面**自动放行「本机 / 非 RFC1918」来源；**RFC1918 默认不放行**。Docker 存在时 `apply` 自动把其子网加入放行集合（`compile` 不探测环境，保持确定性）。

- 没有 Docker 又需要内网访问，要在 ACL 里显式写内网网段。
- 伪造来源仍可能被放行；`rp_filter=0` 时建议开启反向路径过滤。
- 完整语义、apply 流程与 Docker 发布端口见 [部署说明](guide/deploy.md)。

## 文档

- [DSL 参考](guide/dsl.md)：语法、简写、动作块与边界
- [部署说明](guide/deploy.md)：部署参数、apply、内网来源、Docker forward
- [开发与发布](guide/development.md)：Actions 发布流程、测试、v1 不做
