# efw

把一套面向 ACL 的 DSL 编译成**完整、可直接 `nft -f` 加载**的 nftables ruleset。

- 默认纯离线编译；`efw apply` 编译后直接原子应用到内核，重复执行即覆盖。
- 覆盖入站（`input`）与容器发布端口（`forward`，仅 DNAT 流量，Docker/Podman）；可选 `masquerade` 出站源 NAT（`postrouting`），按源地址/出接口匹配。`table inet` 双栈。
- **只拦截外部来源**：默认放行 loopback/CGNAT/link-local 与 IPv6 ULA/link-local，RFC1918 默认不放；容器来源用 ACL 的 `iface br-*` / `iface docker0` 显式信任（`apply` 不再探测运行时网段）。`input` 链首默认放行 `lo`；需要整卡放行/拒绝时写独立规则 `iface <网卡名>`。

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
curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | VERSION=v1.4.0 sh
curl -fsSL https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | BINDIR="$HOME/.local/bin" sh
```

脚本仅支持 Linux amd64/arm64，会校验 SHA256，安装完成后打印一份示例 ACL。安装前会检查 `nft`：命令缺失直接中止，root 下还会用 `nft list ruleset` 验证内核 nf_tables；`SKIP_NFT_CHECK=1` 可跳过预检。

### 国内网络

`install.sh` 先直连 GitHub，失败后自动按内置前缀列表重试：`gh-proxy.com`、`ghfast.top`、`ghproxy.net`、`gh-proxy.org`、`github.cnxiaobai.com`、`gh.noki.eu.org`。脚本本身也打不开时经镜像获取：

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
```

个别镜像只代理下载、不代理 `api.github.com`，版本探测失败时用 `VERSION=v1.4.0` 指定。SHA256 只能防传输损坏、无法防镜像投毒，介意请安装后与官方 Release 比对。

从源码构建：

```bash
go build -o efw ./cmd/efw
```

要求 Go 1.27+；唯一的第三方依赖是 CLI 框架 [urfave/cli v3](https://github.com/urfave/cli)，编译链路保持标准库。CLI 内置 `efw help` 与 `efw version`（等价 `--version`）。

### 旧版 nft（<1.0，如 CentOS 7 的 nft 0.8）

`efw` 只面向现代 nft（≥1.0）。CentOS 7 这类 nft 0.8 环境用独立命令 **`efw-nft08`**：同一份 DSL，产物固定为 0.8 方言，不再需要 `--compat`：

```bash
go build -o efw-nft08 ./cmd/efw-nft08      # 或使用 Release 里的 efw-nft08_<version>_linux_amd64

efw-nft08 compile -o rules.nft rules.acl
efw-nft08 apply rules.acl
```

`/etc/fw.sh` 首行相应写成 `#!/usr/local/bin/efw-nft08 apply`。

`efw-nft08` 会把 priority 写成数字、把「省略协议 + 端口」拆成 tcp/udp 两条；**masquerade 不可用**（inet 族 NAT 需内核 ≥5.2），出现时直接报 `E102`。nft 0.8 的 `ct original` 实测可用，Docker 发布端口的 forward 链不受影响；容器来源同样用 `iface br-*` / `iface docker0` 显式放行。

## 快速开始

`rules.acl`：

```text
# 公司出口白名单
v6-bootstrap off

accept {
    tcp 1.1.4.0/24 -> 80
    tcp 1.1.4.0/24 -> 443
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
    1.1.4.0/24 -> 22
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
iface <name|prefix*> [log]         # 整卡规则：该入口网卡上的全部流量（动作继承块头；支持尾缀 *）
private                            # 独立一行：私有源地址（RFC1918 + RFC4193 ULA）
masquerade { <出接口> | <源地址> -> <出接口> }   # 出站源 NAT（内核 ≥5.2）
# <规则> = [proto] src [proto] -> [dst] [port]    # proto 可出现在匹配部分任意位置
```

| 字段 | 取值 |
|:--|:--|
| `src` / `dst` | IPv4/IPv6 字面量、CIDR、`*` |
| `private` | 私有源地址集合：IPv4 RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）+ IPv6 ULA（`fc00::/7`）；**只能单独成行**（可加 `log`） |
| `iface` | 入口网卡名（`eth0`、`ens3`；独立成规则 `iface eth0`，≤15 字符；支持尾缀 `*` 通配，如 `iface br-*`、`iface docker*`） |
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
    iface eth0               # 仅从 eth0 进入的全部流量
    iface br-*               # 仅从 Docker 网桥（br-xxxx）进入的全部流量
    iface docker0            # Docker 默认 bridge 网络
    tcp4 80                  # = * -> tcp4 80（所有 IPv4 来源）
}
```

IPv6 带端口写成 `[2001:db8::1]:443`；纯数字一律视为端口（`-> 2001` 是端口 2001）。

出站源 NAT 用独立的 `masquerade` 块（生成 `postrouting` 链，priority 90）：

```text
masquerade {
    eth1                      # 所有从 eth1 出的流量
    192.168.1.0/24 -> eth1    # 只 NAT 该源网段
    private -> eth1           # 私有源地址（RFC1918 + ULA）
}
```

NAT 只做地址转换，不负责放行转发流量：需要 `ip_forward=1` 且 FORWARD 策略允许。出接口必须是网卡名；`private` 可作源地址。详见 [DSL 参考](guide/dsl.md)。

## 容器访问宿主机（按需放行）

efw **不默认信任容器**，也不探测 Docker/Podman 网段；容器访问宿主（含访问宿主发布端口）需要在 ACL 里按**入口网桥**显式放行。

Docker：

```text
accept {
    iface br-*      # 自定义网络（br-<id>）；新建网络、换地址池都覆盖
    iface docker0   # 默认 bridge 网络
}
drop
```

Podman：

```text
accept {
    iface podman0       # rootful netavark 默认网络（实测）
    iface cni-podman0   # rootful CNI（Podman 3.x）
    iface podman*       # 自建网络前缀（按实际网桥名调整）
}
drop
```

- 网桥名以 `ip -br link` 为准，只写机器上真实存在的网桥。
- `iface` 匹配该网桥上的**全部**流量（不是按端口），且不能与源/端口组合。
- forward 侧会自动生成 `ct status dnat iifname "<网桥>"`，容器访问宿主发布端口的 hairpin 也覆盖。
- rootless Podman（pasta/slirp4netns）没有宿主侧网桥/DNAT，容器访问宿主时源地址是宿主/loopback，一般不需要 `iface` 规则；被拦时按具体地址/端口放行。
- 只想放行部分容器时不能用 `iface`（整桥生效），需按容器源地址/网段写规则，并自行维护地址变化。

## 安全默认

efw 在 input/forward 两条链的**最前面**自动放行「本机 / 非 RFC1918」来源；**RFC1918 默认不放行**。容器来源**不自动放行**，需要按入口网桥写 `iface br-*` / `iface docker0`（见上节）；`compile` 与 `apply` 都不探测运行时环境。

- 需要内网访问时写 `private`（独立一行，表示私有源地址）或具体网段。
- `input` 链首默认放行 `lo`：本机访问自身公网/内网地址不受 ACL 影响；如需整卡放行/拒绝，用独立规则 `iface <网卡名>`（支持尾缀 `*`，不能与源/端口组合）。
- `masquerade` 只做源 NAT，不改变 FORWARD 过滤：转发是否放行取决于 `ip_forward` 与主机 FORWARD 策略（efw 的 `forward` 链只处理 DNAT 流量）。
- 伪造来源仍可能被放行；`rp_filter=0` 时建议开启反向路径过滤。
- 完整语义、apply 流程与容器发布端口见 [部署说明](guide/deploy.md)。

## 文档

- [DSL 参考](guide/dsl.md)：语法、简写、动作块与边界
- [部署说明](guide/deploy.md)：部署参数、apply、内网来源、容器 forward
- [开发与发布](guide/development.md)：Actions 发布流程、测试、v1 不做
