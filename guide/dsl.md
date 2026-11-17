# efw DSL 参考

[← 返回 README](../README.md) · 部署参数与 apply 见 [部署说明](deploy.md)

语法骨架（文件头指令、动作块、兜底）见 README 的 [DSL 速查](../README.md#dsl-速查)；这里只列字段、简写与动作块细节。

| 字段 | 取值 |
|:--|:--|
| `src` / `dst` | IPv4/IPv6 字面量、CIDR、`*` |
| `private` | 私有源地址集合：IPv4 RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）+ IPv6 ULA（`fc00::/7`）；**仅单独成行**（可加 `log`） |
| `iface` | 入口网卡名（独立规则：`accept { iface eth0 }`；≤15 字符；支持尾缀 `*` 通配，如 `br-*`） |
| `proto` | `tcp`、`udp`、`icmp`（双栈）；`tcp4`/`tcp6`/`udp4`/`udp6`/`icmp4`/`icmp6`（单栈）；省略 = 任意协议 |
| `port` | `80`、`80-90`、`80,443` 或 `{80,443}`（等价）、`*`（省略 = 任意端口） |
| `action` | 由块头决定：`accept`、`drop`、`reject`；块内 `log` 为修饰（log + 块动作），无单独 log |

- IPv6 带端口写成 `[2001:db8::1]:443`，不带端口直接写 `2001:db8::1`。
- 语法里的“端口”一律指**目的端口（dport）**；本语法没有源端口写法，需要时直接改 nft 产物。
- 协议 token 独立，可放在匹配部分任意位置，每规则最多一次；`tcp`/`udp`/`icmp` 为双栈，`*-4`/`*-6` 只匹配对应地址族。
- 旧 `proto://` 写法已移除（会报迁移错误）。

## 简写（与完整写法完全等价，全部写在块内）

```text
accept {
    1.1.1.2                       # 该来源全部流量
    1.1.1.3 -> 8080               # 指定端口
    1.1.1.4 -> {80, 443}          # 端口列表
    1.1.1.5 -> tcp 8443           # 协议 + 端口
    1.1.1.6 -> 8080-8090          # 端口范围
    1.1.1.7 -> 80 443             # 多端口 token（等价 80,443）
    tcp 1.1.1.8 -> 80             # 协议也可以放在任意位置
    tcp4 1.1.1.9 -> 80            # 仅 IPv4 TCP
    tcp6 2001:db8::9 -> 80        # 仅 IPv6 TCP
    iface eth0                    # 该入口网卡上的全部流量（动作由块头决定）
    iface eth1 log                # 同上，并记录日志
    iface br-*                    # 尾缀 * 通配：所有 br-xxxx（Docker 自定义网络）
    iface docker0                 # Docker 默认 bridge 网络
    private                       # 独立一行：私有源地址（RFC1918 + RFC4193 ULA）

    # 源为 * 且没有目的地址时，`* ->` 可省略：
    tcp4 80                       # = * -> tcp4 80（对所有 IPv4 来源）
    tcp4                          # = * -> tcp4（所有 IPv4 来源的 TCP）

    # 带端口的 token 必然是目的地址（本语法无源端口），也能省略 `* ->`：
    10.0.0.1:80                   # = * -> 10.0.0.1:80（任意来源访问该目的）
    tcp [2001:db8::1]:443         # = * -> tcp [2001:db8::1]:443
    1.1.1.1 53                    # = * -> 1.1.1.1 53（地址与端口分写）
    10.0.0.1                      # 不带端口：仍是源地址（仅来自 10.0.0.1）
    80 443                        # 裸端口行（= * -> 80, 443，对所有来源开放）
}
```

纯数字一律视为端口（`-> 2001` 是端口 2001），不做地址猜测；含冒号的串仍是地址。

`iface` 是独立整卡规则：`iface <网卡名> [log]`，匹配该入口网卡上的全部流量，生成 `iifname "<name>"`；input 与 forward 链都生效（forward 侧即该入口网卡上的 DNAT 流量）。它**不能与 src/dst/proto/port 组合**。名称只允许字母/数字/`_.@-`，长度 1-15；允许**尾缀一个 `*`** 表示前缀通配（如 `br-*`、`docker*`，nft 的 `iifname` 通配匹配）；编译时不校验网卡是否存在。`input` 链首默认生成 `iifname "lo" accept`，因此本机访问自身地址不需要在 ACL 里写自己的 IP。

容器来源推荐用接口通配显式信任，而不是放行整个私网段：

```text
accept {
    iface br-*        # Docker 自定义网络（br-<id>）
    iface docker0     # Docker 默认 bridge
}
drop
```

`private` 是**独立源地址规则**：单独占一行（`private` 或 `private log`），匹配 IPv4 RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）与 IPv6 RFC4193 ULA（`fc00::/7`）上的全部流量，动作继承块头。生成 `private4`/`private6` 两个静态 set，并分别展开 `ip saddr @private4` / `ip6 saddr @private6` 两条规则；仅在用到时生成，不参与相邻规则归集。它**不能与目的地址/协议/端口组合**，也不能作为目的地址；需要按端口限制时请写具体网段。

## 动作块（块内省略 action）

```text
accept {
    tcp 1.1.1.1 -> 80
    1.1.1.2 -> 8080
    1.1.1.3 -> 80,443 log      # 块内 log = log + accept
    1.1.1.4                    # 该来源的全部流量
}

drop {
    2.2.2.2 -> 22
}
```

也支持单行块：`accept { tcp 1.1.1.1 -> 80 }`、`drop { * }`。

块内 action 省略并继承块动作，显式写的动作必须与块头一致；规则按块与块内文本顺序展开。
**块外不能写普通规则**（会报 E101）；兜底可写 `drop { * }`，也可简写为 `drop`（支持 `log drop`、`accept`）。

## masquerade（出站源 NAT）

`masquerade` 是独立的顶层块，生成 `postrouting` 链（`type nat hook postrouting priority 90`），按源地址/出接口做源 NAT：

```text
masquerade {
    eth1                      # 所有从 eth1 出的流量
    192.168.1.0/24 -> eth1    # 只 NAT 该源网段
    2001:db8:1::/64 -> eth1    # IPv6 源网段
    private -> eth1           # 私有源地址（RFC1918 + RFC4193 ULA）
    * -> eth1                 # 等价 eth1
}
```

- 一条规则两种形式：`<出接口>`（不限定来源）或 `<源地址> -> <出接口>`；`->` 左侧必须是源地址，右侧必须是出接口。
- 源地址支持 IP/CIDR、`*`、`private`；出接口必须是网卡名（≤15 字符，允许字母/数字/`_.@-`），不能写成地址，也不能使用 DSL 关键字（`accept`/`drop`/`tcp`/`private` 等）。
- `private` 展开为 `ip saddr @private4` / `ip6 saddr @private6` 两条，并复用 `private4`/`private6` 集合（按需生成）。
- 可写多个块、多行；**严格按书写顺序生成，不去重/不重排**——NAT 首条匹配生效，顺序即语义。多条时建议具体源网段在前、整卡/`*` 在后。
- 不支持目的地址、协议、端口、`log`；不支持只写源地址（必须指定出接口）。
- 只在出现 `masquerade` 块时生成 NAT 链；没有该块时产物不变。
- `masquerade` 不替代兜底规则：文件仍需满足「展开后最后一条匹配一切」的要求（如 `drop` / `accept`）。
- `--chain postrouting` 被禁用（与内置链冲突）。
- 需要内核 ≥ 5.2（`inet` 族 NAT）。NAT 只做地址转换，转发流量是否放行由 `ip_forward` 与 FORWARD 策略决定；efw 的 `forward` 链只处理 DNAT 流量。
- 出接口一般填 WAN 口；`compile` 不校验网卡是否存在。可用 `nft -c -f` 或 `efw apply` 在目标机校验。
