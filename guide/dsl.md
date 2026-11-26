# efw DSL 参考

[← 返回 README](../README.md) · 部署参数与 apply 见 [部署说明](deploy.md)

语法骨架（文件头指令、动作块、兜底）见 README 的 [DSL 速查](../README.md#dsl-速查)；这里只列字段、简写与动作块细节。

| 字段 | 取值 |
|:--|:--|
| `src` / `dst` | IPv4/IPv6 字面量、CIDR、`*`；`src` 还支持命名集合名 |
| `private` | 私有源地址集合：IPv4 RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）+ IPv6 ULA（`fc00::/7`）；**仅单独成行**（可加 `log`） |
| `iface` | 入口网卡名（动作块内独立规则：`accept { iface eth0 }`；dnat 块内可与其它条件组合；≤15 字符；支持尾缀 `*` 通配，如 `br-*`） |
| `proto` | `tcp`、`udp`、`icmp`（双栈）；`tcp4`/`tcp6`/`udp4`/`udp6`/`icmp4`/`icmp6`（单栈）；省略 = 任意协议 |
| `port` | `80`、`80-90`、`80,443` 或 `{80,443}`（等价）、`*`（省略 = 任意端口） |
| `action` | 由块头决定：`accept`、`drop`、`reject`；块内 `log` 为修饰（log + 块动作），无单独 log |

- IPv6 带端口写成 `[2001:db8::1]:443`，不带端口直接写 `2001:db8::1`。
- 语法里的“端口”一律指**目的端口（dport）**；本语法没有源端口写法，需要时直接改 nft 产物。
- 协议 token 独立，可放在匹配部分任意位置，每规则最多一次；`tcp`/`udp`/`icmp` 为双栈，`*-4`/`*-6` 只匹配对应地址族。
- 旧 `proto://` 写法已移除（会报迁移错误）。

## 文件头 priority 与 output

### priority

`priority <nft 关键字|32 位整数>` 设置 `input` 与 `forward` 两条链的 priority，默认 `-99`：

```text
priority -99          # 默认值，可省略
priority filter       # nft 关键字，产物保持关键字
priority 10           # 32 位整数
```

- 取值只能是 `raw`/`mangle`/`filter`/`security`/`dstnat`/`srcnat`（大小写不敏感，产物统一小写）或 32 位整数；其它值报 E102。
- 与其它文件头指令一样，必须位于所有规则之前；重复出现报 E100。
- 优先级关系：显式 `--priority` > ACL 的 `priority` 指令 > flag 默认值 `-99`。
- `-99` 会排在所有 priority `0` 的 filter 链（firewalld/ufw/容器运行时）之前；efw 有兜底 `drop`，等于由 efw 独占裁决。

### output

`output <绝对路径.nft>` 让 `apply` 成功后把同一份产物写到该文件（`compile` 与 `-c` 不写）：

```text
output /etc/nftables.d/efw.nft
```

- 必须是绝对路径且以 `.nft` 结尾（大小写不敏感），否则报 E102；重复出现报 E100。
- 写入时机是 **apply 成功之后**，文件即「已生效规则」的快照；应用失败不会写文件。
- 自动创建父级目录（0755），文件权限固定 `0644`，同目录临时文件 + rename 原子覆盖。
- 目标已是符号链接时拒绝写入；写失败返回 `E104`（exit 2），错误信息会注明「规则已生效」，避免误判为整体失败。

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

## 命名集合

顶层裸名字块定义一个命名集合，块内每行一个或多个 IP/CIDR（逗号或空白分隔）：

```text
WHITELIST {
    203.0.113.10
    198.51.100.0/25
    2001:db8::1
}

WHITELIST2 { 10.0.0.1 10.0.0.2 }   # 也支持单行
```

- 定义块头写裸名字，**引用必须带 `@`**：`@WHITELIST`、`@WHITELIST -> 80`、`@WHITELIST -> {80,443}`、`drop { @WHITELIST -> 22 }`；漏写 `@` 报「地址不合法（命名集合引用要加 @ 前缀）」，作为目的地址报「只能作为源地址」。
- `@` 只用于引用；`@WHITELIST {` 不是定义语法（定义写 `WHITELIST {`）。`private` 是独立规则关键字，不走 `@`。
- 一个块可混写 v4/v6；nft set 单族，产物拆成 `<Name>_v4` / `<Name>_v6`，引用处按集合实际含有的族展开（单族 1 条，混合 2 条）。规则里钉死族（`tcp4`/`tcp6`、v4/v6 字面量目的地址）时只展开匹配的腿。
- 元素在编译期去重、排序并归并重叠/相邻区间，输出最小 CIDR 列表；因此 `1.1.1.0/25` + `1.1.1.22` 只输出 `/25`，不会触发 nft 的 `conflicting intervals specified`。
- 名称 `[A-Za-z_][A-Za-z0-9_]*`、长度 1-32、区分大小写；DSL/nft 关键字（`set`、`private`、`accept`、`table`…）与内置名（`private4`/`private6`、`input`/`forward`/`postrouting`）是保留字。
- 定义可出现在文件任意位置（引用可前向）；未定义引用、重复定义、空集合、非法元素都报错 E102；未被引用的集合告警 W4 且不产出。
- 只能定义在顶层，不能嵌套在动作块/`masquerade`/其它集合块内；`masquerade` 的源不支持引用集合（用 `private` 或具体网段）。

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

`allow` 是 `accept` 的别名（大小写不敏感）：`allow { ... }`、单行 `allow { ... }`、兜底 `allow` / `log allow`、块内规则尾部的 `allow` 都与 `accept` 完全等价；产物、告警与 nft 输出统一为 `accept`。`allow` 因此不能再用作命名集合名。

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

## dnat（入站目的 NAT）

`dnat` 块生成 `prerouting` 链（`type nat hook prerouting priority dstnat + 1`），用于入站端口重定向与跨机端口转发：

```text
# 端口汇聚：eth0 上进来的 UDP 20000-50000 全部改到本机 443（等价 iptables REDIRECT）
dnat {
    iface eth0 udp 20000-50000 -> 443
}

# 跨机端口转发（等价 iptables DNAT）
dnat {
    iface eth0 tcp 8080 -> 10.0.0.5:8080
    iface eth0 tcp 8443 -> [2001:db8::5]:8443
    iface eth0 tcp 9090 -> 10.0.0.6           # 只改地址，端口保持 9090
}
```

- 条目语法：`<匹配部分> -> <目标>`。`->` 左边是匹配条件（`iface` / 协议 / 源地址 / 目的端口，顺序不限，源地址可省略），右边是 NAT 目标；**dnat 块内 `iface` 可以与其它条件组合**（动作块仍要求 iface 独立成行，见 D45）。
- 与动作块不同，`->` 左侧没有「目的地址」的位置，因此**不支持按原目的地址匹配**；需要按 VIP 原目的转发时，可后续增加 `daddr` 关键字。
- `->` 右侧只写端口 = **本机重定向**（nft `redirect to :port`）；写地址 = **跨机转发**（nft `dnat ip to` / `dnat ip6 to`，inet 表必须显式地址族，产物会自动补 `ip`/`ip6` 或 `meta nfproto`）。
- 目标单端口支持多对一（`udp 20000-50000 -> 443`）；目标写范围时必须与匹配范围**等长**（`udp 5000-5100 -> 6000-6100`）。目标写多个端口/集合、以及不等长范围都报 E102。
- 跨机目标的地址族必须与匹配侧一致：`tcp4`、IPv4 源/目的地址不能转发到 IPv6 目标，反之亦然。
- 源地址不支持命名集合引用（写具体网段或 `*`）；`private` 也不能用。
- **重定向后必须放行目标端口**：`redirect` 把包改成「到本机」，之后走 `input` 链；默认零信任下未放行会被兜底丢弃。编译期检查，找不到对应 `accept` 时给 `W5` 告警。
- 可写多个块、多行；**严格按书写顺序生成，不去重/不重排**——NAT 首条匹配生效。
- `dnat` 不替代兜底规则：文件仍需满足「展开后最后一条匹配一切」的要求（如 `drop` / `accept`）。
- `--chain prerouting` 被禁用（与内置链冲突）；`efw-nft08` 出现 dnat 直接报 E102（0.8 没有 inet 族 NAT）。
- 需要内核 ≥ 5.2。`redirect` 会改写目的地址：服务需要原目的信息时用 `IP_RECVORIGDSTADDR` 取回；透明代理场景应评估 TPROXY 而不是 dnat。
- prerouting 链 priority 是 `dstnat + 1`，排在 iptables/Docker 的 `dstnat`(-100) 之后，不会抢容器已发布端口。
