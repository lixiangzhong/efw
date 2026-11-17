# 部署与运行

[← 返回 README](../README.md) · DSL 语法见 [DSL 参考](dsl.md)

## 部署参数

```bash
efw compile \
  --table efw --chain input --priority filter \
  --log-prefix "efw: " \
  -o /etc/nftables.d/efw.nft rules.acl
```

| 参数 | 默认 | 说明 |
|:--|:--|:--|
| `-f, --file` | — | 显式指定 DSL 文件（等价 `efw <file>` 位置参数） |
| `--table` | `efw` | table 名，不能是 nft 关键字 |
| `--chain` | `input` | chain 名，不能是 nft 关键字；也不能是 `forward` / `postrouting`（与内置链冲突） |
| `--hook` | `input` | v1 仅支持 input |
| `--priority` | `filter` | `raw`/`mangle`/`filter`/`security`/`dstnat`/`srcnat` 或 32 位整数（关键字统一小写） |
| `--log-prefix` | `"efw: "` | 原样输出；非空，不得含引号/反斜杠/控制字符 |
| `--stamp` | 关 | 产物头追加生成时间（会破坏确定性） |
| `--quiet` | 关 | 抑制 warning |

退出码：`0` 成功（可有 warning）/ `1` 编译错误 / `2` 用法错误或 apply 环境失败（nft 缺失、权限不足、nft 执行失败，`E104`）。错误统一为 `<file>:<line>:<col>: <category>: <code>: <message>`。

## 直接应用（apply）

`apply` 在编译成功后调用系统 `nft` 把规则应用到内核，**重复执行等于覆盖**：

```bash
efw apply rules.acl            # 文件
efw apply -f rules.acl         # 等价
cat rules.acl | efw apply      # stdin
```

执行流程：

1. 编译 DSL（告警照常输出到 stderr；编译错误 exit 1，不触碰内核）。
2. `nft -c -f -` 校验生成的完整 ruleset。
3. 探测 `table inet <table>`：已存在则在同一 `nft` 批次内 `delete table` + 新定义（原子替换，失败时旧表不变）；不存在则直接创建。
4. 成功时静默（无状态输出，exit 0）；warning 与失败才写 stderr。

约束与边界：

- 需要 root 或 `CAP_NET_ADMIN`；nft 缺失/权限不足/应用失败 → `E104`，exit 2。
- 只替换自己的 `table inet <table>`，不执行 `flush ruleset`，不碰容器运行时（Docker/Podman）的链；nft 批次是原子的，失败不会留下半套规则。
- apply 不做自动备份——规则源文件就是唯一事实来源；`-o/--output` 只属于 `compile`，`apply` 不接受。
- 与 `/etc/fw.sh` 的差异：efw 默认全局生效（可用独立 `iface <网卡名>` 规则按入口网卡整卡放行/拒绝），也不使用 ipset。
- shebang 用法：`#!/usr/local/bin/efw apply`；`rc.local` 直接调用同一文件即可开机重建。想沿用 `/etc/fw.sh` 的习惯，把 ACL 写到 `/etc/fw.sh`、首行加同一 shebang 并 `chmod +x`，之后照旧「编辑 → 执行」。

## 只拦截外部来源（默认全局，可按网卡限定）

efw 在 input/forward 两条链的**最前面**自动放行「本机 / 非 RFC1918」来源：

```nft
iifname "lo" accept
ip  saddr { 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 } accept
ip6 saddr { ::1, fc00::/7, fe80::/10 } accept
```

- **默认放行 `lo`**：input 链首生成 `iifname "lo" accept`，本机访问自身公网/内网地址不再需要把自身 IP 写进 ACL；forward 链不生成（本机流量不经过 forward）。
- **RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）默认不放行**；需要内网访问时写 `private`（独立一行，私有源地址）或具体网段（例如 DB 客户端连本机 MariaDB）。
- Docker 或 Podman（rootful）存在时，`efw apply` 执行 `network inspect` 读取本机所有容器网络的子网，追加到上述两组集合（IPv4/IPv6）；两者都存在时合并去重。运行时命令缺失则跳过，命令存在但网络不可用会告警并继续。
- `compile` 不做环境探测，保持确定性；只有 `apply` / shebang 执行时才会自动加容器网段。
- forward 侧放行**不带 `ct status dnat`**，所以容器→宿主发布端口（hairpin）也能放行；容器之间的直连本来就不经过这两条规则。
- rootless Podman 没有宿主侧 DNAT（pasta/slirp4netns + 用户态端口转发）：发布端口由宿主进程监听，落在 input 链的端口 ACL 里；容器访问宿主服务的源地址是宿主地址或 loopback，若被拦需在 ACL 显式放行。
- 需要按入口网卡整卡放行/拒绝时，单独写一条 `iface <网卡名>` 规则（生成 `iifname "<网卡名>"`，可加 `log`；不能与源/端口组合）；不写 iface 即不限定，多网卡/网卡改名都不影响。
- 残余风险：伪造来源仍可能被放行；`rp_filter=0` 时建议开启反向路径过滤（`sysctl -w net.ipv4.conf.all.rp_filter=1`）。

## 容器发布端口（forward 链）

Docker/Podman（rootful）的发布端口（`-p 8080:80`）走的是 **DNAT + FORWARD**，流量不会经过 INPUT。efw 默认同时生成两条链；容器网段由 `apply` 探测后在链首自动放行，其余外部来源进入下列过滤。ACL 里的 `-> 8080` 既允许宿主 8080，也允许所有 8080 的发布端口：

| 链 | hook / priority | 匹配语义 |
|:--|:--|:--|
| `input` | `input` / `filter` | 宿主本机端口（dport） |
| `forward` | `forward` / `-10` | 仅 `ct status dnat` 流量；端口按**宿主发布端口**匹配（`ct original proto-dst`），目的地址按 DNAT 前地址匹配（`ct original ip daddr`） |

forward 链产物：

```nft
chain forward {
    type filter hook forward priority -10; policy accept;

    ct state established,related accept

    ct status dnat ip saddr 1.1.1.0/24 meta l4proto { tcp, udp } ct original proto-dst 8080 accept

    ct status dnat drop      # default deny：未命中的发布端口流量丢弃
}
```

说明：

- `default deny` 的兜底在 forward 侧自动变成 `ct status dnat <verdict>`，**只影响 DNAT 转发流量**；容器出站、普通路由转发不受影响（链 policy 仍是 `accept`）。
- 不碰容器运行时自己的链（不使用 `DOCKER-USER`），通过 hook priority 抢在 Docker / Netavark 的 filter 规则（priority 0）之前；`drop` 是终结动作，能覆盖运行时的 accept。
- 不需要声明容器网段或容器 IP，端口直接写宿主发布端口；文件头 `forward off` 可关闭 forward 链，退回纯 input 行为。
- `iface <网卡名>` 是独立整卡规则，在 input/forward 两条链都生效（forward 侧即该入口网卡上的 DNAT 流量）。
- 已知边界：host 网络模式的容器、rootless Docker/Podman（无宿主 DNAT）、以及非容器运行时的 DNAT 端口转发也会落入 `ct status dnat` 的作用范围；容器之间的东西向流量不在其列。
- 容器网段整段视为内部来源：efw 对它的放行不带 `ct status dnat`，但**不会改变运行时的隔离结论**——Docker/Netavark 的转发 drop 仍然生效（实测跨网络容器仍被 Docker 隔离拦截）。

## 出站 NAT（masquerade）

`masquerade` 块生成同一张 `table inet <table>` 里的 `postrouting` nat 链，用于把 LAN/私网流量源 NAT 到出口网卡：

```nft
chain postrouting {
    type nat hook postrouting priority 90; policy accept;
    ip saddr 192.168.1.0/24 oifname "eth1" masquerade
}
```

- 优先级 90 **先于** Docker/Netavark/Tailscale 的 srcnat（100）；NAT 首条匹配生效，显式源网段规则优先生效。不要依赖同优先级（100）的跨表顺序。
- 需要内核 ≥ 5.2（`inet` 族 NAT）。已在 nft 1.0.6 / 1.0.9（kernel 6.1 / 6.8）上用 `nft -c` 实测通过；旧内核会在校验阶段失败。
- 需要 `net.ipv4.ip_forward=1`，且 FORWARD 策略允许转发。efw 的 `forward` 链**只匹配 DNAT 流量**，不会为 LAN→WAN 转发自动放行，也不做非 DNAT 转发过滤；若主机 FORWARD 为 DROP（部分 Docker 默认），需另行放行。
- 裸出接口（`masquerade { eth1 }`）会对所有从该口出的流量做 SNAT，包括 Tailscale/Docker 转发的流量；生产建议用源网段限定。
- 只影响新连接：已有 conntrack 条目保持原 NAT 映射；变更后用新连接验证。
- `--chain postrouting` 被禁用（与内置 NAT 链冲突）；没有 `masquerade` 块时不生成该链。
- 验证时可用独立 `--table efw_nat_test` + netns/veth 做「未 NAT → NAT」A/B，测完 `nft delete table inet efw_nat_test`，不碰生产表与 `/etc/fw.sh`。

## Podman 说明

Podman 与 Docker 的差异集中在网络后端，对 efw 的影响只有子网探测和发布端口的路径：

| 场景 | 行为 |
|:--|:--|
| rootful（默认 netavark，Podman ≥ 4.0） | 与 Docker 等价：`apply` 自动探测 `podman` 默认网络（`10.88.0.0/16`）及自建网络的子网；发布端口在 nat 阶段 DNAT，走 `forward` 链 |
| rootful + CNI（Podman 3.x） | 子网从 CNI 配置 `plugins[].ipam.ranges` 读取，其余同上；Podman 5 起只有 netavark |
| rootless（pasta / slirp4netns） | 没有宿主侧 DNAT，发布端口由用户态转发进程监听，按 `input` 链的端口 ACL 过滤；不需要网段探测。容器访问宿主服务的源地址是宿主地址/loopback，被拦时在 ACL 显式放行 |

- 探测以 root 身份执行，只看到 rootful 网络；rootless 网络在用户自己的配置目录里，不参与探测。
- Podman 的隔离链同样在 filter priority 0，efw 的 `-10` 仍然先决策。
- 与 Docker 相同：默认网络子网（`10.88.0.0/16`、`172.17.0.0/16`）会整段放行。如果宿主的真实内网恰好落在这些网段，需要留意这是「视为内部」而非「仅容器」。
