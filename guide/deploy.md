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
| `--chain` | `input` | chain 名，不能是 nft 关键字 |
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
- 只替换自己的 `table inet <table>`，不执行 `flush ruleset`，不碰 Docker 的链；nft 批次是原子的，失败不会留下半套规则。
- apply 不做自动备份——规则源文件就是唯一事实来源；`-o/--output` 只属于 `compile`，`apply` 不接受。
- 与 `/etc/fw.sh` 的差异：efw 规则不按网卡限定（全局生效），也不使用 ipset。
- shebang 用法：`#!/usr/local/bin/efw apply`；`rc.local` 直接调用同一文件即可开机重建。想沿用 `/etc/fw.sh` 的习惯，把 ACL 写到 `/etc/fw.sh`、首行加同一 shebang 并 `chmod +x`，之后照旧「编辑 → 执行」。

## 只拦截外部来源（无需指定网卡）

efw 在 input/forward 两条链的**最前面**自动放行「本机 / 非 RFC1918」来源：

```nft
ip  saddr { 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 } accept
ip6 saddr { ::1, fc00::/7, fe80::/10 } accept
```

- **RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）默认不放行**；需要内网访问时在 ACL 里显式写对应网段（例如 DB 客户端连本机 MariaDB）。
- Docker 存在时，`efw apply` 执行 `docker network inspect`，把本机所有 Docker 网络的子网追加到上述两组集合（IPv4/IPv6）；没有 docker 命令则不加，docker 存在但 daemon 不可用会告警并继续。
- `compile` 不做环境探测，保持确定性；只有 `apply` / shebang 执行时才会自动加 Docker 网段。
- forward 侧放行**不带 `ct status dnat`**，所以 Docker 容器→宿主发布端口（hairpin）也能放行；容器之间的直连本来就不经过这两条规则。
- 不需要 `iface` 指令：不绑定网卡，多网卡/网卡改名都不影响。
- 残余风险：伪造来源仍可能被放行；`rp_filter=0` 时建议开启反向路径过滤（`sysctl -w net.ipv4.conf.all.rp_filter=1`）。

## Docker 发布端口（forward 链）

Docker 的发布端口（`-p 8080:80`）走的是 **DNAT + FORWARD**，流量不会经过 INPUT。efw 默认同时生成两条链；Docker 网段由 `apply` 探测后在链首自动放行，其余外部来源进入下列过滤。ACL 里的 `-> 8080` 既允许宿主 8080，也允许所有 8080 的发布端口：

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
- 不碰 Docker 自己的链（不使用 `DOCKER-USER`），通过 hook priority 抢在 Docker 的 filter 规则之前；`drop` 是终结动作，能覆盖 Docker 的 accept。
- 不需要声明 Docker 网段或容器 IP，端口直接写宿主发布端口；文件头 `forward off` 可关闭 forward 链，退回纯 input 行为。
- 已知边界：host 网络模式的容器、rootless Docker（无 DNAT）、以及非 Docker 的 DNAT 端口转发也会落入 `ct status dnat` 的作用范围；容器之间的东西向流量不在其列。
