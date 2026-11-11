# efw

把一套面向 ACL 的 DSL 编译成**完整、可直接 `nft -f` 加载**的 nftables ruleset。

- 纯离线编译：不做加载、幂等、运行时管理（v1 定位；规格文档 SPEC.md 为本地维护，不纳入版本库）。
- v1 只覆盖入站（`input` hook）；`table inet` 双栈。
- 设计细节、错误码、验收标准见本地 SPEC.md（不纳入版本库），本文只讲怎么用。

## 安装 / 构建

```bash
go build -o efw ./cmd/efw
```

要求 Go 1.27+；**唯一第三方依赖**是 CLI 框架 [urfave/cli v3](https://github.com/urfave/cli)，编译链路保持标准库。

CLI 还内置了 `efw help`（帮助）与 `efw version`（版本，等价 `--version`）。

## 快速开始

`rules.acl`：

```text
# 公司出口白名单
v6-bootstrap off

tcp 1.1.1.0/24 -> 80 accept
tcp 1.1.1.0/24 -> 443 accept
2.2.2.2    -> 8080 accept
icmp       *  accept
3.3.3.3    -> 22 log drop
drop                     # 兜底：以上都不匹配的一律丢弃
```

> 没有 `default` 指令：链 `policy` 恒为 `accept`，**文件最后一条必须是匹配一切的兜底规则**，
> 否则编译报错（E100）。用 `log drop` 兜底可同时记录未命中流量。
> 单独动作行 `drop`、单行块 `drop { * }`、分行块 `drop {\n  *\n}` 三者**完全等价**。

也可以让 ACL 文件自己可执行（shebang）：

```text
#!/usr/local/bin/efw

accept{
    1.1.1.0/24 -> 22
}

drop
```

```bash
chmod +x rules.acl
./rules.acl                  # 内核执行 efw /path/rules.acl（位置参数，不经过 stdin）
./rules.acl --table myt      # 附加编译参数会透传给 efw
```

> 也可以写 `#!/usr/local/bin/efw -f`，或直接 `efw rules.acl`。

编译：

```bash
efw compile rules.acl            # 产物写到 stdout
efw compile -o rules.nft rules.acl
cat rules.acl | efw compile      # 也可从 stdin 读
```

得到的 `rules.nft` 可直接加载：

```bash
nft -c -f rules.nft   # 语法自检（需要 root / NET_ADMIN）
nft -f rules.nft      # 真正生效
```

## DSL 速查

```text
established auto|off               # 默认 auto：链首放行已建立连接
v6-bootstrap auto|off              # 默认 auto：兜底为 drop/reject 时放行 IPv6 NDP/DHCPv6

[proto] src [proto] -> [dst] [port] action   # proto 可出现在匹配部分任意位置
[log] accept|drop|reject           # 兜底规则（必填，必须是最后一条；或块内 `*`）
```

| 字段 | 取值 |
|:--|:--|
| `src` / `dst` | IPv4/IPv6 字面量、CIDR、`*` |
| `proto` | `tcp`、`udp`、`icmp`（双栈）；`tcp4`、`tcp6`、`udp4`、`udp6`、`icmp4`、`icmp6`（单栈）；省略 = 任意协议 |
| `port` | `80`、`80-90`、`80,443` 或 `{80,443}`（等价）、`*`（省略 = 任意端口） |
| `action` | `accept`、`drop`、`reject`，可前缀 `log`；单独 `log` = 只记录 |

IPv6 带端口必须写成 `[2001:db8::1]:443`；不带端口直接写 `2001:db8::1`。

语法里的“端口”一律指**目的端口（dport）**，没有源端口写法；需要源端口时直接改 nft 产物。

协议 token 是独立 token，可出现在匹配部分任意位置，每规则最多一次；
`tcp`/`udp`/`icmp` 表示双栈（同时匹配 IPv4/IPv6），`tcp4`/`tcp6`/`udp4`/`udp6`/`icmp4`/`icmp6` 只匹配对应地址族；
旧 `proto://` 写法已移除（会报迁移错误）。

### 简写（与完整写法完全等价）

```text
1.1.1.2 accept               # 该来源全部流量
1.1.1.3 -> tcp accept        # 指定协议
1.1.1.4 -> 8080 accept       # 指定端口
1.1.1.5 -> {80, 443} accept  # 端口列表
1.1.1.6 -> tcp 8443 accept   # 协议 + 端口
1.1.1.7 -> 80,443 accept     # 裸列表，等价 {80,443}
1.1.1.8 -> 8080-8090 accept  # 端口范围
1.1.1.9 -> 80 443 accept     # 多端口 token（等价 80,443）
tcp 1.1.1.10 -> 80 accept    # 协议也可以放在任意位置
tcp4 1.1.1.11 -> 80 accept   # 仅 IPv4 TCP
tcp6 2001:db8::11 -> 80      # 仅 IPv6 TCP（块内）

# 源为 * 且没有目的地址时，`* ->` 可省略：
tcp4 80 accept               # = * -> tcp4 80（对所有 IPv4 来源）
tcp4                         # 块内：= * -> tcp4（所有 IPv4 来源的 TCP）

# 带端口的 token 必然是目的地址（本语法无源端口），也能省略 `* ->`：
10.0.0.1:80 accept           # = * -> 10.0.0.1:80（任意来源访问该目的）
tcp [2001:db8::1]:443 accept # = * -> tcp [2001:db8::1]:443
1.1.1.1 53 accept            # = * -> 1.1.1.1 53（地址与端口分写）
10.0.0.1 accept              # 不带端口：仍是源地址（仅来自 10.0.0.1）
80 443 accept                # 裸端口行（= * -> 80, 443，对所有来源开放）

accept{
    80 443                   # 块内裸端口行：继承块动作
}
```

纯数字一律视为端口（`-> 2001` 是端口 2001），不做地址猜测；含冒号的串仍是地址。

### 动作块（块内省略 action）

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

drop {
    *                  # 兜底：也可以写在块里
}
```

也支持单行块：`accept { tcp 1.1.1.1 -> 80 }`、`drop { * }`。

块内 action 省略并继承块动作；显式写的动作必须与块头一致。块是纯分组语法，
规则按文本顺序展开，可与普通规则交错。**单独动作行等价于 `action { * }`**，
例如文件末尾的 `drop` 与 `drop { * }` 完全等价。

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

退出码：`0` 成功（可有 warning）/ `1` 编译错误 / `2` 用法错误。错误统一为
`<file>:<line>:<col>: <category>: <code>: <message>`。

## 测试

```bash
go test ./...
```

- 黄金文件在 `testdata/golden/`（`.acl` 输入 + `.nft` 期望产物，逐字节比对）。
- 集成校验：环境里有 `nft` 时自动跑 `nft -c -f`，否则跳过。无 Linux 主机时可用容器：

```bash
# 只需要 CAP_NET_ADMIN；容器内核/Debian 12 镜像里的 nft 1.0.6 与目标环境一致
docker run -d --rm --name test-nft-0 --cap-add=NET_ADMIN debian:12 tail -f /dev/null
docker exec test-nft-0 sh -c 'apt-get update -qq && apt-get install -y -qq nftables'
docker cp testdata/golden/01_basic.nft test-nft-0:/tmp/a.nft
docker exec test-nft-0 nft -c -f /tmp/a.nft

# 或者挂载工作区一次校验全部黄金产物
docker run --rm -v "$PWD":/w -w /w --cap-add=NET_ADMIN debian:12 sh -c '
  apt-get update -qq && apt-get install -y -qq nftables >/dev/null &&
  for f in testdata/golden/*.nft; do nft -c -f "$f" || exit 1; done && echo ALL-OK'
```

## v1 不做

Docker 转发路径、命名集合/别名、`apply` 子命令、规则热更新、SCTP/DCCP —— 详见规格文档 SPEC.md §10（本地维护，不纳入版本库）。
