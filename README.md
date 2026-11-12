# efw

把一套面向 ACL 的 DSL 编译成**完整、可直接 `nft -f` 加载**的 nftables ruleset。

- 默认纯离线编译；`efw apply` 可编译后直接原子应用到内核（重复执行即覆盖）。
- 覆盖入站（`input`）与 Docker 发布端口（`forward`，仅 DNAT 转发流量）；`table inet` 双栈。
- **只拦截外部来源**：默认仅放行 loopback/CGNAT/link-local 与 IPv6 ULA/link-local；**RFC1918 默认不放**。Docker 存在时 `apply` 自动探测并放行其网段。
- 设计细节、错误码、验收标准见本地 SPEC.md（不纳入版本库），本文只讲怎么用。

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

脚本仅支持 Linux amd64/arm64，会校验 SHA256，安装完成后打印一份示例 ACL。

### 国内网络

`install.sh` 的所有 GitHub 请求（最新版本探测、二进制、`checksums.txt`）都是**先直连、失败后自动改用镜像加速**，
内置镜像前缀按顺序尝试：`https://gh-proxy.com` → `https://ghfast.top` → `https://ghproxy.net`
→ `https://gh-proxy.org` → `https://github.cnxiaobai.com` → `https://gh.noki.eu.org`。

个别镜像（如 `ghfast.top`）只代理下载、不代理 `api.github.com`；若最新版本探测失败，用 `VERSION=v1.1.0` 指定版本即可。

如果连 `raw.githubusercontent.com` 都打不开，脚本本身也要先经镜像获取：

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/lixiangzhong/efw/main/install.sh | sh
# 或经 jsDelivr（只镜像仓库文件，不代理 Release 资产）
curl -fsSL https://cdn.jsdelivr.net/gh/lixiangzhong/efw@main/install.sh | sh
```

镜像前缀按「前缀 + 原始 GitHub URL」拼接，如需更换/增删，直接改脚本顶部的 `MIRRORS` 列表即可。

> 注意：镜像同时提供二进制与 `checksums.txt`，SHA256 只能发现传输损坏，无法防镜像本身投毒。
> 对第三方镜像不放心时请安装后与官方 Release 的校验和自行比对。

从源码构建：

```bash
go build -o efw ./cmd/efw
```

要求 Go 1.27+；**唯一第三方依赖**是 CLI 框架 [urfave/cli v3](https://github.com/urfave/cli)，编译链路保持标准库。

CLI 还内置了 `efw help`（帮助）与 `efw version`（版本，等价 `--version`）。

## 快速开始

`rules.acl`：

```text
# 公司出口白名单：块外只允许文件头指令与兜底简写
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

drop                     # 兜底简写 ≡ drop { * }：以上都不匹配的一律丢弃
```

> 没有 `default` 指令：链 `policy` 恒为 `accept`，**文件最后一条必须是匹配一切的兜底规则**，
> 否则编译报错（E100）。`drop` 可换成 `accept`（整体放行）或写成 `log drop`；它们都等价于 `verdict { * }`。
> **语法 v2：块外普通规则与单独 log 已移除**；普通规则必须写在
> `accept { ... }` / `drop { ... }` / `reject { ... }` 块内。块外只允许文件头指令，以及
> 兜底简写 `[log] accept|drop|reject`（等价 `verdict { * }`）。

也可以让 ACL 文件自己可执行：需要**直接生效**就带 `apply` 参数，只想要产物就保持默认。

```text
#!/usr/local/bin/efw apply

accept{
    1.1.1.0/24 -> 22
}

drop
```

```bash
chmod +x rules.acl
./rules.acl                  # 编译 + 校验 + 原子覆盖内核规则（需要 root/CAP_NET_ADMIN）
./rules.acl --table myt      # 附加编译参数会透传给 efw
```

> `apply` 是唯一的 shebang 参数（内核只会再补脚本路径）；重复执行就是覆盖。
> 只编译不应用：`#!/usr/local/bin/efw`（产物到 stdout）。开机重建可放 `/etc/rc.local`：
>
> ```bash
> /etc/fw.acl
> ```

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

accept { <规则> }                  # 块内省略 action，继承块动作
drop { <规则> }                    # 同上（reject 同理）
accept { * } / drop { * }          # 兜底：匹配一切，必须最后一条（可简写为 accept / drop）
# <规则> = [proto] src [proto] -> [dst] [port]    # proto 可出现在匹配部分任意位置
```

| 字段 | 取值 |
|:--|:--|
| `src` / `dst` | IPv4/IPv6 字面量、CIDR、`*` |
| `proto` | `tcp`、`udp`、`icmp`（双栈）；`tcp4`、`tcp6`、`udp4`、`udp6`、`icmp4`、`icmp6`（单栈）；省略 = 任意协议 |
| `port` | `80`、`80-90`、`80,443` 或 `{80,443}`（等价）、`*`（省略 = 任意端口） |
| `action` | 由块头决定：`accept`、`drop`、`reject`；块内 `log` 为修饰（log + 块动作），无单独 log |

IPv6 带端口必须写成 `[2001:db8::1]:443`；不带端口直接写 `2001:db8::1`。

语法里的“端口”一律指**目的端口（dport）**，没有源端口写法；需要源端口时直接改 nft 产物。

协议 token 是独立 token，可出现在匹配部分任意位置，每规则最多一次；
`tcp`/`udp`/`icmp` 表示双栈（同时匹配 IPv4/IPv6），`tcp4`/`tcp6`/`udp4`/`udp6`/`icmp4`/`icmp6` 只匹配对应地址族；
旧 `proto://` 写法已移除（会报迁移错误）。

### 简写（与完整写法完全等价，全部写在块内）

```text
accept {
    1.1.1.2                       # 该来源全部流量
    1.1.1.3 -> tcp                # 指定协议
    1.1.1.4 -> 8080               # 指定端口
    1.1.1.5 -> {80, 443}          # 端口列表
    1.1.1.6 -> tcp 8443           # 协议 + 端口
    1.1.1.7 -> 80,443             # 裸列表，等价 {80,443}
    1.1.1.8 -> 8080-8090          # 端口范围
    1.1.1.9 -> 80 443             # 多端口 token（等价 80,443）
    tcp 1.1.1.10 -> 80            # 协议也可以放在任意位置
    tcp4 1.1.1.11 -> 80           # 仅 IPv4 TCP
    tcp6 2001:db8::11 -> 80       # 仅 IPv6 TCP

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

块内 action 省略并继承块动作；显式写的动作必须与块头一致。规则按块与块内文本顺序展开；
**块外不能写普通规则**（会报 E101）；兜底可写 `drop { * }`，也可简写为 `drop`（支持 `log drop`、`accept`）。

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

退出码：`0` 成功（可有 warning）/ `1` 编译错误 / `2` 用法错误或 apply 环境失败（nft 缺失、权限不足、nft 执行失败，`E104`）。错误统一为
`<file>:<line>:<col>: <category>: <code>: <message>`。

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
3. 探测 `table inet <table>`：
   - 已存在：同一 `nft` 批次内 `delete table` + 新定义（原子替换，失败时旧表不变）；
   - 不存在：直接创建。
4. 成功时静默（无状态输出，exit 0）；warning 与失败才写 stderr。

约束与边界：

- 需要 root 或 `CAP_NET_ADMIN`；nft 缺失/权限不足/应用失败 → `E104`，exit 2。
- 只替换自己的 `table inet <table>`，不执行 `flush ruleset`，不碰 Docker 的链。
- nft 批次是原子的，失败不会留下半套规则；但 apply 不做自动备份——规则源文件就是唯一事实来源。
- `-o/--output` 只属于 `compile`，`apply` 不接受。
- 与 `/etc/fw.sh` 的差异：efw 规则不按网卡限定（全局生效），也不使用 ipset。
- shebang 用法：`#!/usr/local/bin/efw apply`；`rc.local` 直接调用同一文件即可开机重建。
- 想保持 `/etc/fw.sh` 的使用习惯：把 ACL 内容写到 `/etc/fw.sh`，首行加 `#!/usr/local/bin/efw apply`、`chmod +x`，之后照旧「编辑 → 执行 `/etc/fw.sh`」即可。

## 只拦截外部来源（无需指定网卡）

efw 在 input/forward 两条链的**最前面**自动放行「本机 / 非 RFC1918」来源：

```nft
ip  saddr { 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 } accept
ip6 saddr { ::1, fc00::/7, fe80::/10 } accept
```

- **RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）默认不放行**。
- Docker 存在时，`efw apply` 会执行 `docker network inspect`，把本机所有 Docker 网络的子网追加到上面两组集合（IPv4/IPv6）；没有 docker 命令则不加；docker 存在但 daemon 不可用会告警并继续。
- `compile` 不做环境探测，保持确定性；只有 `apply` / shebang 执行时才会自动加 Docker 网段。
- forward 侧放行**不带 `ct status dnat`**，所以 Docker 容器→宿主发布端口（hairpin）也能放行；容器之间的直连本来就不经过这两条规则。
- 不需要 `iface` 指令：不绑定网卡，多网卡/网卡改名都不影响。
- 如果机器没有 Docker 但需要内网访问（例如 DB 客户端连本机 MariaDB），要在 `/etc/fw.sh` 里显式写对应内网网段。
- 残余风险：伪造来源仍可能被放行；`rp_filter=0` 时建议开启反向路径过滤（`sysctl -w net.ipv4.conf.all.rp_filter=1`）进一步收紧。

## Docker 发布端口（forward 链）

Docker 的发布端口（`-p 8080:80`）走的是 **DNAT + FORWARD**，流量不会经过 INPUT。
efw 默认同时生成两条链；Docker 网段由 `apply` 探测后在链首自动放行，其余外部来源进入下列过滤：

| 链 | hook / priority | 匹配语义 |
|:--|:--|:--|
| `input` | `input` / `filter` | 宿主本机端口（dport） |
| `forward` | `forward` / `-10` | 仅 `ct status dnat` 流量；端口按 **宿主发布端口** 匹配（`ct original proto-dst`），目的地址按 DNAT 前地址匹配（`ct original ip daddr`） |

```text
v6-bootstrap off

accept{
  1.1.1.0/24 -> 8080      # 既允许宿主 8080，也允许所有 8080 的发布端口
}

drop { * }
```

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
- 不需要声明 Docker 网段或容器 IP，端口直接写宿主发布端口。
- 文件头 `forward off` 可关闭 forward 链，退回纯 input 行为。
- 已知边界：host 网络模式的容器、rootless Docker（无 DNAT）、以及非 Docker 的 DNAT 端口转发也会落入 `ct status dnat` 的作用范围；容器之间的东西向流量不在其列。

## 发布（GitHub Actions）

`.github/workflows/ci-release.yml`：

- push `main` / pull request：`gofmt`、`go vet`、`go test ./...`
- push 标签 `vX.Y.Z`：测试通过后编译 `linux × amd64/arm64`，生成
  `efw_<version>_<os>_<arch>` 与 `checksums.txt`，自动创建 GitHub Release
- 手动 `workflow_dispatch`：只跑测试

发布一个版本：

```bash
git tag v1.2.3
git push origin v1.2.3
```

版本号通过 ldflags 注入：`-X github.com/lixiangzhong/efw/internal/compiler.Version=<version>`；
本地直接 `go build` 的默认版本是 `1.0.0`。

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

命名集合/别名、规则热更新、SCTP/DCCP、Docker API 动态端口发现 —— 详见规格文档 SPEC.md §10（本地维护，不纳入版本库）。
