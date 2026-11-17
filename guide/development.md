# 开发与发布

[← 返回 README](../README.md)

## 发布（GitHub Actions）

`.github/workflows/ci-release.yml`：

- push `main` / pull request：`gofmt`、`go vet`、`go test ./...`
- push 标签 `vX.Y.Z`：测试通过后编译 `linux × amd64/arm64`，生成 `efw_<version>_<os>_<arch>`、`efw-nft08_<version>_<os>_<arch>` 与 `checksums.txt`，自动创建 GitHub Release
- 手动 `workflow_dispatch`：只跑测试

发布一个版本：

```bash
git tag v1.2.3
git push origin v1.2.3
```

版本号通过 ldflags 注入：`-X github.com/lixiangzhong/efw/internal/compiler.Version=<version>`；本地直接 `go build` 的默认版本是 `1.0.0`。

本地构建两个二进制：

```bash
go build -o efw ./cmd/efw                 # 现代 nft（≥1.0）
go build -o efw-nft08 ./cmd/efw-nft08     # nft 0.8 / CentOS 7
```

## 测试

```bash
go test ./...
```

- 黄金文件：`testdata/golden/`（现代方言）与 `testdata/golden-nft08/`（nft 0.8 方言），均为 `.acl` 输入 + `.nft` 期望产物，逐字节比对。
- nft08 黄金文件需要重生成时：`REGEN_GOLDEN=1 go test ./internal/legacy -run TestGoldenNft08`。
- 集成校验：环境里有 `nft` 时自动跑 `nft -c -f`，否则跳过。无 Linux 主机时可用容器（只需 `CAP_NET_ADMIN`；容器内核/Debian 12 镜像里的 nft 1.0.6 与目标环境一致；nft 0.8 方言需在 CentOS 7 等目标环境验证）：

```bash
docker run --rm -v "$PWD":/w -w /w --cap-add=NET_ADMIN debian:12 sh -c '
  apt-get update -qq && apt-get install -y -qq nftables >/dev/null &&
  for f in testdata/golden/*.nft; do nft -c -f "$f" || exit 1; done && echo ALL-OK'
```

含 `masquerade` 的黄金用例会校验 `postrouting` nat 链，需要内核启用 `nf_nat`（Docker 宿主通常已加载）。

## v1 不做

命名集合/别名、规则热更新、SCTP/DCCP、Docker API 动态端口发现 —— 详见规格文档 SPEC.md §10（本地维护，不纳入版本库）。
