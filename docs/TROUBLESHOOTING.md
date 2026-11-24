# 排错

本文件记录本次实现过程中实际踩到的坑，以及对应的确认方式。没有实际遇到的不列。

## 构建期

### `BuildError: config requires a GPG signature but no APT_GPG_PRIVATE_KEY was supplied`

设计如此。`config/site.json` 的 `publish.requireGpgSignature` 为 `true` 时，没有密钥就不产出仓库。

本地临时去掉强制（仅用于查看产物结构，不要用于部署）：

```bash
python scripts/build.py dist --allow-unsigned
```

CI 里没有这个开关，缺 secret 一律失败。

### `ValueError: sha256 mismatch for <url>`

上游文件内容与 `config/frida.json` 里 pin 的哈希不符。三种可能：

1. 上游重新发布了同版本号的包（罕见但发生过）
2. 本地缓存是旧的或不完整的
3. `config/frida.json` 里的哈希填错了

确认上游真实哈希：

```bash
gh api repos/frida/frida/releases/tags/<版本> \
  --jq '.assets[] | select(.name|startswith("frida_")) | "\(.name) \(.size) \(.digest)"'
```

缓存问题则删掉 `.cache/upstream/<文件名>` 重新构建。

### `ValueError: size mismatch for <url>`

下载被截断。本项目实测 GitHub 直连大文件会中途断流，`curl` 返回 0 但文件不完整。用 `gh release download` 更稳：

```bash
gh release download 17.24.3 -R frida/frida \
  -p "frida_17.24.3_iphoneos-arm64.deb" -O frida-17243.deb
```

下载后必须核对大小与 SHA256 再放进缓存。

### `ValueError: unsupported compression for control.tar.zst`

上游换了压缩格式。当前只支持 `.xz`，`deb_builder.decompress_member` 需要相应扩展。

### `BuildError: missing built deb: <path>`

`scripts/build.py` 不会自己构建 deb，它只消费 `artifacts/debs/` 里已有的产物。必须先跑 `deb_builder.py`。

### `BuildError: dist size ... exceeds Pages limit`

产物超过 1 GB。当前两个 deb 约 45 MB，除非大规模扩包否则不会触发。真超了要迁到对象存储，Pages 只放索引。

### `ValueError: architecture mismatch for ...: control says X expected Y`

`deb_builder.py` 产出的包架构与 `config/frida.json` 的 `variants[].architecture` 不一致。检查 `transform` 分支是否真的改写了 control，或 `outputName` 是否与变体错配。

### gpg 在 Git Bash 下报 `keyblock resource '...'` 或 `can't connect to the gpg-agent`

Git Bash 自带的是 MSYS 版 gpg，对 `GNUPGHOME` 的 Windows 盘符路径处理有问题。手动调用时用 POSIX 形式：

```bash
export GNUPGHOME='/e/AI/app-security-testing/artifacts/gpgnhom'
```

`gpg_signer.py` 已经自动做这个转换，只有手动敲 gpg 命令时才需要注意。

另一个表现是 `gpg --export-secret-keys` 卡住不返回——缺 `--pinentry-mode loopback --passphrase`，gpg 在等交互输入。

### 重打包结果不确定

`deb_builder.py` 通过固定 tar 条目的 `uid/gid/uname/gname`、沿用原始 `mtime`、固定 `lzma` preset 保证确定性。本机连续两次构建产出完全一致的 SHA256。

如果改动了这几项（比如引入当前时间戳），`sha256` 每次都会变，`catalog.json` 与 `Packages` 会随之抖动。改之前先想清楚。

## 部署期

### Actions 失败：`APT_GPG_PRIVATE_KEY secret is not configured`

仓库 Secrets 没配。见 README 的首次部署步骤。

### Actions 失败：`upstream drift detected`

CI 在上传 Pages 前会重新校验缓存里的上游文件哈希。失败说明下载到的内容与 pin 不符，通常是上游重新发版或下载截断。

### Pages 部署成功但页面 404

Settings → Pages → Source 必须是 **GitHub Actions**。选成 "Deploy from a branch" 时自定义 workflow 的产物不会生效。

### 页面能开但 `catalog.json` 加载失败

`js/app.js` 用相对路径 `fetch("catalog.json")`。Project Pages 的 base path 是 `/<REPOSITORY>/`，只要 `catalog.json` 与 `index.html` 同级就能取到。如果改成绝对路径 `/catalog.json` 会丢 base path 而 404。

### 资源路径丢失 `/<REPOSITORY>/`

所有 URL 必须从 `config/site.json` 的 `baseUrl` 拼出来。当前 `index.html` 模板里的 `css/style.css`、`js/app.js` 都是相对路径，天然适配子路径。新增资源时保持相对路径，或从 `baseUrl` 计算。

## 设备侧

### `apt-get update` 报 `NO_PUBKEY <指纹>`

设备还没信任新公钥。两种方式：

- Sileo / Zebra 添加源时按其提示导入 `public.gpg`
- 手工转换并放置：

```bash
# public.gpg 是 ASCII armored，APT 需要二进制 keyring
gpg --dearmor -o trusted.gpg public.gpg
```

本次实测中，设备上没有可用的 `gpg` 命令，改用 Python 做的转换：

```python
import base64
text = open('public.gpg').read()
body = ''.join(l for l in text.splitlines() if l and not l.startswith('-----'))
open('trusted.gpg','wb').write(base64.b64decode(body))
```

### `apt-get update` 报 `Hash Sum mismatch`

`Release` 里记录的索引哈希与设备上实际下载到的文件不符。常见原因是索引文件没传全——本项目实测时漏传了 `Packages.bz2`，APT 优先取 `.bz2` 于是报哈希不匹配。

确认四个文件都在：

```
dists/stable/main/binary-<arch>/Packages
dists/stable/main/binary-<arch>/Packages.gz
dists/stable/main/binary-<arch>/Packages.bz2
```

### `apt-cache policy` 里看不到包

三种可能：

1. 设备架构与索引里的 `Architecture` 不匹配。用 `dpkg --print-architecture` 确认，roothide 是 `iphoneos-arm64e`
2. `Release` 的 `Architectures` 字段没包含设备架构
3. 索引里 `Packages` 文件为空

本机实测：

```
$ apt-cache policy re.frida.server
re.frida.server:
  Installed: (none)
  Candidate: 17.24.3+roothide1
  Version table:
     17.24.3+roothide1 500
        500 file:/... stable/main iphoneos-arm64e Packages
```

### `apt-get install` 报找不到 `rootless-compat`

`roothide-arm64e` 变体声明了 `Pre-Depends: rootless-compat (>= 0.9)`。这是 roothide 环境的标准依赖，正常 Dopamine roothide 设备自带（本次设备上是 `2.0.1`）。如果设备没有，要么装它，要么把 `preDepends` 改成 `null` 重新构建——但那样装上去可能无法正常工作。

### 装完之后 frida attach 失败

这是本次**没有验证过**的部分。设备上原有的 frida-server 是 RootHide Patcher 处理过的，比本仓库产物多三样东西：

1. entitlements：`com.apple.private.security.no-sandbox`、`storage.AppBundles`、`storage.AppDataContainers`
2. `frida-server.roothidepatch` 与 `frida-agent.dylib.roothidepatch` 符号链接（指向 `/usr/lib/DynamicPatches/AutoPatches.dylib`）
3. RootHide Patcher 重签名

`--version` 与守护进程启动不受影响，但注入沙盒 App 可能需要这三项。若 attach 失败，方向是参照设备上的 `/Applications/Patcher.app/patch.sh` 补齐这三项，而不是改 Mach-O（二进制本身已含 arm64e 切片）。

### SSH 写文件成功但看不到

roothide 下 SFTP 与 SSH 的根目录解析不同：

```
$ readlink -f /var/mobile
/rootfs/private/var/mobile/Containers/Shared/AppGroup/.jbroot-C682FF69B69F3CC7/var/mobile
```

SFTP 会落到 `.jbroot` 容器视图，SSH 命令看到的是另一个视图。**用 SSH 命令读写（`cat > file`），不要用 SFTP 的 `put`**。本项目实测 SFTP `put` 报成功但文件在 SSH 侧不可见。

### 大文件传输中断

用 paramiko 的 `exec_command("cat > file")` 传 23 MB 的 deb 会中途断，且脚本仍返回成功。传输后必须逐个 `wc -c` 校验字节数，已在 `push_tree.py` 里实现。生产环境这个概念不适用——CI 通过 Pages artifact 上传，不走 SSH。

## 已确认的设备环境事实

记录于此避免重复排查：

| 项 | 值 |
|---|---|
| 设备 | iPhone10,4 (iPhone XR) / D201AP / iOS 16.7.11 (20H360) |
| 越狱 | Dopamine roothide |
| dpkg 架构 | `iphoneos-arm64e` |
| `/var/jb` | 符号链接到 `/` |
| 已装 frida | `re.frida.server 17.24.3`，Architecture `iphoneos-arm64e` |
| launchd 任务 | `re.frida.server`，常驻 |
| `/usr/sbin/frida-server` | 18,312,544 字节，fat binary（arm64 + arm64e） |
| `rootless-compat` | 已装 2.0.1 |
| 设备上 gpg | **不存在**（`/usr/bin/gpg` 无） |
| 设备上 dpkg-deb | 1.21.21，支持 zstd |

## 已确认的上游事实

| 项 | 值 |
|---|---|
| `build.frida.re` 发布的架构 | `iphoneos-arm`、`iphoneos-arm64`、`appletvos-arm64` |
| 官方是否发布 arm64e | **否** |
| `frida_17.24.3_iphoneos-arm64.deb` SHA256 | `233a0133b027f41a24c7dddfa6e88bc49cf1f14a5066bc32c2523953f59d9e6d` |
| `frida_17.27.5_iphoneos-arm64.deb` SHA256 | `d83c06ce6907666a84195179595d767c05f22e9bc6577e6ec2e4f4a7b1bf6feb` |
| 包内路径 | `./var/jb/usr/sbin/frida-server`、`./var/jb/usr/lib/frida-1.0/frida-agent.dylib` |
| control 里的 `Size` | 与 ar 成员实际大小不一致（23560192 vs 23556884），故重打包时删除该字段 |