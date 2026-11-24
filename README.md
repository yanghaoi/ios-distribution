# ios-distribution

自托管的 iOS 越狱插件分发仓库。GitHub Pages 托管静态门户与 APT 仓库，GitHub Actions 负责构建与部署，本地不运行常驻服务。

当前的第一个插件是 **frida-server**。

## 为什么自建

上游 `build.frida.re`（frida 官方 APT 源）只发布三个架构：

```
Package: re.frida.server   Architecture: iphoneos-arm
Package: re.frida.server   Architecture: iphoneos-arm64
Package: re.frida.server   Architecture: appletvos-arm64
```

本机测试设备是 iPhone XR / iOS 16.7.11 / Dopamine **roothide**，`dpkg --print-architecture` 返回 `iphoneos-arm64e`。roothide 的 APT 只接受 `iphoneos-arm64e` 的包，因此**官方源在这台设备上永远装不上 frida-server**。

自建源的作用：

1. 把上游 `iphoneos-arm64` 包转换成 roothide 可安装的形式
2. 把上游版本号、包大小、SHA256 **写死在配置里**，上游改动或下架会在构建期直接失败，而不是在生产环境静默漂移
3. 保留完整可复现的构建脚本，任何人重跑都能得到字节一致的产物

## 上游如何被抓取和校验

`config/frida.json` 是唯一的版本锚点：

```json
{
  "upstream": {
    "version": "17.24.3",
    "assets": {
      "arm64": {
        "name": "frida_17.24.3_iphoneos-arm64.deb",
        "size": 23504004,
        "sha256": "233a0133b027f41a24c7dddfa6e88bc49cf1f14a5066bc32c2523953f59d9e6d"
      }
    }
  }
}
```

`scripts/deb_builder.py` 下载后先比对 size 与 SHA256，不符即抛出 `ValueError` 终止构建。这个哈希与 GitHub Release API 返回的 `digest` 字段一致。

## 两个变体

| 变体 | Architecture | 处理 | 适用 |
|---|---|---|---|
| `roothide-arm64e` | `iphoneos-arm64e` | `/var/jb` 路径扁平化、改写架构、补 `Pre-Depends: rootless-compat (>= 0.9)` | roothide（Dopamine roothide） |
| `rootless-arm64` | `iphoneos-arm64` | 原样发布，不改一个字节 | 标准 Dopamine rootless |

`rootless-arm64` 变体与上游字节完全相同，用途是验证流水线本身不引入意外改动。

### 二进制不需要改 Mach-O

上游 `frida-server` 与 `frida-agent.dylib` 本身是 fat binary，包含两个切片：

```
slice 0: cputype 0x100000c  subtype 0x0          (arm64)
slice 1: cputype 0x100000c  subtype 0x80000002   (arm64e)
```

所以 `arm64e` 切片已经在包里，只需让 APT 认为这个包适用于 `iphoneos-arm64e`。实测把官方未打补丁的二进制推到设备直接执行，`--version` 正常输出。

### 必须补 roothide 三件套（2026-11-24 实机验证）

**这是实装后发现的强制项，不是可选项。** 只重打包、不加下面三项，沙盒 App 注入会全部失败：

```
NotSupportedError: unexpected error while probing dyld of target process
```

三件套：

1. **entitlements**：`/Applications/Patcher.app/roothide.entitlements`，含
   `com.apple.private.security.no-sandbox`、
   `com.apple.private.security.storage.AppBundles`、
   `com.apple.private.security.storage.AppDataContainers`、
   `platform-application`
2. **符号链接**：`/usr/sbin/frida-server.roothidepatch` 与
   `/usr/lib/frida-1.0/frida-agent.dylib.roothidepatch`，均指向
   `/usr/lib/DynamicPatches/AutoPatches.dylib`
3. **重签名**：`ldid -M -S<entitlements> frida-server`、`ldid -S frida-agent.dylib`

补齐命令（设备上以 root 执行）：

```bash
ldid -M -S/Applications/Patcher.app/roothide.entitlements /usr/sbin/frida-server
ldid -S /usr/lib/frida-1.0/frida-agent.dylib
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/sbin/frida-server.roothidepatch
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/lib/frida-1.0/frida-agent.dylib.roothidepatch
launchctl unload /Library/LaunchDaemons/re.frida.server.plist
launchctl load /Library/LaunchDaemons/re.frida.server.plist
```

**顺序很重要**：符号链接必须在 App 启动前存在。AutoPatches 只在进程启动时注入，对已运行的进程补链接无效——必须先杀掉目标 App 再重新启动，或直接 spawn。

验证结论（详见 `docs/VERIFICATION-20261124.md`）：

| 测试 | 未补三件套 | 补三件套后 |
|---|---|---|
| `--version` | 正常 | 正常 |
| 枚举进程 / 应用 | 正常 | 正常 |
| attach 系统进程（SpringBoard） | 正常 | 正常 |
| attach 沙盒 App | **失败** | spawn 新进程成功 |
| spawn + Interceptor Hook | 未测 | **成功**（getpid 返回值被改写为 4242） |

### 三件套已自动化（`transform: "roothide-full"`）

`deb_builder.py` 会在 control.tar 里注入一个 `postinst`，安装时自动完成全部补齐：

```bash
# postinst 实际执行的步骤
ldid -M -S<内置的 roothide entitlements> /usr/sbin/frida-server
ldid -S /usr/lib/frida-1.0/frida-agent.dylib
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/sbin/frida-server.roothidepatch
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/lib/frida-1.0/frida-agent.dylib.roothidepatch
launchctl unload /Library/LaunchDaemons/re.frida.server.plist
launchctl load  /Library/LaunchDaemons/re.frida.server.plist
```

entitlements 内容内置在 `deb_builder.ROOTHIDE_ENTITLEMENTS`，不依赖设备上 Patcher.app 的存在。`ldid` 缺失时只告警不中断（`echo ... >&2` 后继续），符号链接在 `AutoPatches.dylib` 不存在时跳过。

**实机验证（2026-11-24）**：手动清空 entitlements 与符号链接后，`dpkg -i` 一次即自动恢复全部三项，launchd 新 PID 6737，随后 spawn `ChargeLimiter` 并 Hook `getpid` 成功（返回值被改写为 4242）。详见 `docs/VERIFICATION-20261124.md`。

### 顺序约束（无法自动化解决）

`AutoPatches.dylib` 只在**进程启动时**注入。因此：

- 安装/升级后，**已运行的**沙盒 App 仍然无法 attach，必须杀掉重启或直接 spawn
- `postinst` 已在末尾重启 frida 守护进程，但不会也不应重启用户的 App

### 手工补救（若 postinst 未生效）

```bash
ldid -M -S/Applications/Patcher.app/roothide.entitlements /usr/sbin/frida-server
ldid -S /usr/lib/frida-1.0/frida-agent.dylib
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/sbin/frida-server.roothidepatch
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/lib/frida-1.0/frida-agent.dylib.roothidepatch
launchctl unload /Library/LaunchDaemons/re.frida.server.plist
launchctl load /Library/LaunchDaemons/re.frida.server.plist
```

### 已知差异

设备上原始安装（RootHide Patcher 处理过）与本仓库产出的差异：

| 项 | RootHide Patcher 原始安装 | 本仓库产物（补齐后） |
|---|---|---|
| entitlements | 含 3 项 roothide 专用 | **已补齐，一致** |
| `*.roothidepatch` 符号链接 | 有 | **已重建，一致** |
| 重签名 | RootHide Patcher 重签 | **已用 ldid 重签，一致** |

补齐后实测注入与 Hook 均正常。见下方「必须补 roothide 三件套」。补充说明：dpkg 覆盖安装会**删除旧的 `.roothidepatch` 符号链接**（因为新包不包含它们），所以每次重装后都要重做补齐步骤。

## 本机跑通构建

无需第三方依赖，只用 Python 标准库。

```bash
cd platforms/ios/tools/ios-distribution

# 1. 把上游 deb 放进缓存（首次需要，之后可复用）
mkdir -p .cache/upstream
# 手动下载 frida_17.24.3_iphoneos-arm64.deb 放到该目录，SHA256 必须是
# 233a0133b027f41a24c7dddfa6e88bc49cf1f14a5066bc32c2523953f59d9e6d

# 2. 生成两个 deb 变体
python scripts/deb_builder.py . .cache/upstream artifacts/debs

# 3. 构建站点（需要签名密钥，否则按设计失败）
export APT_GPG_PRIVATE_KEY="$(cat /path/to/private-key.asc)"
export APT_GPG_PASSPHRASE="your-passphrase"
python scripts/build.py dist

# 4. 单元测试
python -m unittest discover -s tests -v
```

产物在 `dist/site/`：

```
dist/site/
├── index.html
├── catalog.json
├── css/ js/ assets/
└── apt/
    ├── dists/stable/
    │   ├── Release  Release.gpg  InRelease
    │   └── main/binary-iphoneos-arm64{,-64e}/{Packages,Packages.gz,Packages.bz2}
    ├── pool/main/r/re.frida.server/*.deb
    └── public.gpg
```

## APT 签名是强制项

`config/site.json` 的 `publish.requireGpgSignature` 为 `true`。没有提供 `APT_GPG_PRIVATE_KEY` 时构建**直接失败**，不会退化成未签名仓库：

```
BuildError: config requires a GPG signature but no APT_GPG_PRIVATE_KEY was supplied;
refusing to produce an unsigned repository
```

CI 里同样是失败关闭——`deploy-pages.yml` 检测到 secret 为空即退出非零。

## 在设备上添加源

在 Sileo 或 Zebra 中添加：

```
https://yanghaoi.github.io/ios-distribution/apt/
```

distribution `stable`，component `main`。公钥地址：

```
https://yanghaoi.github.io/ios-distribution/apt/public.gpg
```

## 首次部署到 GitHub

1. 在 GitHub 创建公开仓库 `ios-distribution`（免费账号的 Pages 需要公开仓库）
2. 生成 APT 专用 GPG 密钥（**只用于签 APT 索引，不要复用其他用途**）：

```bash
export GNUPGHOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '你的口令' \
    --quick-generate-key "你的名字 APT Signing <you@example.com>" rsa3072 sign 2y
gpg --batch --pinentry-mode loopback --passphrase '你的口令' \
    --armor --export-secret-keys > apt-private.asc
```

3. 在仓库 Settings → Secrets and variables → Actions 添加：
   - `APT_GPG_PRIVATE_KEY`：`apt-private.asc` 全文
   - `APT_GPG_PASSPHRASE`：上面设置的口令
4. 按 `docs/PUBLISHING.md` 把本地验证通过的产物推到仓库
5. Settings → Pages → Source 选 **GitHub Actions**
6. 手动运行一次 `Deploy Pages`，或推送到 `main` 触发
7. 打开 `https://yanghaoi.github.io/ios-distribution/` 验证门户
8. 设备上添加 APT 源，确认 `re.frida.server` 可被索引、可下载

## 启动参数与版本管理

frida-server 的 `--listen`、`--token`、`--origin`、`--certificate` 等参数在官方 deb 里没有配置入口。本项目把参数放到设备本地文件，plist 由它生成：

```
/var/mobile/Library/frida-config/
├── re.frida.server.args
└── re.frida.stealth.args
```

每行一个参数：

```
--listen
127.0.0.1:27043
--token
778899
--origin
https://admin.com
```

用 `tools/frida_ctl.py` 管理：

```bash
python tools/frida_ctl.py list                 # 已装服务、端口、参数
python tools/frida_ctl.py doctor               # 设备概况 + 服务 + 监听端口
python tools/frida_ctl.py set frida-stealth --listen 0.0.0.0:65530 --token 778899
python tools/frida_ctl.py add frida-stealth --verbose
python tools/frida_ctl.py ports
```

`set` 会重建 plist 并重启服务，不需要重装包。重装包也不会覆盖已配置的参数。

详见 [docs/FRIDA-CTL.md](docs/FRIDA-CTL.md)，其中记录了 token 认证的三个坑（Python API 的 remote device 缓存、origin 与 token 的报错区别）。

**token 不能写进 deb。** 包在 GitHub Pages 上公开可下载，写进去等于没有认证。包只带端口这类默认值，token 由操作者在设备上配置。

## 目录结构

```
ios-distribution/
├── .github/workflows/deploy-pages.yml
├── config/
│   ├── site.json          站点与 APT 参数
│   └── frida.json         上游版本锚点 + 变体定义（多版本）
├── scripts/
│   ├── deb_builder.py     下载校验、重打包、stealth 补丁
│   ├── apt_generator.py   Packages / Release 生成
│   ├── gpg_signer.py      InRelease / Release.gpg 签名与自验证
│   ├── catalog.py         catalog.json 生成
│   └── build.py           编排入口
├── tools/
│   └── frida_ctl.py       服务端版本与启动参数管理
├── tests/                 34 项单元测试
├── website/               门户页面模板
├── entitlements/          roothide entitlements 参考（不参与构建）
└── docs/
    ├── PUBLISHING.md
    ├── TROUBLESHOOTING.md
    ├── SECURITY.md
    ├── FRIDA-CTL.md
    └── VERIFICATION-20261124.md
```

### 与规格文档的偏离

原始规格设想 `catalog/catalog.json` 是人工维护的唯一数据源。本项目让 `catalog.json` 由 `scripts/catalog.py` 从**实际构建出的 deb 产物**反向生成，理由：

- deb 的 `Version`、`Architecture`、`Size`、`SHA256` 都能从文件本身提取，人工抄写会产生漂移
- 上游版本已经在 `config/frida.json` 里 pin 死，人工维护 catalog 等于把同一事实记录两遍
- 构建产物与索引条目天然一致，不会出现 catalog 与 Packages 不符

代价是 `catalog.json` 不能手工编辑。要改包的展示信息，改 `scripts/catalog.py` 里的映射；要改包本身，改 `config/frida.json`。

## 已验证 / 未验证

**已在本机与真机验证：**

- 上游 SHA256 pin 生效，篡改即失败
- 重打包确定性：同一上游连续两次构建产出完全一致的 SHA256
- `rootless-arm64` 变体与上游字节完全一致
- 生成的 APT 仓库能被设备上的真 APT 读取：`apt-get update` 无报错，GPG 签名校验通过，`apt-cache policy` 正确选中 `17.24.3+roothide1`
- 签名自验证（`gpg --verify InRelease`、`gpg --verify Release.gpg Release`）通过
- 单元测试全部通过
- **arm64e 包在设备上实际安装成功**，守护进程正常启动、监听 `27042`、客户端可连接、枚举到 369 个进程
- **postinst 自动补齐生效**：清空状态后一次 `dpkg -i` 即恢复 entitlements、符号链接与守护进程
- **沙盒 App 注入成功**：spawn `ChargeLimiter`（372 模块）与 `Shadowrocket`（723 模块）
- **Interceptor Hook 成功**：`getpid` 返回值被改写为 4242，`open` 被拦截并读到真实路径

**未验证：**

- attach **已运行**的沙盒 App（受 AutoPatches 加载时机限制，需重启目标 App；这是机制约束不是缺陷）
- GitHub Pages 上的真实公网 HTTP 访问（本地已验证）
- Sileo / Zebra GUI 交互流程
- 真实业务 App（智慧踏勘 / 董e通 / 央视体育）上的业务逻辑 Hook
- SSL unpinning 脚本在新包上的实际效果
- rootful（checkm8 / palera1n）设备
- TrollStore / TrollApps（本期未实现）

## 上游限制

- GitHub Pages 站点上限 1 GB；当前产物约 45 MB（两个 deb 占绝大部分）
- Release 单个资产必须小于 2 GiB
- Pages 是静态托管，不提供服务端接口
- 公开仓库的代码、catalog、Release 资产均可公开访问

## 参考资料

- Frida releases：<https://github.com/frida/frida/releases>
- Debian Repository Format：<https://wiki.debian.org/DebianRepository/Format>
- GitHub Pages 自定义 workflow：<https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages>
- RootHide Patcher 参考：设备上的 `/Applications/Patcher.app/patch.sh`