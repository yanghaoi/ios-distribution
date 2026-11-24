# 安全边界

## 发布内容的来源与授权

本仓库只发布两类内容：

1. **上游开源项目的 Release 资产**，按固定版本与固定 SHA256 重新打包。frida 是 LGPL 许可的开源项目，其 Release 资产可再分发。
2. **不使用任何第三方商业软件、破解版或付费插件。** 若有例外，必须先在 `config/` 里显式登记授权依据，不得静默加入。

不发布、不镜像、不再分发：

- 未经授权的商业 App 或插件
- 他人私有的企业签名产物
- 任何来源不明的 IPA / DEB

## 上游完整性校验

`config/frida.json` 为每个上游资产固定 `size` 与 `sha256`。构建时：

```
下载 → 比对 size → 比对 sha256 → 不符即抛 ValueError 终止
```

CI 在上传 Pages 前还会**再校验一次缓存文件的哈希**，防止缓存被污染后继续发布。

这样做的意义：上游偷偷替换同版本号的包、下架 Release、或中间人篡改传输内容，都会在构建期失败，不会静默进入生产。

SHA256 只证明"文件与记录的元数据一致"，**不证明来源可信**。来源可信性由 `config/frida.json` 里的 URL 与人工审核保证。

## GPG 密钥

### 用途边界

APT 密钥**只用于签名 APT 仓库索引**（`Release`、`InRelease`）。不得用于：

- IPA 或 DEB 的代码签名
- 其他仓库的签名
- 任何与 iOS 设备信任链相关的事情

### 存放

| 位置 | 内容 |
|---|---|
| GitHub Actions Secrets `APT_GPG_PRIVATE_KEY` | 私钥全文（ASCII armored） |
| GitHub Actions Secrets `APT_GPG_PASSPHRASE` | 私钥口令 |
| 仓库内 `apt/public.gpg` | 公钥，可公开 |

私钥与口令**不进入 Git 历史**。`.gitignore` 已排除 `.env`、`secrets/`、`*.p12`、`*.mobileprovision`、`*.pem`。

### 临时 GNUPGHOME

`gpg_signer.py` 每次签名都创建临时 `GNUPGHOME` 目录，导入私钥，签名完成后 `shutil.rmtree` 删除。目的是避免私钥落进 artifact 或构建缓存。

CI 上这个目录在 runner 的临时分区，任务结束即销毁。

### 轮换

生成新密钥 → 更新两个 Secrets → 推送触发部署 → 通知设备用户重新信任公钥。

**没有过渡期。** APT 客户端只信任它已经导入的那把公钥，换密钥后旧公钥立即失效，所有设备必须重新导入。这是 APT 签名的固有特性，不是实现缺陷。

### 私钥泄露的处置

1. 立即在 GitHub 上撤销对应 Secret
2. 生成新密钥并按上面的流程替换
3. 由于旧私钥可以签发任意索引，一旦泄露即视为该源的所有历史签名均不可信
4. 检查是否有非预期的 Release 或 Pages 部署

## 禁止的部署方式

以下做法会让签名机制失去意义，本项目明确不做：

- `trusted=yes` 或 `[trusted=yes]` 绕过签名校验
- 部署未经签名的 APT 仓库到生产
- 在 CI 里用 `|| true` 吞掉签名失败
- 把私钥写进构建日志

`config/site.json` 的 `publish.requireGpgSignature` 为 `true` 时，缺少密钥直接抛 `BuildError`；CI 里检测到 secret 为空即退出非零。这两道都是失败关闭。

## 二进制安全

### 重打包做了什么

`roothide` 变换只改三处：

1. control 的 `Architecture`：`iphoneos-arm64` → `iphoneos-arm64e`
2. control 的 `Version`：追加后缀（如 `+roothide1`），并删除 `Size`、`Installed-Size`、`Pre-Depends` 后按需重写 `Pre-Depends`
3. data.tar 的路径前缀：`./var/jb/` → `./`

**不修改任何二进制内容**，不改 Mach-O、不改 entitlements、不重签名、不解密。

### 不执行包内脚本

`build.py` 与 `deb_builder.py` 只做归档层的读写，**不执行** DEB 内的 `preinst`、`postinst`、`prerm`、`postrm`、`extrainst_`。

这些脚本会原样保留在包内（`extrainst_` 与 `prerm` 是上游原有的，负责 launchctl 加载与卸载），由目标设备上的 dpkg 在执行安装时调用。构建环境从不执行它们。

### 归档路径安全

`deb_builder.read_ar` 对每个成员校验 `size` 字段可解析且不越过数据边界，越界抛 `ValueError`。tar 层通过 `iter_tar` + 显式 `TarInfo` 重建，不调用 `extractall`，因此不存在路径穿越落到构建机文件系统的可能。

本实现把文件内容读进内存处理，不落盘解包。两个 deb 各约 23 MB，内存峰值可控。

## 已知的安全差异

本仓库产出的 arm64e 包与设备上现有安装（RootHide Patcher 处理过）相比，**缺少三项权限**：

| 缺失项 | 作用 |
|---|---|
| `com.apple.private.security.no-sandbox` | 不沙盒化 |
| `com.apple.private.security.storage.AppBundles` | 访问 App Bundle 容器 |
| `com.apple.private.security.storage.AppDataContainers` | 访问 App 数据容器 |

以及缺少 `*.roothidepatch` 符号链接（指向 `AutoPatches.dylib`，负责运行时的路径重定向）。

后果：frida-server 能启动、能报版本，但**注入沙盒内 App 可能失败**。这是未验证项，不是已知失败。

需要补齐时，正确做法是对构建产物跑 RootHide Patcher（设备上 `/Applications/Patcher.app/patch.sh`），而不是手工编造 entitlements 或改二进制。补齐后必须重新验证，并在 `config/frida.json` 的 `variants[].notes` 里记录。

## 仓库可见性

GitHub 免费账号的 Pages 要求公开仓库。因此：

- 代码、`config/`、`catalog.json`、Release 资产、Pages 站点**全部公开可访问**
- 不要往这里放内部 App、内部域名、内网地址、账号凭据、设备 UDID
- 不要在 catalog 里写内部版本号或客户名称

## 未实现的安全能力

本期不做，需要时另行设计：

- 企业 OTA（`channels.enterpriseOta` 与 `ota.enabled` 均为 `false`）
- TrollStore / TrollApps 分发（`channels.trollstore` 为 `false`）
- 访问控制（Pages 是静态托管，没有细粒度权限）
- 下载统计或设备识别

## 上游参考资料

- Frida：<https://github.com/frida/frida>
- Debian Repository Format（含签名要求）：<https://wiki.debian.org/DebianRepository/Format>
- Debian SecureApt：<https://wiki.debian.org/SecureApt>
- GitHub Pages 限制：<https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits>