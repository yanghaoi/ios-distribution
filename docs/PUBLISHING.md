# 发布与版本管理

## 更新到新的上游版本

全部改动集中在 `config/frida.json`。

### 1. 取上游新版本的真实哈希

```bash
gh api repos/frida/frida/releases/tags/<新版本> \
  --jq '.assets[] | select(.name|startswith("frida_")) | "\(.name) \(.size) \(.digest)"'
```

输出示例：

```
frida_17.27.5_iphoneos-arm64.deb 23556884 sha256:d83c06ce6907666a84195179595d767c05f22e9bc6577e6ec2e4f4a7b1bf6feb
```

`digest` 去掉 `sha256:` 前缀即为要写入的 `sha256`。**不要手算也不要凭记忆填**。

### 2. 修改配置

```json
{
  "upstream": {
    "version": "17.27.5",
    "releaseUrl": "https://github.com/frida/frida/releases/tag/17.27.5",
    "assets": {
      "arm64": {
        "name": "frida_17.27.5_iphoneos-arm64.deb",
        "url": "https://github.com/frida/frida/releases/download/17.27.5/frida_17.27.5_iphoneos-arm64.deb",
        "size": 23556884,
        "sha256": "d83c06ce6907666a84195179595d767c05f22e9bc6577e6ec2e4f4a7b1bf6feb"
      }
    }
  }
}
```

`url`、`releaseUrl`、`name`、`size`、`sha256` 五处必须同时改，漏一处会在构建时失败。

### 3. 清理旧缓存

缓存按文件名存放，换版本后文件名变化，旧文件不会干扰。但如果复用了同名文件（例如重新下载同一个版本），必须先删缓存再构建，否则旧缓存会被当作有效内容。

```bash
rm -f .cache/upstream/frida_<版本>_iphoneos-arm64.deb
```

缓存命中时会重新校验 SHA256，哈希不符同样会失败。

### 4. 本地验证后提交

```bash
python scripts/deb_builder.py . .cache/upstream artifacts/debs
python -m unittest discover -s tests -v
python scripts/build.py dist
```

确认 `dist/build-summary.json` 里的版本与 SHA256 符合预期后提交配置改动。

### 5. 客户端同步升级

frida 客户端（`fv` 管理的 Python 侧）与设备上的 frida-server **主版本必须一致**。升级服务端时一起升级：

```bash
fv install 17.27.5
fv use 17.27.5
```

否则连接会报协议不匹配。

## 变体的增删

`config/frida.json` 的 `variants` 数组决定产出哪些包。每个变体字段：

| 字段 | 含义 |
|---|---|
| `id` | 内部标识，仅用于日志与 `build-summary.json` |
| `architecture` | 写入 control 的 `Architecture`，必须与设备 `dpkg --print-architecture` 一致 |
| `sourceArch` | 用哪个上游资产作为输入（对应 `upstream.assets` 的键） |
| `transform` | `none` 原样发布，`roothide` 扁平化路径并改写架构 |
| `versionSuffix` | 追加到上游版本号后，形成独立的 APT 版本 |
| `preDepends` | 写入 `Pre-Depends`，`null` 表示不写 |
| `outputName` | 输出文件名模板，`{version}` 会被替换为最终版本号 |

### 增加一个 rootful 变体

```json
{
  "id": "rootful-arm64",
  "architecture": "iphoneos-arm",
  "sourceArch": "arm",
  "transform": "none",
  "versionSuffix": "+rootful1",
  "preDepends": null,
  "outputName": "re.frida.server_{version}_iphoneos-arm.deb"
}
```

同时在 `upstream.assets` 里加上 `arm` 键，指向 `frida_<版本>_iphoneos-arm.deb` 与它的哈希。

当前 `transform` 只实现了 `none` 与 `roothide`。传入其他值会在构建期抛 `ValueError`。

### 版本后缀的作用

APT 用版本号区分同一包的多个架构实例。`17.24.3+roothide1` 的 `+` 后缀是 Debian 的合法版本语法，排序上高于同名 `17.24.3`。这样当两个架构同时存在于索引里时，`apt-cache policy` 能正确按架构各自匹配，不会互相覆盖。

## 撤销一次发布

1. 从 `config/frida.json` 的 `variants` 里移除对应变体
2. 重新构建并推送

`dist/` 每次构建都是全量重建（`build.py` 开头会删掉整个目录），所以旧包不会残留。

注意：如果设备已经安装过，卸载需要在设备上执行 `apt remove re.frida.server`，仓库侧改动不会自动卸载。

## 密钥轮换

1. 生成新密钥（流程见 README）
2. 更新 GitHub Secrets 的 `APT_GPG_PRIVATE_KEY` 与 `APT_GPG_PASSPHRASE`
3. 推送触发部署，Pages 上的 `apt/public.gpg` 会变成新公钥
4. 通知所有设备用户重新信任公钥；Sileo 通常需要移除源再重新添加

旧密钥在新索引生效后立即失效。没有过渡期，因为 APT 客户端只信任它已经导入的那把公钥。