# frida-server 实机验证记录（2026-11-24）

设备：iPhone10,4 (iPhone XR) / iOS 16.7.11 (20H360) / Dopamine roothide
被测包：`re.frida.server_17.24.3+roothide1_iphoneos-arm64e.deb`
本地产物 SHA256：`d6eb27643fcb49be16b1ab7bd5c2b4807591e1f58f3b5f2f24fcfae60ab96907`

## 安装前基线

| 项 | 值 |
|---|---|
| 已装版本 | `re.frida.server 17.24.3`（Architecture `iphoneos-arm64e`） |
| launchd PID | 633 |
| `/usr/sbin/frida-server` SHA256 | `8d7c99c8a26d4bb9d76aa8b1fc53ef854c36c708c203e7e1addc546564fd4620` |
| `frida-agent.dylib` SHA256 | `58024b6b7211650c6d557db22f79d46101ffee6c29277257e118ed6116c80416` |
| plist SHA256 | `2d581c22ff2e4af346137e85bd39bc43f542aa21a684dcafbe7ed49d4af5b400` |
| 符号链接 | 两个 `.roothidepatch` 均存在，指向 `/usr/lib/DynamicPatches/AutoPatches.dylib` |

备份位置（设备）：`/var/mobile/frida-backup-20261124/` 与 `frida-backup-20261124.tar.gz`（32,410,553 字节）

## 阶段一：仅 dpkg 安装，不做任何补齐

```
$ dpkg -i re.frida.server_17.24.3+roothide1_iphoneos-arm64e.deb
Unpacking re.frida.server (17.24.3+roothide1) over (17.24.3) ...
Setting up re.frida.server (17.24.3+roothide1) ...
```

安装本身成功，无报错。

| 检查项 | 结果 |
|---|---|
| launchd 任务 | 新 PID 6381，状态 0 |
| `frida-server --version` | `17.24.3` |
| `127.0.0.1:27042` 监听 | 正常 |
| 二进制大小 | 18,395,680（旧版 18,312,544） |
| 符号链接 | **被 dpkg 删除** |
| roothide entitlements | **缺失** |
| 连接设备 | 成功 |
| 枚举进程 | 369 个 |
| attach `SpringBoard` (562) | **成功**，1161 模块 |
| attach `afcd` (2195/1236) | **成功** |

## 阶段二：注入沙盒 App（未补齐）

对 10 个运行中的 App 逐个 attach：

| App | 结果 |
|---|---|
| Shadowrocket (849) | `NotSupportedError: unexpected error while probing dyld of target process` |
| BarcodeScanner (819) | `NotSupportedError: unexpected error while resuming process: (os/kern) failure` |
| Dopamine (850) | `probing dyld` 失败 |
| Filza (1186) | `TransportError: timeout was reached` |
| RootHide (1415) | `probing dyld` 失败 |
| Sileo (1416) | `probing dyld` 失败 |
| TrollSpeed (1410) | timeout |
| TrollStoreLite (821) | timeout |
| AppStore (820) | `(os/kern) failure` |
| ChargeLimiter (1414) | `probing dyld` 失败 |

**全部失败。** 系统进程可用、沙盒 App 不可用，指向权限隔离而非 frida 本身故障。

## 阶段三：补齐 roothide 三件套

```bash
ldid -M -S/Applications/Patcher.app/roothide.entitlements /usr/sbin/frida-server
ldid -S /usr/lib/frida-1.0/frida-agent.dylib
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/sbin/frida-server.roothidepatch
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/lib/frida-1.0/frida-agent.dylib.roothidepatch
launchctl unload /Library/LaunchDaemons/re.frida.server.plist
launchctl load /Library/LaunchDaemons/re.frida.server.plist
```

结果：

| 项 | 值 |
|---|---|
| entitlements 验证 | `no-sandbox`、`AppBundles`、`AppDataContainers` 三项均存在 |
| 符号链接 | 两个均重建成功 |
| launchd | 新 PID 6566，状态 0 |
| `--version` | `17.24.3` |

## 阶段四：补齐后重测 attach 已运行 App

对同样 10 个 App 再次 attach：**结果与阶段二完全一致，全部失败。**

原因判断：这些 App 在补齐符号链接**之前**就已启动，`AutoPatches.dylib` 只在进程启动时注入，对已运行进程补链接无效。这是加载时机问题，不是权限问题。

## 阶段五：spawn 新进程（关键验证）

```
=== spawn chaoge.ChargeLimiter
    spawned pid 6620
    msg: {"ok":true,"pid":6620,"arch":"arm64","mods":372,"main":"ChargeLimiter"}
    RESULT: OK

=== spawn com.liguangming.Shadowrocket
    spawned pid 6624
    msg: {"ok":true,"pid":6624,"arch":"arm64","mods":723,"main":"Shadowrocket"}
    RESULT: OK
```

**两个第三方 App 均注入成功。**

## 阶段六：Interceptor Hook 实证

对 spawn 出来的 `ChargeLimiter` 注入 Hook：

```javascript
var fp = Module.getGlobalExportByName("getpid");
var origPid = new NativeFunction(fp, 'int', [])();   // 6637
Interceptor.attach(fp, { onLeave: function (retval) { retval.replace(4242); } });
var nowPid = new NativeFunction(fp, 'int', [])();    // 4242
```

输出：

```json
{
  "libsystem": "0x1f8204000",
  "getpid": "0x1f8205560",
  "origGetpid": 6637,
  "hookedGetpid": 4242,
  "hookWorked": true,
  "openHooked": true
}
```

并捕获到真实的文件访问：

```
OPEN_CALLED: /private/var/containers/Bundle/Application/D3AAE6C5-.../ChargeLimiter.app/Info.plist
```

`getpid` 返回值被成功改写为 4242，`open` 被成功拦截并读到参数。**Hook 能力完整可用。**

## 结论

1. 重打包的 arm64e 包**可以正常安装、启动、被客户端连接**
2. 只重打包**不足以**注入沙盒 App，必须补 roothide 三件套（entitlements + 符号链接 + 重签名）
3. 补齐后 **spawn 注入与 Interceptor Hook 均正常工作**
4. **attach 已运行进程**受 AutoPatches 加载时机限制，补齐后需重启目标 App 才生效
5. dpkg 覆盖安装会删除 `.roothidepatch` 符号链接，每次重装都要重做补齐

## 当前环境最终状态

| 项 | 值 |
|---|---|
| dpkg 记录 | `ii re.frida.server 17.24.3+roothide1 iphoneos-arm64e` |
| launchd | PID 6566，常驻 |
| `/usr/sbin/frida-server` | 18,407,008 字节（重签名后） |
| SHA256 | `9c0f82c6be811770dccac5370ef4b20ed2ed5c581efc9cf2509fafb14ac77e07` |
| `frida-agent.dylib` | 61,823,376 字节 |
| entitlements | roothide 三项齐全 |
| 符号链接 | 两个均存在 |
| `--version` | `17.24.3` |

## 未完成

- 三件套尚未自动化进 `deb_builder.py`（当前为设备侧手工执行）
- 未在真实业务 App（智慧踏勘 / 董e通 / 央视体育）上验证 Hook 业务逻辑
- 未验证 SSL unpinning 脚本在新包上的实际效果
- 未测试 rootful（checkm8）设备

## 回滚方式

```bash
# 恢复原始二进制
cp -a /var/mobile/frida-backup-20261124/bin/frida-server /usr/sbin/frida-server
cp -a /var/mobile/frida-backup-20261124/bin/frida-agent.dylib /usr/lib/frida-1.0/frida-agent.dylib
cp -a /var/mobile/frida-backup-20261124/plist/re.frida.server.plist /Library/LaunchDaemons/
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/sbin/frida-server.roothidepatch
ln -sf /usr/lib/DynamicPatches/AutoPatches.dylib /usr/lib/frida-1.0/frida-agent.dylib.roothidepatch
launchctl unload /Library/LaunchDaemons/re.frida.server.plist
launchctl load /Library/LaunchDaemons/re.frida.server.plist
```

回滚后应恢复到 SHA256 `8d7c99c8...` 与 PID 状态正常。