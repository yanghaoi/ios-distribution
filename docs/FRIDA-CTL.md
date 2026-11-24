# frida-ctl：服务端版本与启动参数管理

设备上同时装着多个 frida-server 时（例如 17.24.3 常规版 + 16.5.7 stealth 版），需要知道每个的端口、协议、启动参数，还要能改参数而不重新装包。这个工具做这件事。

## 为什么需要它

frida-server 的启动参数（`--listen`、`--token`、`--origin`、`--certificate`）在 frida 官方 deb 里没有任何配置入口，全靠手工改 launchd plist。改错一处服务就起不来，而且重启后如果 plist 被覆盖，配置就丢了。

现在参数存在设备上的纯文本文件里，plist 由该文件生成。改参数 = 改文本 + 重启服务，不碰任何二进制。

```
/var/mobile/Library/frida-config/
├── re.frida.server.args     # 每行一个参数
└── re.frida.stealth.args
```

格式：

```
# frida startup flags, one per line
--listen
127.0.0.1:27043
--token
778899
```

以 `#` 开头的行和空行被忽略。重装包不会覆盖这个文件（只在文件不存在时创建）。

## 用法

```bash
cd platforms/ios/tools/ios-distribution

# 看装了哪些、端口、参数
python tools/frida_ctl.py list

# 设备概况 + 服务 + 监听端口
python tools/frida_ctl.py doctor

# 单个服务详情
python tools/frida_ctl.py show frida-stealth

# 替换启动参数（会重建 plist 并重启服务）
python tools/frida_ctl.py set frida-stealth --listen 0.0.0.0:65530 --token 778899 --origin https://admin.com

# 追加参数，保留原有的
python tools/frida_ctl.py add frida-stealth --verbose

# 看 frida 相关监听端口
python tools/frida_ctl.py ports
```

默认连 `127.0.0.1:2222`（iproxy 转发到设备 22 端口），用户名 `mobile`，密码 `123456`。可覆盖：

```bash
python tools/frida_ctl.py --host 172.16.1.8 --port 2222 --password xxx list
```

## 已注册的服务

| 名称 | 包名 | 二进制 | 端口 | 协议 |
|---|---|---|---|---|
| `frida-server` | `re.frida.server` | `/usr/sbin/frida-server` | 27042 | standard |
| `frida-stealth` | `re.frida.stealth` | `/usr/sbin/frida-server-stealth` | 27043 | frnda |

新增服务时改 `KNOWN_SERVICES` 字典。

## 两个版本共存：为什么不冲突

设备上同时装着 frida 17.24.3 和 16.5.7-stealth。实测确认完全隔离，没有争用。

### 文件层面零重叠

```
/usr/sbin/frida-server                        ← re.frida.server   (17.24.3)
/usr/sbin/frida-server-stealth                ← re.frida.stealth  (16.5.7)
/usr/lib/frida-1.0/frida-agent.dylib          ← re.frida.server
/usr/lib/frida/frida-agent.dylib              ← re.frida.stealth
/Library/LaunchDaemons/re.frida.server.plist
/Library/LaunchDaemons/re.frida.stealth.plist
```

`dpkg -L` 逐条比对无交集；`grep -l "/usr/sbin/frida\|/usr/lib/frida" /var/lib/dpkg/info/*.list` 只匹配到这两个包，没有第三方包占用同一路径。

### 进程与端口独立

```
launchctl:  505  0  re.frida.server
            507  0  re.frida.stealth

launchctl print 显示两者 program 分别为
  .../.jbroot-.../usr/sbin/frida-server
  .../.jbroot-.../usr/sbin/frida-server-stealth

netstat:  127.0.0.1.27042  LISTEN
          127.0.0.1.27043  LISTEN
```

### 协议层面互不识别

这就是隔离生效的直接证据——交叉连接全部被拒：

| 客户端 | → 27042 (17.24.3) | → 27043 (16.5.7-stealth) |
|---|---|---|
| 17.24.3 原版 | 成功，337 进程 | `ProtocolError` |
| 16.5.7-stealth | `ProtocolError` | 成功，336 进程 |

原因是 17.x 的 D-Bus 接口名是 `re.frida.*`，stealth 版被替换成 `re.frnda.*`，两边握手阶段就谈不拢。

### 一个依赖上游命名的隐患

两份 agent 路径能天然错开，靠的是 frida 官方在两个大版本间改了 agent 目录名：

```
/usr/lib/frida-1.0/frida-agent.dylib   61,823,376  (17.x)
/usr/lib/frida/frida-agent.dylib       40,291,296  (16.x)
```

而且这个路径是**编译进 frida-server 二进制里的**，不能靠配置改。我们只是让包跟随各自版本的原生布局：

- 17.24.3 的 `frida-server` 写死 `/usr/lib/frida-1.0/frida-agent.dylib`
- 16.5.7 的 `frida-server` 写死 `/usr/lib/frida/frida-agent.dylib`

**这不是我们设计的隔离机制，是上游命名差异带来的巧合。** 如果将来某个 frida 版本把 agent 目录改回与另一版本相同的名字，两个包就会开始互相覆盖 `frida-agent.dylib`。

升级上游版本时必须先确认新版本用的 agent 路径。这个路径在二进制里是**分段存储**的（`frida-1.0` 与 `frida-agent.dylib` 是两个相邻但独立的字符串），所以拼完整路径去 grep 找不到。用 `tools/check_agent_layout.py`：

```bash
python tools/check_agent_layout.py artifacts/debs/<包名>.deb
```

实测输出：

```
=== re.frida.server_17.24.3+roothide1_iphoneos-arm64e.deb
   ./usr/lib/frida-1.0/frida-agent.dylib 61857712
      re.frida.            40
   ./usr/sbin/frida-server 18395680
      frida-1.0            2
      frida-agent.dylib    2
      re.frida.            58

=== re.frida.stealth_16.5.7+stealth1_iphoneos-arm64e.deb
   ./usr/lib/frida/frida-agent.dylib 40325648
      re.frnda.            40
   ./usr/sbin/frida-server-stealth 15028160
      /usr/lib/frida       2
      frida-agent.dylib    2
      re.frnda.            52
```

判读：

- `frida-1.0` 有值 → 该版本用 `/usr/lib/frida-1.0/`
- `/usr/lib/frida` 有值 → 该版本用 `/usr/lib/frida/`
- 两个都是 0 → 路径格式变了，需要重新确认
- `re.frida.` / `re.frnda.` 的值用于确认 stealth 补丁是否已应用

注意设备自带的 `strings` 是精简版，`strings x | grep "frida-agent.dylib"` 返回 0 并不代表路径不存在，不要用它判断。

若路径与已装版本撞车，需要改成独立包名 + 独立 agent 目录，并验证 `frida-server` 能否接受路径不匹配（大概率不能，需像 stealth 变体那样做二进制层面的处理）。

## 实际验证过的场景

**改参数并生效**（2026-11-24，iPhone XR / iOS 16.7.11 / Dopamine roothide）：

```bash
python tools/frida_ctl.py set frida-stealth --listen 0.0.0.0:65530 --token 778899 --origin https://admin.com
```

结果：

```
written: --listen 0.0.0.0:65530 --token 778899 --origin https://admin.com
10244	0	re.frida.stealth
```

设备侧确认：

```
netstat: tcp4  * .65530  LISTEN
plist ProgramArguments:
  /usr/sbin/frida-server-stealth
  --listen
  0.0.0.0:65530
  --token
  778899
  --origin
  https://admin.com
```

**token 生效**：

```
frida-ps -H 127.0.0.1:27045 --token abc123   → 正常列出进程
frida-ps -H 127.0.0.1:27045                  → not authorized, authentication required
```

**重启后配置不丢**：设备重启 + 重越狱后，两个服务自动拉起（新 PID），参数文件和端口全部保持。

## token 认证的三个坑

这三个都在本次实测中踩到，全部确认过。

### 1. Python API 会缓存 remote device

```python
mgr = frida.get_device_manager()
mgr.add_remote_device('127.0.0.1:27045', token='bad')    # 失败
mgr.add_remote_device('127.0.0.1:27045', token='abc123') # 仍然失败！
```

第一次用错 token 后，同一个 `DeviceManager` 里该地址被缓存，后续传正确 token 也返回 `incorrect token`。

**解法**：每次连接前先移除缓存。

```python
try:
    mgr.remove_remote_device('127.0.0.1:27045')
except Exception:
    pass
d = mgr.add_remote_device('127.0.0.1:27045', token='abc123')
```

验证结果：

```
bad    -> FAIL InvalidArgumentError incorrect token
abc123 -> 117 procs
```

### 2. `--origin` 和 `--token` 都启用时，客户端必须同时传

只传 token 不传 origin 会报 `incorrect origin`，而不是 `authentication required`。报错信息指向前者时说明 origin 没对上，不要以为是 token 错。

### 3. `frida-ps` 等 CLI 没有这个缓存问题

同样的 token，CLI 一次就对。排查时优先用 CLI 确认服务端侧是否正常，再怀疑 Python 侧。

## 与打包流程的关系

`deb_builder.py` 生成的 postinst 已经内置了这套配置逻辑：

- 首次安装：创建 args 文件，写入包的默认参数（如 stealth 包写 `-l 127.0.0.1:27043`）
- 之后重装：**保留** args 文件现有内容
- 每次安装：从 args 文件重建 plist，重启服务

所以 `frida_ctl.py set` 改的参数，重装包之后依然有效。

## 关于 token 不要放进 deb

`--token` 的值绝不能写进公开分发的 deb：

- deb 在 GitHub Pages 上公开可下载，任何人都能解包读到 plist 里的 token
- 等于没有认证

所以包里只放**端口**这类无敏感性的默认值。token 由操作者在设备上用 `frida_ctl.py set` 配置，只存在设备本地 `args` 文件（权限 600，目录 700）。

## 已知限制

- 依赖 SSH（iproxy 2222 → 22）。设备未开启 SSH 时不可用
- 只支持 `KNOWN_SERVICES` 里登记的服务名，不自动发现新装的包
- `iproxy` 会累积残留进程，长时间使用后需要 `taskkill //F //IM iproxy.exe` 再重建（本次实测遇到 8 个堆积导致 SSH 连接失败）
- 频繁连续调用会触发 SSH banner 握手失败，两次调用之间留几秒