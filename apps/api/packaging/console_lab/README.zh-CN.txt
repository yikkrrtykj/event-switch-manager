Event Switch Manager — Windows Console Lab Runner（R86）
=========================================================

重要：本工具只用于受控、非生产、已由用户单独授权的 Cisco Console 只读实验。
它不是生产部署工具，不读取完整运行配置，不写入设备，不执行 CON-02。

0. 安全前提
------------
- 目标设备必须确认无生产业务、无关键链路，并允许本次实验。
- 首次实验优先使用空闲单机；确认单机流程后再进行双成员 Stack。
- 不得在 ISP、DANTE 或其他身份不明的设备上自动开始实验。
- 不发送 BREAK，不主动修改 DTR/RTS，不自动 reset，不支持写配置。
- 程序只允许 show 只读查询；密码不在命令行参数或环境变量传递。
- 实验报告不包含完整 transcript，敏感 identity 字段会脱敏或哈希。
- 真实串口完成边界、DTR/RTS 行为、OS 独占和硬件验收仍是 NOT_VERIFIED。

1. 运行环境
------------
- Windows x64。
- 不需要安装 Python、Node.js 或 Web 服务。
- 不需要管理员权限；USB Console 驱动安装除外。
- 可离线运行；不访问网络。
- 串口候选参数：9600 baud, 8 data bits, parity None, 1 stop bit, no flow control。
  现场仍需核对目标设备的官方 Console 参数。

2. Artifact 身份与 COM 枚举（均不打开串口）
-------------------------------------------
先从独立下载的 ZIP 解压，核对外层 ZIP 和 EXE：

  Get-FileHash .\EventSwitchManager-ConsoleLab-windows-x64.zip -Algorithm SHA256
  Get-FileHash .\EventSwitchManager-ConsoleLab\EventSwitchManager-ConsoleLab.exe -Algorithm SHA256

与 `SHA256SUMS.console-lab` 及 `EventSwitchManager-ConsoleLab-build-record.json`
比较。程序启动真实实验时也会重新计算运行 EXE 的 SHA-256，与 Build Record
不一致即拒绝实验。source-run、unknown Git SHA 或缺失 Build Record 不能用于正式验收。

在 ConsoleLab 目录运行：

  EventSwitchManager-ConsoleLab.exe --list-ports
  EventSwitchManager-ConsoleLab.exe --list-ports --json

只枚举，不打开、不写数据。无设备时也会正常返回；驱动/枚举错误会显示状态。
若只看到模糊/重复 identity 的 Bluetooth 或未知适配器，必须停止，不得猜测设备。

3. 选择实验目标
----------------
  --target 2960x    WS-C2960X-24TS-L / 15.2(7)E10
  --target c1000    C1000-16T-2G-L / 15.2(7)E2

必须同时提供明确选择的 --com，例如：

  EventSwitchManager-ConsoleLab.exe --target c1000 --com COM3 --output-dir .\lab-out

程序不会自动连接其他 COM，也不会在适配器 identity 重复/模糊时自动降级。
没有可靠永久 USB identity 的适配器必须由现场人员单独确认身份；本工具不明文
声称支持未知适配器的自动识别。

4. 授权与人工确认
------------------
- 程序枚举并显示 COM、VID/PID、USB serial、Location、identity quality。
- 操作者必须输入 YES，确认设备无生产业务且允许本次实验。
- 授权只对本次进程、本次 COM、本次 adapter identity、本次目标 PID/release 有效。
- 授权默认不存在，不持久化，不支持环境变量或普通开关绕过。
- 授权消费后不能重复使用；过期、取消、identity 变化或已消费即拒绝。
- 初始 attach 采用被动监听；设备静默时不会自动认定其是安全 EXEC。
- 只有操作者明确确认“设备安全、非生产、无未提交命令”后，才允许发送一次 CR 唤醒；
  程序不会自动重复发送 CR、Ctrl+C、BREAK、ESC 或恢复命令。
- 唤醒后必须重新得到可靠 EXEC/auth prompt，否则停止。
- 如果出现 configuration、ROMMON、setup dialog、认证异常或其他不安全状态，禁止唤醒。
- 已经处于 EXEC 时不要求预先输入用户名/密码；只有实际出现认证提示时才读取对应凭据。
  没有安全交互终端时 fail-closed，不允许 getpass 退化为明文回显。
- 登录得到 EXEC prompt 后先执行 show version 和 show inventory。
- 实际 PID/release 与预期不一致时立即停止扩展查询。
- 每条查询开始前必须由操作者明确确认；结果会显示命令、耗时、字节/行数、分页数、
  completion 状态、unknown_fields 和脱敏摘要。人工确认不能覆盖程序发现的超时、
  歧义或不安全状态。
- 最终结果还需操作者复核确认；未确认不会记录成功。
- 不自动重连、不自动重放命令、不自动进入 configuration mode。
- Ctrl+C 会进入取消/清理流程；关闭失败时报告 CLEANUP_REQUIRED，不声明端口已释放。

5. 只读查询范围
----------------
2960X:
  show version
  show inventory
  show interfaces status
  show switch
  show license
  show boot
  show file systems

C1000-16T:
  show version
  show inventory
  show interfaces status
  show boot
  show file systems

C1000 不执行 show license 或 native Stack 查询。
任意未审核命令、generic CLI、configure terminal、terminal length、copy、write、
erase、reload、delete、format、show running-config、show startup-config 都禁止。

5. 时间预算（R87）
------------------
- 初始 passive prompt：10 秒（避免把静默误认为已登录）。
- 认证/Enable：30 秒总预算（不是每个 prompt 单独 30 秒）。
- 普通/大页查询 IO：60 秒；分页仍受 parser 页数和累计字节上限。
- 操作者单次确认/凭据输入：最长 120 秒；超时即中止，不会继续发送。
- 授权总有效期：默认 20 分钟，最多 30 分钟；所有读/发送还受授权 deadline 限制。
- 实时串口读按 50–100ms 轮询，禁止一次 blocking read 吃掉整个 query deadline。
- 9600 baud 下这些值用于现场首次实验，并非真实协议完成性的证明。
- 人工阅读/确认时间不计入查询执行时间；但整体仍受授权 deadline 限制。

6. 输出
--------
输出目录默认 console-lab-output；每次实验自动创建独立子目录
`experiment-<id>`，避免覆盖前次报告。包含：

  console-lab-report.json
  console-lab-report-fingerprint-input.json
  console-lab-summary.txt
  SHA256SUMS

报告包含软件/artifact SHA、实验授权摘要、COM 连接、查询状态/耗时、脱敏观察摘要、
缺失字段、connection/cleanup 状态、experiment verdict 和硬件门禁；不保存真实密码、
完整未脱敏 transcript 或配置备份。失败报告同样脱敏。
不要自动上传报告到 GitHub 或外部服务器。

独立校验报告内容完整性（不需要 Python）：

  (Get-FileHash .\console-lab-report-fingerprint-input.json -Algorithm SHA256).Hash.ToLower()
  # 应与 console-lab-report.json 中的 report_fingerprint 完全一致
  Get-FileHash .\console-lab-report.json -Algorithm SHA256
  # 应与 SHA256SUMS 中的 console-lab-report.json 行一致

fingerprint 只是内容完整性检查，不是密码学签名，也不证明真实性或硬件验收。

7. 退出码
----------
  0  自检/枚举/实验流程正常完成（报告仍需人工审查）
  2  参数错误或缺少目标/COM
  3  COM 枚举/选择/identity 问题
  4  授权被拒绝或过期
  5  实际 PID/release 与授权目标不一致
  6  串口/查询/操作者中止
  7  cleanup 未确认，必须保留 FAILED/CLEANUP_REQUIRED 状态

8. 异常处理
------------
- 认证失败、超时、取消、拔线：停止，不自动重试，不自动发送恢复命令。
- 关闭失败：不声明端口已释放，不开始新会话；报告为 CLEANUP_REQUIRED。
- 程序不会自动从 ROMMON、switch:、configuration mode 或 initial setup dialog 恢复。
- 需要额外唤醒时，只允许经过现场人员独立确认的一次 CR；不得盲目发送控制字符。
- 连接状态与实验结论分别记录：NOT_ATTEMPTED / OPEN_FAILED / OPENED / RELEASED /
  CLEANUP_REQUIRED；只有实际成功打开才可 opened=true。
- Bootstrap 失败、PID/release 不符、必需查询失败、prompt 未可靠完成、操作者取消、
  部分查询未执行或 cleanup 未确认，都不会记录为实验成功。
- 硬件验收 verdict 始终独立于程序退出码和报告写入成功。

9. 报告与硬件验收
------------------
真实设备验收见同目录 H0-H4-ACCEPTANCE-TEMPLATE.txt。
真实读取的观察只能作为 lab evidence，不自动成为硬件能力认证、verified_serial 或
部署许可。所有真实硬件门禁在人工实验完成前保持 NOT_VERIFIED。
