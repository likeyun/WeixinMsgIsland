# WeixinMsgIsland

微信电脑版消息通知灵动岛提醒（Windows）。程序监听 Windows Shell Hook 的任务栏闪烁事件，在屏幕顶部显示提醒胶囊；不读取聊天内容，也不统计未读条数。

## 功能

- 微信请求任务栏关注时显示动画胶囊和绿点。
- 胶囊按闪烁账号调用对应的微信托盘项，使用微信自己的窗口恢复流程；窗口激活后自动清除提醒。
- 多开微信时显示“来自微信N”，单开时保持原有提醒文案；编号按当前实例 PID 顺序分配。
- 空闲时显示拟物化镜头孔圆点；提醒胶囊带柔和阴影。
- 通知区托盘图标提供“恢复胶囊位置”和“退出”菜单。
- 支持拖动位置、自定义微信图标和事件诊断模式。

提醒依赖微信和 Windows 发出任务栏闪烁事件。若微信没有发出该事件，程序无法保证显示提醒。
如果无法把微信托盘项唯一对应到提醒账号，胶囊会停止本次唤起，不会强制显示其他微信窗口。

## v1.1.0

- 修复多开微信时点击胶囊会唤起错误窗口或导致窗口无法操作的问题，改为调用对应实例的原生托盘项。
- 多个微信实例同时运行时显示“来自微信1/微信2”等来源标签；单实例不显示编号。
- 来源编号只区分当前运行的实例，不是微信号；重启或增减实例后编号可能变化。

## 运行

仅支持 Windows。使用 Python 运行时，UI Automation 用于把每个微信托盘项对应到具体账号；Pillow 用于更精细的动画和透明渲染，没有 Pillow 时会回退到简易界面。

```powershell
python -m pip install Pillow uiautomation
pythonw .\wechat_capsule.py
```

`pythonw` 会隐藏控制台；点击右下角托盘图标，在菜单中选择“退出”即可关闭后台进程。调试时可改用 `python .\wechat_capsule.py` 保留控制台。

常用参数：

```powershell
python .\wechat_capsule.py --hide-idle
python .\wechat_capsule.py --probe --seconds 60
python .\wechat_capsule.py --exe Weixin.exe
```

右键胶囊可模拟提醒、恢复默认位置或退出。`--icon` 可指定 PNG 图标，`--tk` 可强制使用简易 Tk 界面。

## 打包 EXE

```powershell
python -m pip install -r requirements-build.txt
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "微信消息胶囊" --icon "wechat_capsule.ico" --add-data "wechat_capsule.ico;." --collect-all uiautomation "wechat_capsule.py"
```

生成文件位于 `dist\微信消息胶囊.exe`。托盘图标资源会打包进单文件 EXE。

## 下载发行版

在 [Releases](https://github.com/likeyun/WeixinMsgIsland/releases) 下载 Windows x64 或 ARM64 版本。程序依赖 Windows Shell Hook，暂不提供 macOS 发行包。

## 诊断

```powershell
python .\wechat_capsule.py --probe --all --seconds 60
```

诊断模式会在控制台列出 Shell Hook 收到的事件，用于判断微信是否发出了任务栏闪烁事件。

