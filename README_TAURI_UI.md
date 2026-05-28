# Ghost Proxifier Tauri UI

这个目录新增了一个 Tauri 桌面 UI，用于管理 `ghost-proxifier.exe`：

- 开机启动开关（当前用户注册表 `HKCU\...\Run`）
- 代理地址配置
- 目标进程名 / PID 配置
- 实时日志查看与关键字过滤
- 配置持久化，下次打开自动恢复界面设置
- UI 停止或退出时可执行 `--uninject` 卸载 `ghost_core.dll`，尽量恢复目标进程状态

## 构建顺序

1. 先构建 C++ 注入器和 DLL：

   ```cmd
   compile.bat
   ```

   需要生成：

   - `bin\ghost-proxifier.exe`
   - `bin\ghost_core.dll`

2. 安装 Tauri 依赖并运行：

   ```cmd
   npm install
   npm run tauri dev
   ```

3. 打包：

   ```cmd
   npm run tauri build
   ```

## 说明

Tauri 后端启动时会把 `ghost-proxifier.exe` 与 `ghost_core.dll` 复制到 AppData 的 runtime 目录，再在那里写入 `ghost.conf` 并启动注入器。这样避免了安装目录只读时无法更新配置的问题。
