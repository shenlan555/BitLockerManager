# BitLockerManager

Windows 分区 BitLocker 加密查看与解密工具。系统重装后，除系统分区外的分区常保留 BitLocker 预加密状态（资源管理器盘符带黄色感叹号），本工具提供图形化的一键查看与解密，替代手动 `manage-bde -status` / `manage-bde -off` 命令。

![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue) ![runtime](https://img.shields.io/badge/dependency-none-brightgreen)

## 功能

- **查看加密状态**：列出所有分区的盘符、容量、加密百分比、卷状态、保护状态、加密方法、锁定状态（替代 `manage-bde -status`）
- **解密所选分区**：列表多选（Ctrl/Shift）后解密
- **一键解密**：自动处理所有已加密分区；遇到已锁定（需恢复密钥）的分区会逐个弹窗输入 48 位恢复密钥（从 [aka.ms/myrecoverykey](https://aka.ms/myrecoverykey) 登录微软账户查询），解锁后自动并入解密队列
- **排除系统盘**：勾选后一键解密自动跳过系统分区（默认勾选）
- **自动刷新**：解密进行中每 3 秒刷新进度，直到加密百分比归 0、感叹号消失
- 密钥输错可无限次重选“重新输入 / 跳过该分区”

## 编译

零第三方依赖，仅需 MSVC（Visual Studio 2022 / Build Tools，勾选“使用 C++ 的桌面开发”）：

```bat
build_exe.bat
```

产物输出到 `Build\BitLockerManager.exe`（约 400 KB）。

- `/MT` 静态链接，不依赖 VC 运行库与 .NET Framework
- 内嵌管理员权限清单（`requireAdministrator`），双击自动弹 UAC
- 内嵌程序图标与版本信息资源（`app.rc` / `app.manifest` / `BitLockerManager.ico`）

也支持 GitHub Actions 云端编译：push 后自动构建并上传 exe 制品；推送 `v*` 标签会自动把 exe 附到 GitHub Release（见 [.github/workflows/build.yml](.github/workflows/build.yml)）。

## 技术要点

- 纯原生 C++ / Win32 API，无任何运行时依赖
- 状态查询与解密通过 WMI COM 接口（`ROOT\CIMV2\Security\MicrosoftVolumeEncryption`），失败自动回退 `manage-bde -off` 命令兜底
- 已锁定分区通过 `manage-bde -unlock` 用恢复密钥解锁，密钥输入自动规范化（自动补短横线）
- 状态值直接映射为中文显示，不解析系统本地化输出，无乱码风险
- 兼容 PE 环境（需 WinPE-WMI + WinPE-SecureStartup 组件）

## 注意事项

- ⚠️ 解密只是移除 BitLocker 保护，**不会丢失数据**，但过程中请勿断电、强制关机
- 大容量分区解密可能需要几十分钟到几小时
- 已锁定的分区必须先输入恢复密钥解锁才能解密；从未备份过恢复密钥的分区无法解密（BitLocker 安全设计）

## 作者

浪哩戈浪

- 主页：http://www.itlog.vip
- 抖音：kk31352778

## 许可证

[MIT](LICENSE)
