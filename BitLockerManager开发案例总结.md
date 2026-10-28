# BitLocker 分区加密管理工具开发案例总结

> 项目：BitLockerManager.exe v1.0.0（2026-10-24）
> 作者：浪哩戈浪　主页：http://www.itlog.vip　抖音：kk31352778

## 一、需求背景

系统重装后，除系统分区外的分区保留 BitLocker 预加密状态（资源管理器显示黄色感叹号），
原需手动执行 `manage-bde -status` 查看状态、`manage-bde -off 盘符:` 解密。
目标：做成**双击即用的图形化 exe 软件**，查看所有分区加密状态并一键解密。

## 二、技术选型演进（关键决策）

| 阶段 | 方案 | 结果 |
|---|---|---|
| 1 | PowerShell + WPF 脚本 | 可用，但用户要"真正的软件" |
| 2 | C# WinForms + .NET | 被 .NET 运行环境依赖否决 |
| 3 | **VC++ 原生 Win32 API + WMI COM** | ✅ 最终采用 |

**最终技术栈**：纯 Win32 API（ListView/WPF 风格界面）+ WMI（`ROOT\CIMV2\Security\MicrosoftVolumeEncryption`）
+ `manage-bde` 命令兜底；`/MT` 静态链接，**零 .NET、零 VC 运行库依赖**，单文件约 400 KB。

## 三、核心功能实现

1. **状态查看**：WMI 枚举分区 → GetConversionStatus / GetLockStatus，中文映射状态值（不解析本地化输出，无乱码）
2. **解密所选 / 一键解密**：WMI `Disable` 方法，失败回退 `manage-bde -off`
3. **锁定分区处理**：解锁能力并入解密流程——遇到锁定分区自动弹窗输入 48 位恢复密钥
   （`manage-bde -unlock`），密钥自动规范化（48 位数字 → 6 位一组加短横线），
   **输错可无限重输或跳过**，解锁成功自动并入解密队列
4. **排除系统盘**勾选框（默认勾选）、解密中 3 秒自动刷新进度
5. **exe 内嵌管理员权限清单**（requireAdministrator）：双击自动弹 UAC

## 四、踩坑记录（避坑要点）

1. **权限清单冲突**：`/MANIFEST:EMBED /MANIFESTINPUT:app.manifest` 必须搭配
   `/MANIFESTUAC:NO`，否则链接器默认 asInvoker 片段与 requireAdministrator 冲突
2. **mt.exe 不在 MSVC 目录**：在 Windows SDK `bin\<版本>\x64` 下；编译前需把 SDK bin、
   MSVC bin 都加入 PATH，并手工设置 INCLUDE/LIB 环境变量（vcvars64 在非交互环境不便）
3. **中文编码**：C++ 源码用 `/utf-8` 编译选项；rc 文件需 UTF-8 BOM +
   `#pragma code_page(65001)`，否则版本信息中文乱码
4. **exe 被占用**：链接失败 LNK1104——用户测试时程序开着，改完代码要先关程序再编译
5. **窗口标题栏图标**：图标打进资源只是第一步，还必须 `LoadImageW` 从资源加载并赋给
   `wc.hIcon / wc.hIconSm`，否则标题栏仍是系统默认图标
6. **列表"假空列"**：列宽总和 < 列表宽度时右侧露出空白，看起来像多了一列——列宽要铺满
7. **STATIC 控件底色框**：默认背景与窗口底色不一致，需处理 `WM_CTLCOLORSTATIC`
   返回同色画刷；多行文字高度按 ~19px/行计算并留余量，否则第三行被裁
8. **图标资源生成**：PNG → 多尺寸 ico（16~128 用 32bpp DIB、256 用 PNG），
   PowerShell 生成时注意函数返回 `byte[]` 需要 `[byte[]]` 强转，否则数组退化

## 五、工程组织

```
E:\Dev\BitLocker-off\
├── Build\BitLockerManager.exe   ← 编译产物（/MT 静态链接，拷到任何 Win10/11 即用）
├── BitLockerManager.cpp         ← 源码（单文件，约 35KB）
├── BitLockerManager.ico         ← 多尺寸程序图标（AI 生成 logo 转换）
├── app.manifest                 ← requireAdministrator + comctl32 v6 + Win10/11 兼容声明
├── app.rc                       ← 图标资源 + VERSIONINFO（版本 1.0.0 / 作者信息）
└── build_exe.bat                ← 一键重编译（自动找 vcvars64，输出到 Build\）
```

版本号出现在三处（app.rc / cpp 标题 / VERSIONINFO），升级版本需同步修改。

## 六、经验沉淀

- **原生路线的价值**：对"绿色单文件、无运行时依赖"的诉求，VC++ /MT 是最优解；
  AI 辅助写 Win32 代码完全可行，关键是编译环境变量手工拼装要仔细
- **状态值映射而非输出解析**：凡调用系统组件，优先取结构化数据（WMI/COM 返回值），
  不解析本地化字符串，天然免疫语言差异
- **危险操作必须二次确认**：解密/解锁全程带确认弹窗 + 日志留痕，密钥错误由用户选择重输或跳过
- **快速迭代节奏**：用户截图圈点反馈 → 精准定位 UI 细节 → 改代码 → 重编译，
  单轮 5 分钟内完成，是本地编译环境（MSVC Build Tools）+ AI 协作的高效范式
