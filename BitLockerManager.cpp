// ============================================================
//  BitLocker 分区加密管理工具（VC++ 原生 Win32 版）
//  - 纯 Win32 API 界面，无 .NET 依赖，/MT 静态链接无 VC 运行库依赖
//  - 通过 WMI (ROOT\CIMV2\Security\MicrosoftVolumeEncryption) 查询/解密
//  - 内嵌 manifest，启动自动请求管理员权限
//
//  编译（VS 命令行）:
//    cl /nologo /W3 /O2 /MT /utf-8 /DUNICODE /D_UNICODE ^
//       /Fe:BitLockerManager.exe BitLockerManager.cpp ^
//       /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTINPUT:app.manifest
// ============================================================
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------- 控件 ID ----------------
#define ID_BTN_REFRESH  1001
#define ID_BTN_SEL      1002
#define ID_BTN_ALL      1003
#define ID_CHK_AUTO     1004
#define ID_CHK_EXCLUDE  1008
#define ID_LIST         1005
#define ID_PROGRESS     1006
#define ID_LOG          1007
#define ID_TIMER_AUTO   1

// ---------------- 数据结构 ----------------
struct VolInfo
{
    std::wstring drive;      // L"C:"
    std::wstring objPath;    // WMI 对象路径（用于 ExecMethod）
    double       capacityGB;
    int          pct;        // 加密百分比 0-100
    int          convStatus; // 转换状态
    int          lockStatus; // 0=已解锁 1=已锁定
    int          protStatus; // 0=关闭 1=开启 2=未知
    int          encMethod;  // 加密方法
    bool         isSystem;
};

static HWND g_hWnd, g_hList, g_hLog, g_hProgress, g_hBtnRefresh, g_hBtnSel, g_hBtnAll, g_hChkAuto, g_hChkExclude, g_hLabel, g_hAuthor;
static IWbemServices* g_svc = nullptr;
static HFONT g_hFont = nullptr;
static HBRUSH g_hbrBg = nullptr;
static std::vector<VolInfo> g_vols;   // 最近一次查询结果
static std::wstring g_lastError;

// ---------------- 小工具 ----------------
static std::wstring NowTime()
{
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static void AppendLog(const std::wstring& s)
{
    if (!g_hLog) return;
    std::wstring line = L"[" + NowTime() + L"] " + s + L"\r\n";
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
}

static std::wstring Fmt(const wchar_t* fmt, ...)
{
    wchar_t buf[512];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    return buf;
}

static BSTR SB(const wchar_t* s) { return SysAllocString(s); }

// ---------------- WMI 状态文本 ----------------
static const wchar_t* ConvStatusText(int s)
{
    switch (s)
    {
    case 0:  return L"未加密";
    case 1:  return L"已加密";
    case 2:  return L"正在加密…";
    case 3:  return L"正在解密…";
    case 4:  return L"加密已暂停";
    case 5:  return L"解密已暂停";
    case 6:  return L"解密失败";
    default: return L"未知";
    }
}

static const wchar_t* MethodText(int m)
{
    switch (m)
    {
    case 0:  return L"无";
    case 1:  return L"AES-128(扩散)";
    case 2:  return L"AES-256(扩散)";
    case 3:  return L"AES-128";
    case 4:  return L"AES-256";
    case 5:  return L"硬件加密";
    case 6:  return L"XTS-AES-128";
    case 7:  return L"XTS-AES-256";
    case 8:  return L"硬件加密(XTS)";
    default: return L"未知";
    }
}

static const wchar_t* ProtStatusText(int s)
{
    switch (s)
    {
    case 0:  return L"保护关闭";
    case 1:  return L"保护开启";
    case 2:  return L"未知";
    default: return L"-";
    }
}

static bool IsActive(int convStatus)
{
    return convStatus == 2 || convStatus == 3 || convStatus == 4 || convStatus == 5;
}

// ---------------- WMI ----------------
static bool WmiConnect(std::wstring* err)
{
    if (g_svc) return true;

    IWbemLocator* loc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&loc);
    if (FAILED(hr)) { if (err) *err = L"COM 初始化失败"; return false; }

    BSTR ns = SB(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
    hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &g_svc);
    SysFreeString(ns);
    loc->Release();
    if (FAILED(hr) || !g_svc)
    {
        if (err) *err = L"无法连接 BitLocker WMI 提供程序（此系统可能不支持 BitLocker，或权限不足）";
        return false;
    }

    hr = CoSetProxyBlanket(g_svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    if (FAILED(hr)) { if (err) *err = L"WMI 代理设置失败"; return false; }
    return true;
}

static std::wstring GetStr(IWbemClassObject* o, const wchar_t* name)
{
    std::wstring r;
    VARIANT v; VariantInit(&v);
    if (SUCCEEDED(o->Get(name, 0, &v, nullptr, nullptr)))
    {
        if (v.vt == VT_BSTR && v.bstrVal) r = v.bstrVal;
        VariantClear(&v);
    }
    return r;
}

static LONG GetInt(IWbemClassObject* o, const wchar_t* name)
{
    LONG r = -1;
    VARIANT v; VariantInit(&v);
    if (SUCCEEDED(o->Get(name, 0, &v, nullptr, nullptr)))
    {
        if (v.vt == VT_I4) r = v.lVal;
        else if (v.vt == VT_UI4) r = (LONG)v.ulVal;
        else if (v.vt == VT_I8) r = (LONG)v.llVal;
        else if (v.vt == VT_UI8) r = (LONG)v.ullVal;
        VariantClear(&v);
    }
    return r;
}

// WMI 对象路径中转义 \ 和 "
static std::wstring EscapeObjPath(const std::wstring& deviceId)
{
    std::wstring esc;
    for (size_t i = 0; i < deviceId.size(); ++i)
    {
        wchar_t c = deviceId[i];
        if (c == L'\\') esc += L"\\\\";
        else if (c == L'"') esc += L"\\\"";
        else esc += c;
    }
    return L"Win32_EncryptableVolume.DeviceID=\"" + esc + L"\"";
}

// 调用无输入参数的方法，返回输出对象（调用者负责 Release）
static IWbemClassObject* WmiExec(const std::wstring& objPath, const wchar_t* method)
{
    if (!g_svc) return nullptr;
    BSTR p = SB(objPath.c_str());
    BSTR m = SB(method);
    IWbemClassObject* out = nullptr;
    HRESULT hr = g_svc->ExecMethod(p, m, 0, nullptr, nullptr, &out, nullptr);
    SysFreeString(p); SysFreeString(m);
    if (FAILED(hr)) return nullptr;
    return out;
}

// 调用 Decrypt（带 Flags=0 输入参数）
static bool WmiDecrypt(const std::wstring& objPath, LONG* retCode)
{
    if (!g_svc) return false;

    // 获取方法输入签名
    BSTR clsName = SB(L"Win32_EncryptableVolume");
    IWbemClassObject* cls = nullptr;
    if (FAILED(g_svc->GetObject(clsName, 0, nullptr, &cls, nullptr))) { SysFreeString(clsName); return false; }
    SysFreeString(clsName);

    BSTR mName = SB(L"Decrypt");
    IWbemClassObject* inDef = nullptr;
    cls->GetMethod(mName, 0, &inDef, nullptr);
    cls->Release();

    IWbemClassObject* in = nullptr;
    if (inDef)
    {
        inDef->SpawnInstance(0, &in);
        inDef->Release();
    }

    IWbemClassObject* out = nullptr;
    BSTR p = SB(objPath.c_str());
    HRESULT hr = g_svc->ExecMethod(p, mName, 0, nullptr, in, &out, nullptr);
    SysFreeString(p); SysFreeString(mName);
    if (in) in->Release();
    if (FAILED(hr)) return false;

    bool ok = false;
    if (out)
    {
        LONG rc = GetInt(out, L"ReturnValue");
        if (retCode) *retCode = rc;
        ok = (rc == 0);
        out->Release();
    }
    return ok;
}

// 磁盘容量（字节）—— 用 Win32 API 直接取
static double DriveCapacityGB(const std::wstring& drive)
{
    ULARGE_INTEGER total = {};
    std::wstring root = drive + L"\\";
    if (GetDiskFreeSpaceExW(root.c_str(), nullptr, &total, nullptr) && total.QuadPart > 0)
        return (double)total.QuadPart / (1024.0 * 1024.0 * 1024.0);
    return 0;
}

// 查询所有 BitLocker 可管理卷
static bool QueryVolumes(std::vector<VolInfo>& vols, std::wstring* err)
{
    vols.clear();
    if (!WmiConnect(err)) return false;

    IEnumWbemClassObject* en = nullptr;
    BSTR q = SB(L"Win32_EncryptableVolume");
    HRESULT hr = g_svc->CreateInstanceEnum(q, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                           nullptr, &en);
    SysFreeString(q);
    if (FAILED(hr) || !en) { if (err) *err = L"枚举加密卷失败"; return false; }

    wchar_t sysDrive[MAX_PATH] = L"C:";
    GetEnvironmentVariableW(L"SystemDrive", sysDrive, MAX_PATH);

    for (;;)
    {
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        if (en->Next(WBEM_INFINITE, 1, &obj, &ret) != S_OK || ret == 0) break;

        std::wstring dev = GetStr(obj, L"DeviceID");
        std::wstring letter = GetStr(obj, L"DriveLetter");
        LONG prot = (LONG)GetInt(obj, L"ProtectionStatus");
        obj->Release();

        if (letter.empty() || dev.empty()) continue; // 跳过没有盘符的卷
        if (!letter.empty() && letter[letter.size()-1] != L':') letter += L":";

        VolInfo vi;
        vi.drive = letter;
        vi.objPath = EscapeObjPath(dev);
        vi.protStatus = (int)prot;
        vi.pct = 0;
        vi.convStatus = -1;
        vi.lockStatus = 0;
        vi.encMethod = 0;
        vi.capacityGB = DriveCapacityGB(letter);
        vi.isSystem = _wcsicmp(letter.c_str(), sysDrive) == 0;

        IWbemClassObject* out = WmiExec(vi.objPath, L"GetConversionStatus");
        if (out)
        {
            vi.convStatus = (int)GetInt(out, L"ConversionStatus");
            vi.pct = (int)GetInt(out, L"EncryptionPercentage");
            if (vi.pct < 0) vi.pct = 0;
            if (vi.pct > 100) vi.pct = 100;
            out->Release();
        }

        out = WmiExec(vi.objPath, L"GetLockStatus");
        if (out)
        {
            vi.lockStatus = (int)GetInt(out, L"LockStatus");
            out->Release();
        }

        out = WmiExec(vi.objPath, L"GetEncryptionMethod");
        if (out)
        {
            vi.encMethod = (int)GetInt(out, L"EncryptionMethod");
            out->Release();
        }

        vols.push_back(vi);
    }
    en->Release();

    std::sort(vols.begin(), vols.end(),
              [](const VolInfo& a, const VolInfo& b) { return _wcsicmp(a.drive.c_str(), b.drive.c_str()) < 0; });
    return true;
}

// manage-bde 兜底解密
static bool RunManageBdeOff(const std::wstring& drive)
{
    std::wstring cmd = L"manage-bde.exe -off \"" + drive + L"\"";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static void DecryptVolume(const VolInfo& v)
{
    if (v.lockStatus == 1)
    {
        AppendLog(Fmt(L"%s 处于锁定状态，请先用\"输入恢复密钥解锁\"按钮解锁后再解密。", v.drive.c_str()));
        return;
    }
    LONG rc = -1;
    if (WmiDecrypt(v.objPath, &rc) && rc == 0)
    {
        AppendLog(Fmt(L"已对 %s 发起解密，正在后台进行（可能需要较长时间，请勿关机）。", v.drive.c_str()));
        return;
    }
    if (RunManageBdeOff(v.drive))
        AppendLog(Fmt(L"已通过 manage-bde 对 %s 发起解密。", v.drive.c_str()));
    else
        AppendLog(Fmt(L"对 %s 解密失败（WMI 返回码 %ld）。", v.drive.c_str(), rc));
}

// ---------------- 列表刷新 ----------------
static void RefreshList()
{
    std::set<std::wstring> sel;
    {
        int i = -1;
        while ((i = ListView_GetNextItem(g_hList, i, LVNI_SELECTED)) >= 0)
        {
            wchar_t buf[32] = L"";
            ListView_GetItemText(g_hList, i, 0, buf, 32);
            sel.insert(buf);
        }
    }

    std::wstring err;
    if (!QueryVolumes(g_vols, &err))
    {
        AppendLog(L"读取 BitLocker 状态失败：" + err);
        return;
    }

    SendMessageW(g_hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hList);

    wchar_t capBuf[64], pctBuf[32], noteBuf[128];
    for (size_t n = 0; n < g_vols.size(); ++n)
    {
        const VolInfo& v = g_vols[n];
        if (v.capacityGB > 0) swprintf_s(capBuf, L"%.1f GB", v.capacityGB);
        else wcscpy_s(capBuf, L"-");
        swprintf_s(pctBuf, L"%d%%", v.pct);
        wcscpy_s(noteBuf, v.isSystem ? L"系统分区（建议保留加密）" : L"");

        LVITEMW it = { 0 };
        it.mask = LVIF_TEXT;
        it.iItem = (int)n;
        it.pszText = (LPWSTR)v.drive.c_str();
        int idx = ListView_InsertItem(g_hList, &it);
        ListView_SetItemText(g_hList, idx, 1, capBuf);
        ListView_SetItemText(g_hList, idx, 2, pctBuf);
        ListView_SetItemText(g_hList, idx, 3, (LPWSTR)(v.lockStatus == 1 ? L"已锁定" : L"否"));
        ListView_SetItemText(g_hList, idx, 4, (LPWSTR)ConvStatusText(v.convStatus));
        ListView_SetItemText(g_hList, idx, 5, (LPWSTR)ProtStatusText(v.protStatus));
        ListView_SetItemText(g_hList, idx, 6, (LPWSTR)MethodText(v.encMethod));
        ListView_SetItemText(g_hList, idx, 7, noteBuf);

        if (sel.count(v.drive))
            ListView_SetItemState(g_hList, idx, LVIS_SELECTED, LVIS_SELECTED);
    }
    SendMessageW(g_hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hList, nullptr, TRUE);

    // 进度条：统计正在加密/解密的卷的平均百分比
    int sum = 0, nActive = 0;
    for (size_t i = 0; i < g_vols.size(); ++i)
        if (IsActive(g_vols[i].convStatus)) { sum += g_vols[i].pct; ++nActive; }
    if (nActive > 0)
    {
        int avg = sum / nActive;
        SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(g_hProgress, PBM_SETPOS, avg < 5 ? 5 : avg, 0);
        ShowWindow(g_hProgress, SW_SHOW);
    }
    else
    {
        ShowWindow(g_hProgress, SW_HIDE);
    }

    int encrypted = 0;
    for (size_t i = 0; i < g_vols.size(); ++i)
        if (g_vols[i].pct > 0) ++encrypted;
    AppendLog(Fmt(L"状态已刷新：共 %d 个分区，其中 %d 个处于加密状态。",
                  (int)g_vols.size(), encrypted));
}

static bool HasActiveWork()
{
    for (size_t i = 0; i < g_vols.size(); ++i)
        if (IsActive(g_vols[i].convStatus)) return true;
    return false;
}

// ---------------- 恢复密钥解锁 ----------------

// 规范化 48 位恢复密钥：去掉空格/短横线，必须 48 位数字，按 6 位一组加 "-"
static std::wstring NormalizeRecoveryKey(const std::wstring& raw)
{
    std::wstring digits;
    for (size_t i = 0; i < raw.size(); ++i)
        if (iswdigit(raw[i])) digits += raw[i];
    if (digits.size() != 48) return L"";

    std::wstring out;
    for (size_t i = 0; i < digits.size(); ++i)
    {
        out += digits[i];
        if ((i + 1) % 6 == 0 && i + 1 < digits.size()) out += L'-';
    }
    return out;
}

// manage-bde -unlock 分区 -RecoveryPassword 密钥，返回是否成功
static bool RunUnlock(const std::wstring& drive, const std::wstring& key)
{
    std::wstring cmd = L"manage-bde.exe -unlock \"" + drive + L"\" -RecoveryPassword " + key;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

// 解锁输入对话框
static std::wstring g_unlockKey;
static bool g_unlockOk = false;

static LRESULT CALLBACK UnlockWndProc(HWND h, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT f = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND lbl = CreateWindowExW(0, L"STATIC",
            L"该分区已被 BitLocker 锁定，需要输入 48 位恢复密钥解锁。\r\n"
            L"恢复密钥可在微软官网 aka.ms/myrecoverykey 或打印件中查找，\r\n"
            L"可以带短横线（如 123456-123456-...），也可以只输入数字。",
            WS_CHILD | WS_VISIBLE, 14, 12, 380, 60, h, nullptr, nullptr, nullptr);
        SendMessageW(lbl, WM_SETFONT, (WPARAM)f, TRUE);
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            14, 80, 380, 24, h, (HMENU)(INT_PTR)2000, nullptr, nullptr);
        SendMessageW(edit, WM_SETFONT, (WPARAM)f, TRUE);
        SetFocus(edit);
        HWND ok = CreateWindowExW(0, L"BUTTON", L"解锁",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            190, 116, 90, 28, h, (HMENU)(INT_PTR)2001, nullptr, nullptr);
        HWND cancel = CreateWindowExW(0, L"BUTTON", L"取消",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            296, 116, 90, 28, h, (HMENU)(INT_PTR)2002, nullptr, nullptr);
        SendMessageW(ok, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(cancel, WM_SETFONT, (WPARAM)f, TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 2001)
        {
            wchar_t buf[512] = L"";
            GetWindowTextW(GetDlgItem(h, 2000), buf, 512);
            g_unlockKey = NormalizeRecoveryKey(buf);
            if (g_unlockKey.empty())
            {
                MessageBoxW(h, L"恢复密钥应为 48 位数字（短横线可省略），请重新输入。",
                            L"密钥格式错误", MB_ICONWARNING);
                return 0;
            }
            g_unlockOk = true;
            DestroyWindow(h);
        }
        else if (LOWORD(wParam) == 2002)
        {
            DestroyWindow(h);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wParam, lParam);
}

// 弹出模态输入框，返回 true 表示用户确认输入
static bool ShowUnlockDialog(HWND parent, const std::wstring& drive)
{
    static bool registered = false;
    if (!registered)
    {
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.lpfnWndProc = UnlockWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"BitLockerUnlockDlg";
        RegisterClassExW(&wc);
        registered = true;
    }

    RECT rc = { 0, 0, 420, 190 };
    AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BitLockerUnlockDlg",
        (L"输入恢复密钥解锁 " + drive).c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        parent, nullptr, GetModuleHandleW(nullptr), nullptr);

    g_unlockOk = false;
    g_unlockKey.clear();
    EnableWindow(parent, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    return g_unlockOk;
}

// ---------------- 操作 ----------------

static std::wstring JoinDrives(const std::vector<VolInfo>& v)
{
    std::wstring s;
    for (size_t i = 0; i < v.size(); ++i)
    {
        if (i) s += L"、";
        s += v[i].drive;
    }
    return s;
}

// 对单个锁定分区执行"输密钥解锁"，密钥错误时允许重输或跳过
// 返回 true 表示已成功解锁（可纳入解密），false 表示跳过
static bool UnlockOneVolume(const VolInfo& v)
{
    for (;;)
    {
        if (!ShowUnlockDialog(g_hWnd, v.drive))
        {
            AppendLog(Fmt(L"%s 已跳过（未输入密钥）。", v.drive.c_str()));
            return false;
        }
        AppendLog(Fmt(L"正在解锁 %s …", v.drive.c_str()));
        SetCursor(LoadCursorW(nullptr, IDC_WAIT));
        bool ok = RunUnlock(v.drive, g_unlockKey);
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        if (ok)
        {
            AppendLog(Fmt(L"%s 解锁成功，纳入解密。", v.drive.c_str()));
            return true;
        }
        AppendLog(Fmt(L"%s 解锁失败：恢复密钥不正确。", v.drive.c_str()));
        int r = MessageBoxW(g_hWnd,
            Fmt(L"%s 恢复密钥不正确。\r\n\r\n是 = 重新输入密钥\r\n否 = 跳过该分区，继续处理后面的",
                v.drive.c_str()).c_str(),
            L"密钥错误", MB_YESNO | MB_ICONERROR);
        if (r != IDYES)
        {
            AppendLog(Fmt(L"%s 已跳过。", v.drive.c_str()));
            return false;
        }
        // 选"是"则回到循环开头重新弹窗输入
    }
}

static void DoDecryptSelected()
{
    // 收集所有选中的待解密分区（含锁定的，锁定的一会儿先解锁）
    std::vector<VolInfo> normal, locked;
    {
        int i = -1;
        while ((i = ListView_GetNextItem(g_hList, i, LVNI_SELECTED)) >= 0)
        {
            wchar_t buf[32] = L"";
            ListView_GetItemText(g_hList, i, 0, buf, 32);
            for (size_t k = 0; k < g_vols.size(); ++k)
            {
                const VolInfo& v = g_vols[k];
                if (_wcsicmp(v.drive.c_str(), buf) != 0) continue;
                if (v.convStatus == 3 || v.convStatus == 5) continue;   // 已在解密
                if (v.convStatus == 0 && v.pct <= 0) continue;          // 已完全解密
                if (v.lockStatus == 1) locked.push_back(v);
                else normal.push_back(v);
                break;
            }
        }
    }
    if (normal.empty() && locked.empty())
    {
        AppendLog(L"请先在列表中选择要解密的已加密分区。");
        return;
    }

    std::wstring allDrives = JoinDrives(normal);
    if (!locked.empty())
    {
        if (!allDrives.empty()) allDrives += L"、";
        allDrives += JoinDrives(locked);
    }
    std::wstring msg = Fmt(L"确定要解密以下分区吗？\r\n\r\n%s\r\n\r\n解密后数据不再受 BitLocker 保护，过程中请勿断电。",
                           allDrives.c_str());
    if (!locked.empty())
        msg += Fmt(L"\r\n\r\n⚠️ 其中 %s 已锁定，将依次弹窗要求输入 48 位恢复密钥。",
                   JoinDrives(locked).c_str());
    if (MessageBoxW(g_hWnd, msg.c_str(), L"确认解密", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
    {
        AppendLog(L"已取消。");
        return;
    }

    // 逐个解锁锁定的分区
    for (size_t k = 0; k < locked.size(); ++k)
    {
        if (UnlockOneVolume(locked[k]))
        {
            VolInfo v = locked[k];
            v.lockStatus = 0;
            normal.push_back(v);
        }
    }

    if (normal.empty())
    {
        AppendLog(L"没有成功解锁的分区，操作结束。");
        return;
    }
    for (size_t i = 0; i < normal.size(); ++i)
        DecryptVolume(normal[i]);
    Sleep(800);
    RefreshList();
}

static void DoDecryptAllNonSystem()
{
    bool excludeSystem =
        SendMessageW(g_hChkExclude, BM_GETCHECK, 0, 0) == BST_CHECKED;

    wchar_t sysDrive[MAX_PATH] = L"C:";
    GetEnvironmentVariableW(L"SystemDrive", sysDrive, MAX_PATH);

    // 收集所有待解密分区（含锁定的，锁定的一会儿先解锁）
    std::vector<VolInfo> normal, locked;
    for (size_t k = 0; k < g_vols.size(); ++k)
    {
        const VolInfo& v = g_vols[k];
        if (excludeSystem && _wcsicmp(v.drive.c_str(), sysDrive) == 0) continue;
        if (v.convStatus == 3 || v.convStatus == 5) continue;   // 已在解密
        if (v.convStatus == 0 && v.pct <= 0) continue;          // 已完全解密
        if (v.lockStatus == 1) locked.push_back(v);
        else normal.push_back(v);
    }

    if (normal.empty() && locked.empty())
    {
        AppendLog(excludeSystem ? L"没有需要解密的非系统分区。" : L"没有需要解密的分区。");
        return;
    }

    std::wstring allDrives = JoinDrives(normal);
    if (!locked.empty())
    {
        if (!allDrives.empty()) allDrives += L"、";
        allDrives += JoinDrives(locked);
    }
    std::wstring msg = Fmt(L"将一键解密以下分区：\r\n\r\n%s\r\n\r\n", allDrives.c_str());
    if (excludeSystem)
        msg += Fmt(L"（已排除系统盘 %s）\r\n", sysDrive);
    else
        msg += Fmt(L"（包含系统盘 %s，解密后 Windows 的 BitLocker 保护将被完全移除）\r\n", sysDrive);
    if (!locked.empty())
        msg += Fmt(L"\r\n⚠️ 其中 %s 已锁定，将依次弹窗要求输入 48 位恢复密钥，输入正确后自动解锁并继续解密。\r\n",
                   JoinDrives(locked).c_str());
    msg += L"\r\n请确认数据不再需要 BitLocker 保护，过程中请勿断电。";

    if (MessageBoxW(g_hWnd, msg.c_str(), L"一键解密确认", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
    {
        AppendLog(L"已取消。");
        return;
    }

    // 逐个解锁锁定的分区
    for (size_t k = 0; k < locked.size(); ++k)
    {
        if (UnlockOneVolume(locked[k]))
        {
            VolInfo v = locked[k];
            v.lockStatus = 0;
            normal.push_back(v);
        }
    }

    if (normal.empty())
    {
        AppendLog(L"没有成功解锁的分区，一键解密结束。");
        return;
    }

    for (size_t i = 0; i < normal.size(); ++i)
        DecryptVolume(normal[i]);
    Sleep(800);
    RefreshList();
}

// ---------------- 窗口过程 ----------------
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_BTN_REFRESH:
            SetCursor(LoadCursorW(nullptr, IDC_WAIT));
            RefreshList();
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));
            break;
        case ID_BTN_SEL:  DoDecryptSelected(); break;
        case ID_BTN_ALL:  DoDecryptAllNonSystem(); break;
        }
        return 0;

    case WM_CTLCOLORSTATIC:
    {
        // 让 STATIC 文字背景与窗口底色一致（去除底色框）
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(244, 245, 247));
        return (LRESULT)g_hbrBg;
    }

    case WM_TIMER:
        if (wParam == ID_TIMER_AUTO)
        {
            if (SendMessageW(g_hChkAuto, BM_GETCHECK, 0, 0) == BST_CHECKED && HasActiveWork())
                RefreshList();
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static HWND MakeButton(HWND parent, HINSTANCE hInst, int id, const wchar_t* text,
                       int x, int y, int w, int h)
{
    HWND b = CreateWindowExW(0, L"BUTTON", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                             x, y, w, h, parent, (HMENU)(INT_PTR)id, hInst, nullptr);
    SendMessageW(b, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return b;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow)
{
    // 公共控件 v6
    INITCOMMONCONTROLSEX icc = { sizeof(icc),
        ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    // COM
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 1;
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    // 字体
    g_hFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

    // 窗口（固定大小）
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    g_hbrBg = CreateSolidBrush(RGB(244, 245, 247));
    wc.hbrBackground = g_hbrBg;
    wc.lpszClassName = L"BitLockerManagerWnd";
    // 加载内嵌的程序图标（标题栏小图标 + 任务栏/Alt+Tab 大图标）
    wc.hIcon   = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    RegisterClassExW(&wc);

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT rc = { 0, 0, 880, 600 };
    AdjustWindowRect(&rc, style, FALSE);

    g_hWnd = CreateWindowExW(0, wc.lpszClassName,
                             L"BitLocker 分区加密管理工具 v1.0.0 - 浪哩戈浪", style,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             rc.right - rc.left, rc.bottom - rc.top,
                             nullptr, nullptr, hInst, nullptr);

    // 顶部说明（左：功能说明；右上角：作者信息三行）
    g_hLabel = CreateWindowExW(0, L"STATIC",
        L"系统重装后，除系统分区外的分区常保留 BitLocker 预加密状态（资源管理器显示黄色感叹号）。\r\n"
        L"本工具可查看所有分区加密状态，并一键关闭（解密）。解密过程请勿断电、强制关机。",
        WS_CHILD | WS_VISIBLE, 16, 10, 560, 52, g_hWnd, nullptr, hInst, nullptr);
    SendMessageW(g_hLabel, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    g_hAuthor = CreateWindowExW(0, L"STATIC",
        L"作者：浪哩戈浪    版本：1.0.0\r\n"
        L"主页：http://www.itlog.vip\r\n"
        L"抖音：kk31352778",
        WS_CHILD | WS_VISIBLE | SS_RIGHT, 560, 8, 306, 58, g_hWnd, nullptr, hInst, nullptr);
    SendMessageW(g_hAuthor, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    // 按钮
    g_hBtnRefresh = MakeButton(g_hWnd, hInst, ID_BTN_REFRESH, L"刷新状态",           16,  68, 110, 30);
    g_hBtnSel     = MakeButton(g_hWnd, hInst, ID_BTN_SEL,     L"解密所选分区",      134,  68, 130, 30);
    g_hBtnAll     = MakeButton(g_hWnd, hInst, ID_BTN_ALL,     L"一键解密",          272, 68, 120, 30);
    g_hChkExclude = CreateWindowExW(0, L"BUTTON", L"排除系统盘",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                 404, 73, 100, 20, g_hWnd, (HMENU)(INT_PTR)ID_CHK_EXCLUDE, hInst, nullptr);
    SendMessageW(g_hChkExclude, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    SendMessageW(g_hChkExclude, BM_SETCHECK, BST_CHECKED, 0);
    g_hChkAuto = CreateWindowExW(0, L"BUTTON", L"解密中自动刷新(3秒)",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                 520, 73, 170, 20, g_hWnd, (HMENU)(INT_PTR)ID_CHK_AUTO, hInst, nullptr);
    SendMessageW(g_hChkAuto, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    SendMessageW(g_hChkAuto, BM_SETCHECK, BST_CHECKED, 0);

    // 分区列表
    g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
                              16, 106, 850, 356, g_hWnd, (HMENU)(INT_PTR)ID_LIST, hInst, nullptr);
    SendMessageW(g_hList, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    struct { const wchar_t* name; int width; } cols[] = {
        { L"盘符",        55  },
        { L"容量",        80  },
        { L"加密百分比",  95  },
        { L"锁定",        55  },
        { L"卷状态",      105 },
        { L"保护状态",    85  },
        { L"加密方法",    125 },
        { L"备注",        240 },
    };
    LVCOLUMNW col = { 0 };
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
    col.fmt = LVCFMT_LEFT;
    for (int i = 0; i < 8; ++i)
    {
        col.iSubItem = i;
        col.pszText = (LPWSTR)cols[i].name;
        col.cx = cols[i].width;
        ListView_InsertColumn(g_hList, i, &col);
    }

    // 表头文字居中（列表内容保持左对齐）
    {
        HWND hHeader = ListView_GetHeader(g_hList);
        for (int i = 0; i < 8; ++i)
        {
            HDITEMW hdi = { 0 };
            hdi.mask = HDI_FORMAT;
            if (Header_GetItem(hHeader, i, &hdi))
            {
                hdi.fmt |= HDF_CENTER;
                Header_SetItem(hHeader, i, &hdi);
            }
        }
    }

    // 进度条（默认隐藏）
    g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                                  WS_CHILD | PBS_SMOOTH, 16, 470, 850, 10,
                                  g_hWnd, (HMENU)(INT_PTR)ID_PROGRESS, hInst, nullptr);

    // 日志
    g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                             WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                             ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                             16, 486, 850, 100, g_hWnd, (HMENU)(INT_PTR)ID_LOG, hInst, nullptr);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    AppendLog(L"BitLocker 管理工具 v1.0.0 已启动（管理员模式）。");
    AppendLog(L"提示：系统分区一般建议保留加密，其他分区可按需解密。");

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    RefreshList();
    SetTimer(g_hWnd, ID_TIMER_AUTO, 3000, nullptr);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    if (g_svc) g_svc->Release();
    CoUninitialize();
    return 0;
}
