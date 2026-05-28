#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <sstream>
#include <cctype>
#include <atomic>
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#include <mutex>
#include <deque>
#include <streambuf>

#pragma comment(lib, "ws2_32.lib")

#define WM_TRAYICON (WM_APP + 1)
#define ID_TRAY_RESTORE 1001
#define ID_TRAY_EXIT 1002
#define ID_LOG_CLEAR 1003
#define ID_LOG_COPY 1004
#define WM_APPEND_LOG (WM_APP + 2)

static HWND g_trayWnd = NULL;
static HWND g_logEdit = NULL;
static NOTIFYICONDATAA g_trayIcon = {};
static bool g_trayEnabled = true;
static std::atomic<bool> g_exitRequested{false};
static WNDPROC g_originalConsoleWndProc = NULL;
static std::mutex g_pendingLogMutex;
static std::deque<std::string> g_pendingLogs;
static std::ofstream g_logFile;
static std::streambuf *g_oldCoutBuf = nullptr;
static std::streambuf *g_oldCerrBuf = nullptr;

bool IsGuiBuild() {
#ifdef GHOST_GUI_BUILD
  return true;
#else
  return false;
#endif
}

void AppendLogToUi(const std::string &text);

class UiLogStreamBuf : public std::streambuf {
 public:
  explicit UiLogStreamBuf(std::streambuf *fallback) : fallback_(fallback) {}
 protected:
  std::streamsize xsputn(const char *s, std::streamsize n) override {
    if (fallback_) fallback_->sputn(s, n);
    AppendLogToUi(std::string(s, static_cast<size_t>(n)));
    return n;
  }
  int overflow(int ch) override {
    if (ch == traits_type::eof()) return traits_type::not_eof(ch);
    char c = static_cast<char>(ch);
    if (fallback_) fallback_->sputc(c);
    AppendLogToUi(std::string(1, c));
    return ch;
  }
  int sync() override {
    if (fallback_) fallback_->pubsync();
    if (g_logFile.is_open()) g_logFile.flush();
    return 0;
  }
 private:
  std::streambuf *fallback_;
};

static UiLogStreamBuf *g_uiCoutBuf = nullptr;
static UiLogStreamBuf *g_uiCerrBuf = nullptr;

void HideConsoleToTray();
void ShowMainWindow();

std::string GetExeDir();

void AppendLogToUi(const std::string &text) {
  if (text.empty()) return;
  if (g_logFile.is_open()) {
    g_logFile << text;
    g_logFile.flush();
  }
  if (!IsGuiBuild()) return;
  std::string *copy = new std::string(text);
  HWND target = g_trayWnd;
  if (target && PostMessageA(target, WM_APPEND_LOG, 0, reinterpret_cast<LPARAM>(copy))) return;
  {
    std::lock_guard<std::mutex> lock(g_pendingLogMutex);
    g_pendingLogs.push_back(*copy);
    while (g_pendingLogs.size() > 2000) g_pendingLogs.pop_front();
  }
  delete copy;
}

void FlushPendingLogsToEdit() {
  if (!g_logEdit) return;
  std::deque<std::string> pending;
  {
    std::lock_guard<std::mutex> lock(g_pendingLogMutex);
    pending.swap(g_pendingLogs);
  }
  for (const auto &text : pending) {
    int len = GetWindowTextLengthA(g_logEdit);
    SendMessageA(g_logEdit, EM_SETSEL, len, len);
    SendMessageA(g_logEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
  }
}

void AppendLogTextToEdit(const std::string &text) {
  if (!g_logEdit) return;
  int len = GetWindowTextLengthA(g_logEdit);
  SendMessageA(g_logEdit, EM_SETSEL, len, len);
  SendMessageA(g_logEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
}

void InstallUiLogCapture() {
  if (!IsGuiBuild() || g_uiCoutBuf) return;
  std::string logPath = GetExeDir() + "\\ghost-proxifier.log";
  g_logFile.open(logPath, std::ios::app | std::ios::binary);
  if (g_logFile.is_open()) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    g_logFile << "\r\n===== Ghost Proxifier started "
              << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
              << st.wHour << ":" << st.wMinute << ":" << st.wSecond
              << " =====\r\n";
  }
  g_oldCoutBuf = std::cout.rdbuf();
  g_oldCerrBuf = std::cerr.rdbuf();
  g_uiCoutBuf = new UiLogStreamBuf(g_oldCoutBuf);
  g_uiCerrBuf = new UiLogStreamBuf(g_oldCerrBuf);
  std::cout.rdbuf(g_uiCoutBuf);
  std::cerr.rdbuf(g_uiCerrBuf);
}

void UninstallUiLogCapture() {
  if (g_oldCoutBuf) std::cout.rdbuf(g_oldCoutBuf);
  if (g_oldCerrBuf) std::cerr.rdbuf(g_oldCerrBuf);
  delete g_uiCoutBuf;
  delete g_uiCerrBuf;
  g_uiCoutBuf = nullptr;
  g_uiCerrBuf = nullptr;
  g_oldCoutBuf = nullptr;
  g_oldCerrBuf = nullptr;
  if (g_logFile.is_open()) g_logFile.close();
}

LRESULT CALLBACK ConsoleWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  if (msg == WM_CLOSE ||
      (msg == WM_SYSCOMMAND && ((wParam & 0xFFF0) == SC_CLOSE))) {
    HideConsoleToTray();
    std::cout << "[Injector] Close button hides to tray. Use tray menu Exit to quit and restore processes." << std::endl;
    return 0;
  }
  return CallWindowProcA(g_originalConsoleWndProc, hwnd, msg, wParam, lParam);
}

void ShowMainWindow() {
  if (IsGuiBuild() && g_trayWnd) {
    ShowWindow(g_trayWnd, SW_SHOW);
    ShowWindow(g_trayWnd, SW_RESTORE);
    SetForegroundWindow(g_trayWnd);
    return;
  }
  HWND console = GetConsoleWindow();
  if (console) {
    ShowWindow(console, SW_SHOW);
    ShowWindow(console, SW_RESTORE);
    SetForegroundWindow(console);
  }
}

void RestoreConsoleFromTray() {
  ShowMainWindow();
}

void HideConsoleToTray() {
  if (IsGuiBuild() && g_trayWnd) {
    ShowWindow(g_trayWnd, SW_HIDE);
    return;
  }
  HWND console = GetConsoleWindow();
  if (console) ShowWindow(console, SW_HIDE);
}

void InstallConsoleCloseToTrayHook() {
  if (!g_trayEnabled || g_originalConsoleWndProc) return;
  HWND console = GetConsoleWindow();
  if (!console) return;
  g_originalConsoleWndProc =
      (WNDPROC)SetWindowLongPtrA(console, GWLP_WNDPROC, (LONG_PTR)ConsoleWndProc);
  if (!g_originalConsoleWndProc) {
    // Console windows are owned by conhost.exe on modern Windows, so subclassing
    // can be denied.  In that case disable the Close command to prevent Windows
    // from force-terminating us without running the restore path.  Minimize and
    // tray Exit remain available.
    HMENU menu = GetSystemMenu(console, FALSE);
    if (menu) {
      DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
      DrawMenuBar(console);
    }
  }
}

void UninstallConsoleCloseToTrayHook() {
  HWND console = GetConsoleWindow();
  if (console && g_originalConsoleWndProc) {
    SetWindowLongPtrA(console, GWLP_WNDPROC, (LONG_PTR)g_originalConsoleWndProc);
    g_originalConsoleWndProc = NULL;
  }
  if (console) GetSystemMenu(console, TRUE);
}

void RemoveTrayIcon() {
  if (g_trayIcon.cbSize) Shell_NotifyIconA(NIM_DELETE, &g_trayIcon);
}

void RequestExit() {
  g_exitRequested.store(true);
  if (g_trayWnd) PostMessageA(g_trayWnd, WM_CLOSE, 0, 0);
  HWND console = GetConsoleWindow();
  if (console) ShowWindow(console, SW_SHOW);
}

BOOL WINAPI ConsoleCtrlHandler(DWORD type) {
  if (type == CTRL_CLOSE_EVENT) {
    HideConsoleToTray();
    std::cout << "[Injector] Close button hides to tray. Use tray menu Exit to quit and restore processes." << std::endl;
    return TRUE;
  }
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
      type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
    RequestExit();
    return TRUE;
  }
  return FALSE;
}

void CopyAllLogText() {
  if (!g_logEdit) return;
  SendMessageA(g_logEdit, EM_SETSEL, 0, -1);
  SendMessageA(g_logEdit, WM_COPY, 0, 0);
  int len = GetWindowTextLengthA(g_logEdit);
  SendMessageA(g_logEdit, EM_SETSEL, len, len);
}

LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
    case WM_CREATE: {
      if (IsGuiBuild()) {
        g_logEdit = CreateWindowExA(
            WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE |
                ES_AUTOVSCROLL | ES_READONLY,
            0, 0, 0, 0, hwnd, NULL, GetModuleHandleA(NULL), NULL);
        if (g_logEdit) {
          SendMessageA(g_logEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
          FlushPendingLogsToEdit();
        }
        AppendLogToUi("[Injector] UI log window ready. Close hides to tray; right-click tray icon -> Exit really quits.\r\n");
      } else {
        SetTimer(hwnd, 1, 500, NULL);
      }
      return 0;
    }
    case WM_SIZE:
      if (g_logEdit) MoveWindow(g_logEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
      if (!IsGuiBuild()) {
        HWND console = GetConsoleWindow();
        if (console && IsIconic(console)) HideConsoleToTray();
      }
      return 0;
    case WM_TIMER: {
      HWND console = GetConsoleWindow();
      if (console && IsIconic(console)) HideConsoleToTray();
      return 0;
    }
    case WM_APPEND_LOG: {
      std::string *text = reinterpret_cast<std::string *>(lParam);
      if (text) {
        AppendLogTextToEdit(*text);
        delete text;
      }
      return 0;
    }
    case WM_TRAYICON:
      if (lParam == WM_LBUTTONDBLCLK) {
        RestoreConsoleFromTray();
      } else if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
        POINT pt;
        GetCursorPos(&pt);
        HMENU menu = CreatePopupMenu();
        AppendMenuA(menu, MF_STRING, ID_TRAY_RESTORE, "Open Logs");
        if (IsGuiBuild()) {
          AppendMenuA(menu, MF_STRING, ID_LOG_COPY, "Copy Logs");
          AppendMenuA(menu, MF_STRING, ID_LOG_CLEAR, "Clear Logs");
        }
        AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(menu, MF_STRING, ID_TRAY_EXIT, "Exit");
        SetForegroundWindow(hwnd);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(menu);
      }
      return 0;
    case WM_COMMAND:
      switch (LOWORD(wParam)) {
        case ID_TRAY_RESTORE:
          RestoreConsoleFromTray();
          return 0;
        case ID_LOG_COPY:
          CopyAllLogText();
          return 0;
        case ID_LOG_CLEAR:
          if (g_logEdit) SetWindowTextA(g_logEdit, "");
          return 0;
        case ID_TRAY_EXIT:
          RequestExit();
          return 0;
      }
      break;
    case WM_CLOSE:
      if (!g_exitRequested.load()) {
        HideConsoleToTray();
        AppendLogToUi("[Injector] Close button hides to tray. Use tray menu Exit to quit and restore processes.\r\n");
        return 0;
      }
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      RemoveTrayIcon();
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcA(hwnd, msg, wParam, lParam);
}

void TrayThread() {
  HINSTANCE hInst = GetModuleHandleA(NULL);
  const char *cls = IsGuiBuild() ? "GhostProxifierLogWindow" : "GhostProxifierTrayWindow";
  WNDCLASSA wc = {};
  wc.lpfnWndProc = TrayWndProc;
  wc.hInstance = hInst;
  wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.lpszClassName = cls;
  RegisterClassA(&wc);

  DWORD style = IsGuiBuild() ? WS_OVERLAPPEDWINDOW : WS_OVERLAPPED;
  int w = IsGuiBuild() ? 900 : 0;
  int h = IsGuiBuild() ? 560 : 0;
  g_trayWnd = CreateWindowExA(0, cls, "Ghost Proxifier Logs", style,
                              CW_USEDEFAULT, CW_USEDEFAULT, w, h,
                              NULL, NULL, hInst, NULL);
  if (!g_trayWnd) return;

  g_trayIcon = {};
  g_trayIcon.cbSize = sizeof(g_trayIcon);
  g_trayIcon.hWnd = g_trayWnd;
  g_trayIcon.uID = 1;
  g_trayIcon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  g_trayIcon.uCallbackMessage = WM_TRAYICON;
  g_trayIcon.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  strcpy_s(g_trayIcon.szTip, "Ghost Proxifier");
  Shell_NotifyIconA(NIM_ADD, &g_trayIcon);

  if (IsGuiBuild()) ShowWindow(g_trayWnd, SW_SHOW);

  MSG m;
  while (GetMessageA(&m, NULL, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageA(&m);
  }
}

void PrintHelp() {
  std::cout << "========================================================="
            << std::endl;
  std::cout << "  Process Proxy Injector & Log Server" << std::endl;
  std::cout << "========================================================="
            << std::endl;
  std::cout << "Usage:" << std::endl;
  std::cout << "  ghost-proxifier.exe [options]" << std::endl;
  std::cout << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -p <name|pid>    Target process to inject (e.g., chrome.exe or 1234)."
            << std::endl;
  std::cout << "                   Can be specified multiple times. With --watch, child processes are also injected."
            << std::endl;
  std::cout
      << "  -u <addr:port>   Set upstream proxy. Supports http://addr:port and socks5://addr:port."
      << std::endl;
  std::cout << "  -c <file>        Read config file (default: ghost.conf)." << std::endl;
  std::cout << "                   Config can define process=, proxy=/socks5=, direct_domain=, direct_ip=." << std::endl;
  std::cout << "  --watch          Keep scanning and inject into new matching processes."
            << std::endl;
  std::cout << "  --no-tray        Disable system tray icon/minimize-to-tray behavior."
            << std::endl;
  std::cout << "  -l, --log-only   Start log server only, skip injection."
            << std::endl;
  std::cout << "  -s, --status     List all processes with ghost_core.dll injected."
            << std::endl;
  std::cout << "  --unload         Unload ghost_core.dll from injected processes and exit."
            << std::endl;
  std::cout << "  -h, --help, /help, /?  Show this help message." << std::endl;
  std::cout << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  ghost-proxifier.exe                         (double-click: ghost.conf + --watch)" << std::endl;
  std::cout << "  ghost-proxifier.exe -p chrome -u 127.0.0.1:2080 --watch" << std::endl;
  std::cout << "  ghost-proxifier.exe -c ghost.conf --watch" << std::endl;
  std::cout << "  ghost-proxifier.exe -p 5188 -u socks5://127.0.0.1:1080" << std::endl;
  std::cout << "  ghost-proxifier.exe -s" << std::endl;
  std::cout << "  ghost-proxifier.exe --unload" << std::endl;
  std::cout << "  ghost-proxifier.exe -l" << std::endl;
  std::cout << "========================================================="
            << std::endl;
}

bool IsDllLoaded(DWORD pid, const char *dllName);

void ListInjectedProcesses(const char *dllName) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    std::cout << "[Error] Failed to create process snapshot." << std::endl;
    return;
  }
  PROCESSENTRY32 pe = {sizeof(pe)};
  int count = 0;
  std::cout << "=========================================================" << std::endl;
  std::cout << "  Injected Processes (ghost_core.dll)" << std::endl;
  std::cout << "=========================================================" << std::endl;
  std::cout << "  PID       Process Name" << std::endl;
  std::cout << "---------------------------------------------------------" << std::endl;
  if (Process32First(snap, &pe)) {
    do {
      if (IsDllLoaded(pe.th32ProcessID, dllName)) {
        std::cout << "  " << pe.th32ProcessID << "\t" << pe.szExeFile << std::endl;
        count++;
      }
    } while (Process32Next(snap, &pe));
  }
  CloseHandle(snap);
  std::cout << "---------------------------------------------------------" << std::endl;
  std::cout << "  Total: " << count << " process(es)" << std::endl;
  std::cout << "=========================================================" << std::endl;
}

// Check if DLL is already loaded
bool IsDllLoaded(DWORD pid, const char *dllName) {
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess)
    return false;
  HMODULE hMods[1024];
  DWORD cbNeeded;
  bool found = false;
  if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      char szModName[MAX_PATH];
      if (GetModuleFileNameExA(hProcess, hMods[i], szModName,
                               sizeof(szModName))) {
        if (strstr(szModName, dllName)) {
          found = true;
          break;
        }
      }
    }
  }
  CloseHandle(hProcess);
  return found;
}

HMODULE FindDllModule(DWORD pid, const char *dllName) {
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess)
    return NULL;
  HMODULE hMods[1024];
  DWORD cbNeeded;
  HMODULE found = NULL;
  if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      char szModName[MAX_PATH];
      if (GetModuleFileNameExA(hProcess, hMods[i], szModName,
                               sizeof(szModName))) {
        if (strstr(szModName, dllName)) {
          found = hMods[i];
          break;
        }
      }
    }
  }
  CloseHandle(hProcess);
  return found;
}

bool Unload(DWORD pid, const char *dllName) {
  HMODULE mod = FindDllModule(pid, dllName);
  if (!mod) return false;
  HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                             PROCESS_VM_OPERATION | PROCESS_VM_READ,
                         FALSE, pid);
  if (!h) return false;
  FARPROC freeLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
  HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)freeLib,
                                mod, 0, NULL);
  if (!t) {
    CloseHandle(h);
    return false;
  }
  WaitForSingleObject(t, 3000);
  DWORD exitCode = 0;
  GetExitCodeThread(t, &exitCode);
  CloseHandle(t);
  CloseHandle(h);
  return exitCode != 0;
}

int UnloadAllInjected(const char *dllName) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32 pe = {sizeof(pe)};
  int count = 0;
  if (Process32First(snap, &pe)) {
    do {
      if (Unload(pe.th32ProcessID, dllName)) {
        std::cout << "[-] Unloaded: " << pe.th32ProcessID << " ("
                  << pe.szExeFile << ")" << std::endl;
        count++;
      }
    } while (Process32Next(snap, &pe));
  }
  CloseHandle(snap);
  return count;
}

struct ExitRestoreGuard {
  const char *dllName;
  bool enabled;
  bool restored;
  ExitRestoreGuard(const char *name) : dllName(name), enabled(false), restored(false) {}
  void Enable() { enabled = true; }
  void RestoreNow() {
    if (!enabled || restored) return;
    restored = true;
    std::cout << "[Injector] Restoring process state by unloading ghost_core.dll..." << std::endl;
    int n = UnloadAllInjected(dllName);
    std::cout << "[Injector] Restored " << n << " process(es)." << std::endl;
  }
  ~ExitRestoreGuard() {
    RestoreNow();
    UninstallConsoleCloseToTrayHook();
    RemoveTrayIcon();
    UninstallUiLogCapture();
  }
};

// TCP Log Server
void LogServerThread() {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
  int opt = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
  sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(9999);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(s, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    return;
  listen(s, 5);
  while (true) {
    SOCKET c = accept(s, NULL, NULL);
    if (c != INVALID_SOCKET) {
      std::thread([c]() {
        char b[4096];
        while (true) {
          int n = recv(c, b, sizeof(b) - 1, 0);
          if (n <= 0)
            break;
          b[n] = 0;
          std::cout << b << std::flush;
        }
        closesocket(c);
      }).detach();
    }
  }
}

// Safe Injection
bool Inject(DWORD pid, const char *dllName) {
  char fullPath[MAX_PATH];
  if (GetFullPathNameA(dllName, MAX_PATH, fullPath, NULL) == 0)
    return false;
  HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!h)
    return false;
  void *m =
      VirtualAllocEx(h, NULL, strlen(fullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
  if (!m) {
    CloseHandle(h);
    return false;
  }
  WriteProcessMemory(h, m, (void *)fullPath, strlen(fullPath) + 1, NULL);
  HANDLE t =
      CreateRemoteThread(h, NULL, 0,
                         (LPTHREAD_START_ROUTINE)GetProcAddress(
                             GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
                         m, 0, NULL);
  if (t) {
    WaitForSingleObject(t, 2000);
    DWORD exitCode = 0;
    GetExitCodeThread(t, &exitCode);
    CloseHandle(t);
    VirtualFreeEx(h, m, 0, MEM_RELEASE);
    CloseHandle(h);
    return exitCode != 0;
  }
  CloseHandle(h);
  return false;
}

bool IsNumber(const std::string &s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}

std::string Trim(const std::string &s) {
  size_t b = 0;
  while (b < s.size() && std::isspace((unsigned char)s[b])) b++;
  size_t e = s.size();
  while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
  return s.substr(b, e - b);
}

std::string ToLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
  return s;
}

void NormalizeAndAddTarget(std::vector<std::string> &targets, std::string target) {
  target = Trim(target);
  if (target.empty()) return;
  if (!IsNumber(target)) {
    std::string lower = ToLower(target);
    if (lower.size() < 4 || lower.substr(lower.size() - 4) != ".exe")
      target += ".exe";
  }
  if (std::find(targets.begin(), targets.end(), target) == targets.end()) targets.push_back(target);
}

void LoadInjectorConfigTargets(const std::string &configPath, std::vector<std::string> &targets, std::string &upstream) {
  std::ifstream f(configPath);
  if (!f.is_open()) return;
  std::string line;
  bool first = true;
  while (std::getline(f, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::string t = Trim(line);
    if (t.empty() || t[0] == '#' || t[0] == ';') continue;
    if (first && t.find('=') == std::string::npos && t.front() != '[') {
      if (upstream.empty()) upstream = t;
      first = false;
      continue;
    }
    first = false;
    if (t.front() == '[' && t.back() == ']') {
      std::string sec = Trim(t.substr(1, t.size() - 2));
      std::string lower = ToLower(sec);
      const std::string prefix = "process:";
      if (lower.rfind(prefix, 0) == 0) NormalizeAndAddTarget(targets, sec.substr(prefix.size()));
      continue;
    }
    size_t eq = t.find('=');
    if (eq == std::string::npos) continue;
    std::string key = ToLower(Trim(t.substr(0, eq)));
    std::string value = Trim(t.substr(eq + 1));
    if ((key == "proxy" || key == "upstream" || key == "http_proxy" || key == "socks5" || key == "socks5_proxy") && upstream.empty()) {
      if ((key == "socks5" || key == "socks5_proxy") && ToLower(value).rfind("socks5://", 0) != 0)
        upstream = "socks5://" + value;
      else
        upstream = value;
    }
    else if (key == "process" || key == "target") {
      std::stringstream ss(value);
      std::string item;
      while (std::getline(ss, item, ',')) NormalizeAndAddTarget(targets, item);
    }
  }
}

bool CopyTextFile(const std::string &src, const std::string &dst) {
  std::ifstream in(src, std::ios::binary);
  if (!in.is_open()) return false;
  std::ofstream out(dst, std::ios::binary);
  if (!out.is_open()) return false;
  out << in.rdbuf();
  return true;
}

std::string GetExeDir() {
  char path[MAX_PATH] = {0};
  GetModuleFileNameA(NULL, path, MAX_PATH);
  std::string p(path);
  size_t last = p.find_last_of("\\/");
  return last == std::string::npos ? "." : p.substr(0, last);
}

bool FileExists(const std::string &path) {
  DWORD attr = GetFileAttributesA(path.c_str());
  return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::string FullPath(const std::string &path) {
  char full[MAX_PATH] = {0};
  if (GetFullPathNameA(path.c_str(), MAX_PATH, full, NULL) == 0) return path;
  return full;
}

void AttachConsoleForCliIfNeeded(int argc) {
  if (argc <= 1 || GetConsoleWindow()) return;
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    FILE *f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
    std::ios::sync_with_stdio(true);
  }
}

int AppMain(int argc, char *argv[]) {
  AttachConsoleForCliIfNeeded(argc);
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  InstallUiLogCapture();

  std::vector<DWORD> injectedPids;

  std::vector<std::string> targets;
  std::string upstream = "";
  std::string configPath = "ghost.conf";
  bool upstreamFromCli = false;
  bool configFromCli = false;
  bool watchMode = false;
  bool logOnly = false;
  bool statusMode = false;
  bool unloadMode = false;
  bool defaultDoubleClickMode = (argc == 1);
  SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0 ||
        strcmp(argv[i], "/help") == 0 ||
        strcmp(argv[i], "/?") == 0 || strcmp(argv[i], "-?") == 0) {
      PrintHelp();
      return 0;
    }
    if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      NormalizeAndAddTarget(targets, argv[++i]);
    }
    else if ((strcmp(argv[i], "-u") == 0 ||
              strcmp(argv[i], "--upstream") == 0) &&
             i + 1 < argc) {
      upstream = argv[++i];
      upstreamFromCli = true;
    }
    else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
      configPath = argv[++i];
      configFromCli = true;
    }
    else if (strcmp(argv[i], "--watch") == 0)
      watchMode = true;
    else if (strcmp(argv[i], "--log-only") == 0 || strcmp(argv[i], "-l") == 0)
      logOnly = true;
    else if (strcmp(argv[i], "--status") == 0 || strcmp(argv[i], "-s") == 0)
      statusMode = true;
    else if (strcmp(argv[i], "--unload") == 0)
      unloadMode = true;
    else if (strcmp(argv[i], "--no-tray") == 0)
      g_trayEnabled = false;
  }

  if (defaultDoubleClickMode) {
    watchMode = true;
  }

  if (g_trayEnabled && !statusMode) {
    std::thread(TrayThread).detach();
    InstallConsoleCloseToTrayHook();
  }

  std::string exeDir = GetExeDir();
  std::string runtimeConfigPath = exeDir + "\\ghost.conf";
  std::string configReadPath = configPath;
  if (!configFromCli && !FileExists(configReadPath) && FileExists(runtimeConfigPath)) {
    configReadPath = runtimeConfigPath;
  }

  LoadInjectorConfigTargets(configReadPath, targets, upstream);

  const char *dllName = "ghost_core.dll";
  std::string dllPath = exeDir + "\\ghost_core.dll";
  ExitRestoreGuard restoreGuard(dllName);

  if (statusMode) {
    ListInjectedProcesses(dllName);
    return 0;
  }

  if (unloadMode) {
    int n = UnloadAllInjected(dllName);
    std::cout << "[Injector] Unloaded ghost_core.dll from " << n << " process(es)." << std::endl;
    return 0;
  }

  restoreGuard.Enable();

  // Always start log server
  std::thread(LogServerThread).detach();

  if (logOnly) {
    std::cout << "[Injector] Log-only mode. Listening on port 9999..."
              << std::endl;
    while (!g_exitRequested.load())
      Sleep(10000);
    return 0;
  }

  if (targets.empty()) {
    std::cout << "[Injector] no target process need inject. Set process= in ghost.conf or use -p <name|pid>." << std::endl;
    if (defaultDoubleClickMode) {
      std::cout << "[Injector] Double-click mode used: " << configReadPath << " + --watch." << std::endl;
      std::cout << "[Injector] Press Ctrl+C or use tray menu Exit to quit." << std::endl;
      while (!g_exitRequested.load()) Sleep(10000);
      return 0;
    }
    return 0;
  }

  if (upstream.empty()) {
    std::cout << "[Error] Upstream proxy is required. Set -u <addr:port> or proxy=<addr:port> in ghost.conf." << std::endl;
    if (!defaultDoubleClickMode) PrintHelp();
    else {
      std::cout << "[Injector] Double-click mode used: " << configReadPath << " + --watch." << std::endl;
      std::cout << "[Injector] Press Ctrl+C or use tray menu Exit to quit." << std::endl;
      while (!g_exitRequested.load()) Sleep(10000);
      return 1;
    }
    return 1;
  }

  if (configFromCli) {
    if (_stricmp(FullPath(configPath).c_str(), FullPath(runtimeConfigPath).c_str()) != 0 &&
        !CopyTextFile(configPath, runtimeConfigPath)) {
      std::cout << "[Error] Failed to copy config file to runtime ghost.conf: " << configPath
                << " -> " << runtimeConfigPath << std::endl;
      return 1;
    }
  } else if (upstreamFromCli) {
    std::ofstream conf(runtimeConfigPath);
    if (conf.is_open()) {
      conf << "proxy=" << upstream << std::endl;
      for (const auto &t : targets) conf << "process=" << t << std::endl;
      conf.close();
    } else {
      std::cout << "[Error] Failed to write runtime ghost.conf: " << runtimeConfigPath << std::endl;
      return 1;
    }
  } else if (FileExists(configReadPath) &&
             _stricmp(FullPath(configReadPath).c_str(), FullPath(runtimeConfigPath).c_str()) != 0) {
    if (!CopyTextFile(configReadPath, runtimeConfigPath)) {
      std::cout << "[Error] Failed to copy config file to runtime ghost.conf: " << configReadPath
                << " -> " << runtimeConfigPath << std::endl;
      return 1;
    }
  }

  std::cout << "[Injector] Ready. Upstream: " << upstream
            << " Targets: " << targets.size()
            << " Config: " << configReadPath
            << " RuntimeConfig: " << runtimeConfigPath
            << " Watch: " << (watchMode ? "ON" : "OFF")
            << " Tray: " << (g_trayEnabled ? "ON" : "OFF") << std::endl;
  if (defaultDoubleClickMode) {
    std::cout << "[Injector] Double-click mode: loaded ghost.conf and enabled --watch automatically." << std::endl;
  }

  int totalInjected = 0;
  do {
    int currentRoundInjected = 0;
    for (const auto &t : targets) {
      if (IsNumber(t)) {
        DWORD pid = (DWORD)std::stoul(t);
        if (!IsDllLoaded(pid, dllName)) {
          if (Inject(pid, dllPath.c_str())) {
            std::cout << "[+] Injected into PID: " << pid << std::endl;
            currentRoundInjected++;
          }
        }
      }
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};
    if (Process32First(snap, &pe)) {
      do {
        bool shouldInject = false;

        // Check if process matches direct target names
        for (const auto &t : targets) {
          if (!IsNumber(t) && _stricmp(pe.szExeFile, t.c_str()) == 0) {
            shouldInject = true;
            break;
          }
        }

        // If watch mode, also check if parent PID was already injected
        if (!shouldInject && watchMode) {
          if (std::find(injectedPids.begin(), injectedPids.end(), pe.th32ParentProcessID) != injectedPids.end()) {
            shouldInject = true;
          }
        }

        if (shouldInject) {
          if (!IsDllLoaded(pe.th32ProcessID, dllName)) {
            if (Inject(pe.th32ProcessID, dllPath.c_str())) {
              std::cout << "[+] Injected: " << pe.th32ProcessID << " ("
                        << pe.szExeFile << ")" << std::endl;
              currentRoundInjected++;
            }
          }
        }
        
        // Always track loaded PIDs for child process tracking
        if (IsDllLoaded(pe.th32ProcessID, dllName)) {
            if (std::find(injectedPids.begin(), injectedPids.end(), pe.th32ProcessID) == injectedPids.end()) {
                 injectedPids.push_back(pe.th32ProcessID);
            }
        }

      } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    totalInjected += currentRoundInjected;

    if (g_exitRequested.load()) {
      break;
    }

    if (watchMode) {
      Sleep(2000);
    } else {
      if (totalInjected > 0) {
        std::cout << "[Info] All targets handled. Listening for logs..."
                  << std::endl;
      } else {
        std::cout << "[Warning] No matching processes found to inject."
                  << std::endl;
        std::cout << "[Info] Waiting for logs from any existing hooks..."
                  << std::endl;
      }
      while (!g_exitRequested.load())
        Sleep(10000);
      break;
    }
  } while (watchMode && !g_exitRequested.load());

  restoreGuard.RestoreNow();

  return 0;
}


int main(int argc, char *argv[]) {
  return AppMain(argc, argv);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
  int argc = 0;
  LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!wargv) return AppMain(0, nullptr);

  std::vector<std::string> args;
  std::vector<char *> argv;
  args.reserve(argc);
  argv.reserve(argc + 1);
  for (int i = 0; i < argc; ++i) {
    int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
    std::string arg;
    if (len > 0) {
      arg.resize(len);
      WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, arg.data(), len, nullptr, nullptr);
      arg.resize(len - 1);
    }
    args.push_back(std::move(arg));
  }
  LocalFree(wargv);
  for (auto &arg : args) argv.push_back(arg.data());
  argv.push_back(nullptr);
  return AppMain(argc, argv.data());
}
