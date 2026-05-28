#include <winsock2.h>
#include <windows.h>
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
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "ws2_32.lib")

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
  std::cout << "  -l, --log-only   Start log server only, skip injection."
            << std::endl;
  std::cout << "  -s, --status     List all processes with ghost_core.dll injected."
            << std::endl;
  std::cout << "  -h, --help, /help, /?  Show this help message." << std::endl;
  std::cout << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  ghost-proxifier.exe -p chrome -u 127.0.0.1:2080 --watch" << std::endl;
  std::cout << "  ghost-proxifier.exe -c ghost.conf --watch" << std::endl;
  std::cout << "  ghost-proxifier.exe -p 5188 -u socks5://127.0.0.1:1080" << std::endl;
  std::cout << "  ghost-proxifier.exe -s" << std::endl;
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

int main(int argc, char *argv[]) {
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  if (argc == 1) {
    PrintHelp();
    return 0;
  }

  std::vector<DWORD> injectedPids;

  std::vector<std::string> targets;
  std::string upstream = "";
  std::string configPath = "ghost.conf";
  bool upstreamFromCli = false;
  bool configFromCli = false;
  bool watchMode = false;
  bool logOnly = false;
  bool statusMode = false;

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
  }

  std::string exeDir = GetExeDir();
  std::string runtimeConfigPath = exeDir + "\\ghost.conf";
  std::string configReadPath = configPath;
  if (!configFromCli && !FileExists(configReadPath) && FileExists(runtimeConfigPath)) {
    configReadPath = runtimeConfigPath;
  }

  LoadInjectorConfigTargets(configReadPath, targets, upstream);

  const char *dllName = "ghost_core.dll";

  if (statusMode) {
    ListInjectedProcesses(dllName);
    return 0;
  }

  // Always start log server
  std::thread(LogServerThread).detach();

  if (logOnly) {
    std::cout << "[Injector] Log-only mode. Listening on port 9999..."
              << std::endl;
    while (true)
      Sleep(10000);
    return 0;
  }

  if (targets.empty()) {
    std::cout << "[Injector] no target process need inject." << std::endl;
    return 0;
  }

  if (upstream.empty()) {
    std::cout << "[Error] Upstream proxy is required. Set -u <addr:port> or proxy=<addr:port> in ghost.conf." << std::endl;
    PrintHelp();
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
            << " Watch: " << (watchMode ? "ON" : "OFF") << std::endl;

  int totalInjected = 0;
  do {
    int currentRoundInjected = 0;
    for (const auto &t : targets) {
      if (IsNumber(t)) {
        DWORD pid = (DWORD)std::stoul(t);
        if (!IsDllLoaded(pid, dllName)) {
          if (Inject(pid, dllName)) {
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
            if (Inject(pe.th32ProcessID, dllName)) {
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
      while (true)
        Sleep(10000);
    }
  } while (watchMode);

  return 0;
}
