#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <fstream>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#include "MinHook.h"

// --- Typedefs ---
typedef int(WINAPI *connect_t)(SOCKET s, const sockaddr *name, int namelen);
typedef int(WINAPI *WSAConnect_t)(SOCKET s, const sockaddr *name, int namelen,
                                  LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                                  LPQOS lpSQOS, LPQOS lpGQOS);
typedef BOOL(PASCAL *ConnectEx_t)(SOCKET s, const struct sockaddr *name,
                                  int namelen, PVOID lpSendBuffer,
                                  DWORD dwSendDataLength, LPDWORD lpBytesSent,
                                  LPOVERLAPPED lpOverlapped);
typedef int(WINAPI *WSAIoctl_t)(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer,
    LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI *send_t)(SOCKET s, const char *buf, int len, int flags);
typedef int(WINAPI *recv_t)(SOCKET s, char *buf, int len, int flags);
typedef int(WINAPI *WSARecv_t)(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI *sendto_t)(SOCKET s, const char *buf, int len, int flags,
                              const struct sockaddr *to, int tolen);
typedef int(WINAPI *WSASendTo_t)(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr *lpTo,
    int iTolen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI *recvfrom_t)(SOCKET s, char *buf, int len, int flags,
                                struct sockaddr *from, int *fromlen);
typedef int(WINAPI *WSARecvFrom_t)(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom,
    LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int(WINAPI *WSASend_t)(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

typedef INT(WSAAPI *getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef INT(WSAAPI *GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef struct hostent* (WSAAPI *gethostbyname_t)(const char*);

// --- Globals ---
connect_t real_connect = NULL;
WSAConnect_t real_WSAConnect = NULL;
ConnectEx_t real_ConnectEx = NULL;
WSAIoctl_t real_WSAIoctl = NULL;
send_t real_send = NULL;
recv_t real_recv = NULL;
WSARecv_t real_WSARecv = NULL;
sendto_t real_sendto = NULL;
WSASendTo_t real_WSASendTo = NULL;
recvfrom_t real_recvfrom = NULL;
WSARecvFrom_t real_WSARecvFrom = NULL;
WSASend_t real_WSASend = NULL;

getaddrinfo_t real_getaddrinfo = NULL;
GetAddrInfoW_t real_GetAddrInfoW = NULL;
gethostbyname_t real_gethostbyname = NULL;

std::string g_ProxyIP = "127.0.0.1";
int g_ProxyPort = 2080;
enum class ProxyType { Http, Socks5 };
ProxyType g_ProxyType = ProxyType::Http;
enum class DnsMode { Proxy, System };
DnsMode g_DnsMode = DnsMode::Proxy;
enum class Ipv6ConnectMode { Direct, Fail, Proxy };
Ipv6ConnectMode g_Ipv6ConnectMode = Ipv6ConnectMode::Proxy;
bool g_DnsIpv6 = true;
std::string g_DnsServerIP = "8.8.8.8";
int g_DnsServerPort = 53;
const DWORD DNS_SOCKET_TIMEOUT_MS = 2500;

struct DirectIpRule {
  DWORD network; // network byte order
  DWORD mask;    // network byte order
  std::string text;
};

std::vector<std::string> g_DirectDomains;
std::vector<DirectIpRule> g_DirectIpRules;
SOCKET g_DnsProxyUdpSocket = INVALID_SOCKET;
int g_DnsProxyPort = 0;
std::atomic<bool> g_Running{true};

// --- Forward Declarations ---
// --- Domain Reverse Map (Real IP -> Domain) ---
std::unordered_map<DWORD, std::string> g_IpToDomainMap;
std::mutex g_IpMapMutex;

void RecordIpDomainMapping(DWORD net_ip, const std::string& domain) {
    if (domain.empty()) return;
    std::lock_guard<std::mutex> lock(g_IpMapMutex);
    g_IpToDomainMap[net_ip] = domain;
}

bool GetDomainByRealIp(DWORD net_ip, std::string& domain) {
    std::lock_guard<std::mutex> lock(g_IpMapMutex);
    auto it = g_IpToDomainMap.find(net_ip);
    if (it != g_IpToDomainMap.end()) {
        domain = it->second;
        return true;
    }
    return false;
}

void NetLog(const char *format, ...);
bool PerformProxyConnect(SOCKET s, const char *ip_str, int port, int family, const std::string& domain = "");
bool BuildProxySockaddrForSocket(SOCKET s, int socket_family, sockaddr_storage &proxy_addr, int &proxy_len);

// --- Pending Proxy (Lazy Handshake) ---
struct PendingProxy {
    std::string target_ip;
    int target_port;
    int target_family;
    std::string domain;
    std::vector<char> initial_data; // ConnectEx send buffer
};
std::unordered_map<SOCKET, PendingProxy> g_PendingProxySockets;
std::mutex g_PendingMutex;

// Complete deferred proxy handshake before the first socket I/O.
bool CompletePendingHandshake(SOCKET s) {
    PendingProxy pp;
    {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        auto it = g_PendingProxySockets.find(s);
        if (it == g_PendingProxySockets.end()) return true; // no pending
        pp = std::move(it->second);
        g_PendingProxySockets.erase(it);
    }
    // Check if proxy connect is still pending (non-blocking mode)
    // For blocking sockets, connect already completed before we get here
    int err = 0; int errlen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen);
    if (err != 0) {
        // Non-blocking connect might still be in progress, wait for it
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        timeval tv = {5, 0};
        if (select(0, NULL, &wfds, NULL, &tv) <= 0) {
            NetLog("[Proxy] Lazy connect timeout: %s:%d", pp.target_ip.c_str(), pp.target_port);
            return false;
        }
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen);
        if (err != 0) {
            NetLog("[Proxy] Lazy connect failed: %s:%d (err=%d)", pp.target_ip.c_str(), pp.target_port, err);
            return false;
        }
    }
    // Temporarily set blocking for proxy handshake.
    // We cannot reliably query the previous FIONBIO state here, so restore to
    // non-blocking after the handshake; Winsock callers that use overlapped I/O
    // are unaffected, and blocking callers still work for normal send/recv.
    unsigned long m = 0;
    ioctlsocket(s, FIONBIO, &m);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
    bool ok = PerformProxyConnect(s, pp.target_ip.c_str(), pp.target_port, pp.target_family, pp.domain);
    // Send any initial data from ConnectEx
    if (ok && !pp.initial_data.empty()) {
        ok = (real_send(s, pp.initial_data.data(), (int)pp.initial_data.size(), 0) > 0);
    }
    // Restore non-blocking (caller will manage actual mode if needed)
    m = 1;
    ioctlsocket(s, FIONBIO, &m);
    if (ok) {
        NetLog("[Proxy] %s handshake OK: %s:%d | %s", g_ProxyType == ProxyType::Socks5 ? "SOCKS5" : "HTTP", pp.target_ip.c_str(), pp.target_port, pp.domain.c_str());
    } else {
        NetLog("[Proxy] %s handshake FAILED: %s:%d | %s", g_ProxyType == ProxyType::Socks5 ? "SOCKS5" : "HTTP", pp.target_ip.c_str(), pp.target_port, pp.domain.c_str());
    }
    return ok;
}

bool IsKnownDoHServer(const char* ip, int port) {
    (void)port;
    if (strcmp(ip, "8.8.8.8") == 0) return true;
    if (strcmp(ip, "8.8.4.4") == 0) return true;
    if (strcmp(ip, "1.1.1.1") == 0) return true;
    if (strcmp(ip, "1.0.0.1") == 0) return true;
    if (strcmp(ip, "2001:4860:4860::8888") == 0) return true;
    if (strcmp(ip, "2001:4860:4860::8844") == 0) return true;
    if (strcmp(ip, "2606:4700:4700::1111") == 0) return true;
    if (strcmp(ip, "2606:4700:4700::1001") == 0) return true;
    return false;
}

bool ShouldFastFailIpv6Connect(int family, bool is_local) {
    return family == AF_INET6 && !is_local && g_Ipv6ConnectMode == Ipv6ConnectMode::Fail;
}

bool ShouldBlockDohConnect(int family, const char* ip, int port) {
    if (!IsKnownDoHServer(ip, port)) return false;
    if (g_DnsMode == DnsMode::Proxy) return true;
    return family == AF_INET6 && g_Ipv6ConnectMode == Ipv6ConnectMode::Fail;
}

// --- Helpers ---
SOCKET g_LogSocket = INVALID_SOCKET;
std::mutex g_LogMutex;

SOCKET NetLogConnect() {
  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET) return INVALID_SOCKET;
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(9999);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (real_connect && real_connect(s, (sockaddr *)&addr, sizeof(addr)) == 0)
    return s;
  closesocket(s);
  return INVALID_SOCKET;
}

void NetLog(const char *format, ...) {
  char buffer[1024];
  va_list args;
  va_start(args, format);
  vsprintf_s(buffer, format, args);
  va_end(args);
  SYSTEMTIME st;
  GetLocalTime(&st);
  char line[1200];
  int len = sprintf_s(line, "[%02d:%02d:%02d.%03d][%04d] %s\x0a", st.wHour,
                      st.wMinute, st.wSecond, st.wMilliseconds,
                      GetCurrentProcessId(), buffer);
  std::lock_guard<std::mutex> lock(g_LogMutex);
  // Try send, reconnect on failure
  for (int attempt = 0; attempt < 2; attempt++) {
    if (g_LogSocket == INVALID_SOCKET)
      g_LogSocket = NetLogConnect();
    if (g_LogSocket == INVALID_SOCKET) return;
    if (real_send && real_send(g_LogSocket, line, len, 0) > 0)
      return; // success
    // Send failed, connection broken - close and retry
    closesocket(g_LogSocket);
    g_LogSocket = INVALID_SOCKET;
  }
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

bool ParseProxyAddress(const std::string &value, std::string &host, int &port) {
  std::string v = Trim(value);
  if (v.empty()) return false;
  std::string lower = ToLower(v);
  const std::string httpPrefix = "http://";
  const std::string socksPrefix = "socks5://";
  if (lower.rfind(httpPrefix, 0) == 0) {
    g_ProxyType = ProxyType::Http;
    v = Trim(v.substr(httpPrefix.size()));
  } else if (lower.rfind(socksPrefix, 0) == 0) {
    g_ProxyType = ProxyType::Socks5;
    v = Trim(v.substr(socksPrefix.size()));
  }
  size_t pos = v.rfind(':');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= v.size()) return false;
  host = Trim(v.substr(0, pos));
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  std::string portText = Trim(v.substr(pos + 1));
  try {
    int p = std::stoi(portText);
    if (p <= 0 || p > 65535 || host.empty()) return false;
    port = p;
    return true;
  } catch (...) {
    return false;
  }
}

bool ParseHostPort(const std::string &value, std::string &host, int &port) {
  std::string v = Trim(value);
  if (v.empty()) return false;
  size_t pos = v.rfind(':');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= v.size()) return false;
  host = Trim(v.substr(0, pos));
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  try {
    int p = std::stoi(Trim(v.substr(pos + 1)));
    if (p <= 0 || p > 65535 || host.empty()) return false;
    port = p;
    return true;
  } catch (...) {
    return false;
  }
}

bool ParseBool(const std::string &value, bool defaultValue) {
  std::string v = ToLower(Trim(value));
  if (v == "1" || v == "true" || v == "yes" || v == "on" || v == "enable" || v == "enabled") return true;
  if (v == "0" || v == "false" || v == "no" || v == "off" || v == "disable" || v == "disabled") return false;
  return defaultValue;
}

bool IsIpLiteral(const char *value) {
  if (!value || !*value) return false;
  in_addr a4;
  in6_addr a6;
  return inet_pton(AF_INET, value, &a4) == 1 || inet_pton(AF_INET6, value, &a6) == 1;
}

const ADDRINFOA *Ipv4OnlyHintsA(const ADDRINFOA *src, ADDRINFOA &tmp) {
  if (g_DnsIpv6) return src;
  if (src && src->ai_family != AF_UNSPEC) return src;
  memset(&tmp, 0, sizeof(tmp));
  if (src) tmp = *src;
  tmp.ai_family = AF_INET;
  return &tmp;
}

const ADDRINFOW *Ipv4OnlyHintsW(const ADDRINFOW *src, ADDRINFOW &tmp) {
  if (g_DnsIpv6) return src;
  if (src && src->ai_family != AF_UNSPEC) return src;
  memset(&tmp, 0, sizeof(tmp));
  if (src) tmp = *src;
  tmp.ai_family = AF_INET;
  return &tmp;
}

void AddDirectDomain(const std::string &value) {
  std::string v = ToLower(Trim(value));
  if (v.empty()) return;
  if (v.rfind("domain:", 0) == 0) v = Trim(v.substr(7));
  if (v.rfind("*.", 0) == 0) v = v.substr(2);
  if (!v.empty() && v[0] == '.') v = v.substr(1);
  if (!v.empty()) g_DirectDomains.push_back(v);
}

void AddDirectIpRule(const std::string &value) {
  std::string v = ToLower(Trim(value));
  if (v.empty()) return;
  if (v.rfind("ip:", 0) == 0) v = Trim(v.substr(3));
  size_t slash = v.find('/');
  std::string ipText = (slash == std::string::npos) ? v : v.substr(0, slash);
  int prefix = 32;
  if (slash != std::string::npos) {
    try { prefix = std::stoi(v.substr(slash + 1)); } catch (...) { return; }
  }
  if (prefix < 0 || prefix > 32) return;
  in_addr addr;
  if (inet_pton(AF_INET, ipText.c_str(), &addr) != 1) return;
  DWORD hostMask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
  DWORD mask = htonl(hostMask);
  DirectIpRule rule;
  rule.network = addr.s_addr & mask;
  rule.mask = mask;
  rule.text = v;
  g_DirectIpRules.push_back(rule);
}

bool LooksLikeIpOrCidr(const std::string &v) {
  std::string x = v;
  if (x.rfind("ip:", 0) == 0) x = x.substr(3);
  size_t slash = x.find('/');
  if (slash != std::string::npos) x = x.substr(0, slash);
  in_addr addr;
  return inet_pton(AF_INET, Trim(x).c_str(), &addr) == 1;
}

void AddDirectRule(const std::string &value) {
  std::stringstream ss(value);
  std::string item;
  while (std::getline(ss, item, ',')) {
    item = Trim(item);
    if (item.empty()) continue;
    std::string lower = ToLower(item);
    if (lower.rfind("domain:", 0) == 0) AddDirectDomain(item);
    else if (LooksLikeIpOrCidr(lower)) AddDirectIpRule(item);
    else AddDirectDomain(item);
  }
}

bool CurrentProcessMatchesSection(const std::string &sectionName) {
  std::string s = ToLower(Trim(sectionName));
  const std::string prefix = "process:";
  if (s.rfind(prefix, 0) != 0) return false;
  std::string target = Trim(s.substr(prefix.size()));
  if (target.empty()) return false;

  char exePath[MAX_PATH] = {0};
  GetModuleFileNameA(NULL, exePath, MAX_PATH);
  std::string exe = exePath;
  size_t last = exe.find_last_of("\\/");
  if (last != std::string::npos) exe = exe.substr(last + 1);
  exe = ToLower(exe);
  std::string base = exe;
  if (base.size() > 4 && base.substr(base.size() - 4) == ".exe") base = base.substr(0, base.size() - 4);

  DWORD pid = GetCurrentProcessId();
  if (std::all_of(target.begin(), target.end(), [](unsigned char c) { return std::isdigit(c); })) {
    try { return (DWORD)std::stoul(target) == pid; } catch (...) { return false; }
  }
  if (target == exe || target == base) return true;
  if (target.size() > 4 && target.substr(target.size() - 4) == ".exe") return target == exe;
  return false;
}

void ApplyConfigKey(const std::string &key, const std::string &value) {
  std::string k = ToLower(Trim(key));
  std::string v = Trim(value);
  if (k == "proxy" || k == "upstream" || k == "http_proxy" || k == "socks5" || k == "socks5_proxy") {
    if (k == "http_proxy") g_ProxyType = ProxyType::Http;
    if (k == "socks5" || k == "socks5_proxy") g_ProxyType = ProxyType::Socks5;
    std::string host; int port = 0;
    if (ParseProxyAddress(v, host, port)) {
      g_ProxyIP = host;
      g_ProxyPort = port;
    }
  } else if (k == "proxy_type" || k == "type" || k == "protocol") {
    std::string lower = ToLower(v);
    if (lower == "socks5" || lower == "socks") g_ProxyType = ProxyType::Socks5;
    else if (lower == "http" || lower == "http-connect" || lower == "connect") g_ProxyType = ProxyType::Http;
  } else if (k == "direct" || k == "bypass") {
    AddDirectRule(v);
  } else if (k == "direct_domain" || k == "bypass_domain") {
    AddDirectDomain(v);
  } else if (k == "direct_ip" || k == "bypass_ip") {
    AddDirectIpRule(v);
  } else if (k == "dns" || k == "dns_mode" || k == "dns_proxy") {
    std::string lower = ToLower(v);
    if (lower == "off" || lower == "system" || lower == "direct" || lower == "disable" || lower == "disabled") {
      g_DnsMode = DnsMode::System;
    } else if (lower == "on" || lower == "proxy" || lower == "proxied" || lower == "enable" || lower == "enabled") {
      g_DnsMode = DnsMode::Proxy;
    }
  } else if (k == "dns_server" || k == "dns_upstream") {
    std::string host; int port = 0;
    if (ParseHostPort(v, host, port)) {
      g_DnsServerIP = host;
      g_DnsServerPort = port;
    } else if (!v.empty()) {
      g_DnsServerIP = v;
      g_DnsServerPort = 53;
    }
  } else if (k == "dns_ipv6" || k == "ipv6_dns" || k == "dns_aaaa") {
    g_DnsIpv6 = ParseBool(v, g_DnsIpv6);
  } else if (k == "ipv6_connect" || k == "connect_ipv6" || k == "ipv6") {
    std::string lower = ToLower(v);
    if (lower == "direct" || lower == "system" || lower == "bypass") {
      g_Ipv6ConnectMode = Ipv6ConnectMode::Direct;
    } else if (lower == "fail" || lower == "off" || lower == "disable" || lower == "disabled" || lower == "fast_fail" || lower == "fast-fail") {
      g_Ipv6ConnectMode = Ipv6ConnectMode::Fail;
    } else if (lower == "proxy" || lower == "proxied" || lower == "on" || lower == "enable" || lower == "enabled") {
      g_Ipv6ConnectMode = Ipv6ConnectMode::Proxy;
    }
  }
}

void LoadConfig() {
  char path[MAX_PATH];
  GetModuleFileNameA(GetModuleHandleA("ghost_core.dll"), path, MAX_PATH);
  std::string p(path);
  size_t last = p.find_last_of("\\/");
  std::string confPath =
      (last != std::string::npos ? p.substr(0, last) : ".") + "\\ghost.conf";
  std::ifstream f(confPath);
  if (!f.is_open()) return;

  bool legacyFirstLine = true;
  bool inMatchingProcessSection = false;
  bool inGlobalSection = true;
  std::string line;
  while (std::getline(f, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::string trimmed = Trim(line);
    if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') continue;

    // Backward-compatible legacy config: first non-comment line is addr:port.
    if (legacyFirstLine && trimmed.find('=') == std::string::npos && trimmed.front() != '[') {
      std::string host; int port = 0;
      if (ParseProxyAddress(trimmed, host, port)) {
        g_ProxyIP = host;
        g_ProxyPort = port;
      }
      legacyFirstLine = false;
      continue;
    }
    legacyFirstLine = false;

    if (trimmed.front() == '[' && trimmed.back() == ']') {
      std::string sec = trimmed.substr(1, trimmed.size() - 2);
      std::string lowerSec = ToLower(Trim(sec));
      inGlobalSection = (lowerSec == "global" || lowerSec == "default");
      inMatchingProcessSection = CurrentProcessMatchesSection(sec);
      continue;
    }

    size_t eq = trimmed.find('=');
    if (eq == std::string::npos) continue;
    if (inGlobalSection || inMatchingProcessSection) {
      ApplyConfigKey(trimmed.substr(0, eq), trimmed.substr(eq + 1));
    }
  }
}

bool IsDirectDomain(const std::string &domain) {
  std::string d = ToLower(Trim(domain));
  if (!d.empty() && d.back() == '.') d.pop_back();
  if (d.empty()) return false;
  for (const auto &rule : g_DirectDomains) {
    if (d == rule) return true;
    if (d.size() > rule.size() && d.compare(d.size() - rule.size(), rule.size(), rule) == 0 &&
        d[d.size() - rule.size() - 1] == '.') return true;
  }
  return false;
}

bool IsDirectIp(DWORD net_ip) {
  for (const auto &rule : g_DirectIpRules) {
    if ((net_ip & rule.mask) == rule.network) return true;
  }
  return false;
}

bool ShouldDirectConnect(const char *ip, int port, const std::string &domain, int family, bool is_local) {
  if (is_local || port == g_ProxyPort || port == 9999) return true;
  if (family == AF_INET6 && g_Ipv6ConnectMode == Ipv6ConnectMode::Direct) return true;
  if (!domain.empty() && IsDirectDomain(domain)) return true;
  if (family == AF_INET) {
    in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) == 1 && IsDirectIp(addr.s_addr)) return true;
  }
  return false;
}

bool BuildProxySockaddrForSocket(SOCKET s, int socket_family, sockaddr_storage &proxy_addr, int &proxy_len) {
  memset(&proxy_addr, 0, sizeof(proxy_addr));
  proxy_len = 0;

  in_addr a4;
  in6_addr a6;
  bool proxyIsV4 = inet_pton(AF_INET, g_ProxyIP.c_str(), &a4) == 1;
  bool proxyIsV6 = inet_pton(AF_INET6, g_ProxyIP.c_str(), &a6) == 1;

  if (socket_family == AF_INET) {
    if (!proxyIsV4) {
      NetLog("[Proxy] Cannot redirect IPv4 socket to non-IPv4 proxy address: %s", g_ProxyIP.c_str());
      return false;
    }
    sockaddr_in *p = (sockaddr_in *)&proxy_addr;
    p->sin_family = AF_INET;
    p->sin_addr = a4;
    p->sin_port = htons(g_ProxyPort);
    proxy_len = sizeof(sockaddr_in);
    return true;
  }

  if (socket_family == AF_INET6) {
    sockaddr_in6 *p6 = (sockaddr_in6 *)&proxy_addr;
    p6->sin6_family = AF_INET6;
    p6->sin6_port = htons(g_ProxyPort);
    if (proxyIsV6) {
      p6->sin6_addr = a6;
    } else if (proxyIsV4) {
      // AF_INET6 sockets cannot connect to a sockaddr_in.  Use an IPv4-mapped
      // IPv6 loopback/proxy address and explicitly allow dual-stack sockets.
      DWORD off = 0;
      setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof(off));
      memset(&p6->sin6_addr, 0, sizeof(p6->sin6_addr));
      p6->sin6_addr.s6_addr[10] = 0xff;
      p6->sin6_addr.s6_addr[11] = 0xff;
      memcpy(&p6->sin6_addr.s6_addr[12], &a4, 4);
    } else {
      NetLog("[Proxy] Cannot parse proxy address for IPv6 socket redirect: %s", g_ProxyIP.c_str());
      return false;
    }
    proxy_len = sizeof(sockaddr_in6);
    return true;
  }

  return false;
}

void LogDirectConnectIfUseful(const char *api, const char *ip, int port, const std::string &domain, int family, bool is_local) {
  if (family == AF_INET6 && !is_local && g_Ipv6ConnectMode == Ipv6ConnectMode::Direct) {
    NetLog("[hook] %s direct IPv6: %s:%d | %s (ipv6_connect=direct)",
           api, ip, port, domain.c_str());
  }
}

std::string GetDnsName(const char *buf, int &offset, int total_len) {
  std::string name = "";
  int pos = offset;
  int jumps = 0;
  int first_jump = -1;
  while (pos < total_len) {
    unsigned char len = (unsigned char)buf[pos++];
    if (len == 0)
      break;
    if ((len & 0xC0) == 0xC0) {
      if (pos >= total_len)
        break;
      if (first_jump == -1)
        first_jump = pos + 1;
      pos = ((len & 0x3F) << 8) | (unsigned char)buf[pos];
      if (++jumps > 10)
        break;
      continue;
    }
    if (pos + len > total_len)
      break;
    for (int i = 0; i < len; i++)
      name += buf[pos++];
    name += ".";
  }
  offset = (first_jump != -1) ? first_jump : pos;
  return name;
}

bool SyncSend(SOCKET s, const char *buf, int len) {
  int sent = 0;
  while (sent < len) {
    int n = real_send(s, buf + sent, len - sent, 0);
    if (n > 0)
      sent += n;
    else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
      fd_set wfds;
      FD_ZERO(&wfds);
      FD_SET(s, &wfds);
      timeval tv = {5, 0};
      if (select(0, NULL, &wfds, NULL, &tv) <= 0)
        return false;
    } else
      return false;
  }
  return true;
}

bool SyncRecvResponse(SOCKET s, std::string &resp) {
  char buf[1024];
  while (resp.find("\x0d\x0a\x0d\x0a") == std::string::npos) {
    int n = real_recv(s, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      buf[n] = '\0';
      resp += buf;
    } else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(s, &rfds);
      timeval tv = {5, 0};
      if (select(0, &rfds, NULL, NULL, &tv) <= 0)
        return false;
    } else
      return false;
    if (resp.size() > 4096)
      return false;
  }
  return true;
}

bool SyncRecvExact(SOCKET s, char *buf, int len) {
  int got = 0;
  while (got < len) {
    int n = real_recv(s, buf + got, len - got, 0);
    if (n > 0) {
      got += n;
    } else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(s, &rfds);
      timeval tv = {5, 0};
      if (select(0, &rfds, NULL, NULL, &tv) <= 0)
        return false;
    } else {
      return false;
    }
  }
  return true;
}

bool PerformHttpConnect(SOCKET s, const char *ip_str, int port, int family, const std::string& domain) {
  char request[512];
  int req_len = 0;
  
  if (!domain.empty()) {
      req_len = sprintf_s(
                request,
                "CONNECT %s:%d HTTP/1.1\x0d\x0aHost: %s:%d\x0d\x0a\x0d\x0a",
                domain.c_str(), port, domain.c_str(), port);
  } else {
      const char *final_host = (port == 53) ? "8.8.8.8" : ip_str;
      if (family == AF_INET6) {
          req_len = sprintf_s(
                request,
                "CONNECT [%s]:%d HTTP/1.1\x0d\x0aHost: [%s]:%d\x0d\x0a\x0d\x0a",
                final_host, port, final_host, port);
      } else {
          req_len = sprintf_s(
                request,
                "CONNECT %s:%d HTTP/1.1\x0d\x0aHost: %s:%d\x0d\x0a\x0d\x0a",
                final_host, port, final_host, port);
      }
  }

  if (!SyncSend(s, request, req_len))
    return false;
  std::string response;
  if (!SyncRecvResponse(s, response))
    return false;
  if (response.find(" 200 ") != std::string::npos) {
    // 1ms is usually enough for the NekoBox pipeline to switch to blind relay
    return true;
  }
  return false;
}

bool PerformSocks5Connect(SOCKET s, const char *ip_str, int port, int family, const std::string& domain) {
  unsigned char hello[3] = {0x05, 0x01, 0x00}; // SOCKS5, one method, no-auth
  if (!SyncSend(s, (const char*)hello, sizeof(hello)))
    return false;
  unsigned char helloResp[2] = {0};
  if (!SyncRecvExact(s, (char*)helloResp, sizeof(helloResp)))
    return false;
  if (helloResp[0] != 0x05 || helloResp[1] != 0x00)
    return false;

  std::vector<unsigned char> req;
  req.push_back(0x05); // VER
  req.push_back(0x01); // CMD CONNECT
  req.push_back(0x00); // RSV

  if (!domain.empty() && domain.size() <= 255) {
    req.push_back(0x03); // ATYP DOMAINNAME
    req.push_back((unsigned char)domain.size());
    req.insert(req.end(), domain.begin(), domain.end());
  } else if (family == AF_INET6) {
    in6_addr a6;
    if (inet_pton(AF_INET6, ip_str, &a6) != 1)
      return false;
    req.push_back(0x04); // ATYP IPv6
    unsigned char *p = (unsigned char*)&a6;
    req.insert(req.end(), p, p + 16);
  } else {
    in_addr a4;
    const char *final_host = (port == 53) ? "8.8.8.8" : ip_str;
    if (inet_pton(AF_INET, final_host, &a4) != 1)
      return false;
    req.push_back(0x01); // ATYP IPv4
    unsigned char *p = (unsigned char*)&a4;
    req.insert(req.end(), p, p + 4);
  }
  req.push_back((unsigned char)((port >> 8) & 0xFF));
  req.push_back((unsigned char)(port & 0xFF));

  if (!SyncSend(s, (const char*)req.data(), (int)req.size()))
    return false;

  unsigned char head[4] = {0};
  if (!SyncRecvExact(s, (char*)head, sizeof(head)))
    return false;
  if (head[0] != 0x05 || head[1] != 0x00)
    return false;

  int addrLen = 0;
  if (head[3] == 0x01) addrLen = 4;
  else if (head[3] == 0x04) addrLen = 16;
  else if (head[3] == 0x03) {
    unsigned char lenByte = 0;
    if (!SyncRecvExact(s, (char*)&lenByte, 1)) return false;
    addrLen = lenByte;
  } else {
    return false;
  }
  std::vector<char> tail(addrLen + 2);
  return SyncRecvExact(s, tail.data(), (int)tail.size());
}

bool PerformProxyConnect(SOCKET s, const char *ip_str, int port, int family, const std::string& domain) {
  if (g_ProxyType == ProxyType::Socks5)
    return PerformSocks5Connect(s, ip_str, port, family, domain);
  return PerformHttpConnect(s, ip_str, port, family, domain);
}

unsigned short GetDnsQuestionType(const char *buf, int len) {
  if (!buf || len < 16) return 0;
  int off = 12;
  GetDnsName(buf, off, len);
  if (off + 4 > len) return 0;
  return ntohs(*(unsigned short *)(buf + off));
}

void SendDnsNoDataResponse(const char *query, int len, const sockaddr_in &client, int clientLen) {
  if (!query || len < 12 || g_DnsProxyUdpSocket == INVALID_SOCKET) return;
  std::vector<char> resp(query, query + len);
  resp[2] = (char)0x81; // response + recursion desired
  resp[3] = (char)0x80; // recursion available, NOERROR
  resp[6] = resp[7] = 0; // ANCOUNT
  resp[8] = resp[9] = 0; // NSCOUNT
  resp[10] = resp[11] = 0; // ARCOUNT
  real_sendto(g_DnsProxyUdpSocket, resp.data(), (int)resp.size(), 0,
              (const sockaddr *)&client, clientLen);
}

// --- DNS over TCP Worker ---
struct DnsReq {
  sockaddr_in client_addr;
  int client_len;
  char buf[2048];
  int len;
};
DWORD WINAPI DnsWorkerThread(LPVOID param) {
  DnsReq *req = (DnsReq *)param;
  unsigned short qtype = GetDnsQuestionType(req->buf, req->len);
  if (qtype == 28 && !g_DnsIpv6) {
    SendDnsNoDataResponse(req->buf, req->len, req->client_addr, req->client_len);
    NetLog("[DNS] AAAA query answered locally with empty response (dns_ipv6=off)");
    delete req;
    return 0;
  }
  SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_sock == INVALID_SOCKET) {
    delete req;
    return 0;
  }
  setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&DNS_SOCKET_TIMEOUT_MS, sizeof(DNS_SOCKET_TIMEOUT_MS));
  setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&DNS_SOCKET_TIMEOUT_MS, sizeof(DNS_SOCKET_TIMEOUT_MS));
  sockaddr_in p_addr;
  p_addr.sin_family = AF_INET;
  p_addr.sin_addr.s_addr = inet_addr(g_ProxyIP.c_str());
  p_addr.sin_port = htons(g_ProxyPort);
  if (real_connect &&
      real_connect(tcp_sock, (sockaddr *)&p_addr, sizeof(p_addr)) == 0) {
    int opt = 1;
    setsockopt(tcp_sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&opt, sizeof(opt));
    std::string empty_domain = "";
    if (PerformProxyConnect(tcp_sock, g_DnsServerIP.c_str(), g_DnsServerPort, AF_INET, empty_domain)) {
      unsigned short len_n = htons((unsigned short)req->len);
      real_send(tcp_sock, (char *)&len_n, 2, 0);
      real_send(tcp_sock, req->buf, req->len, 0);
      unsigned short rlen_n = 0;
      if (real_recv(tcp_sock, (char *)&rlen_n, 2, 0) == 2) {
        int rlen = ntohs(rlen_n);
        if (rlen > 0 && rlen <= 2048) {
          std::vector<char> resp_buf(rlen);
          int rvd = 0;
          while (rvd < rlen) {
            int c = real_recv(tcp_sock, resp_buf.data() + rvd, rlen - rvd, 0);
            if (c <= 0)
              break;
            rvd += c;
          }
          if (rvd == rlen) {
            real_sendto(g_DnsProxyUdpSocket, resp_buf.data(), rlen, 0,
                        (sockaddr *)&req->client_addr, req->client_len);
            int q_off = 12;
            std::string domain = GetDnsName(req->buf, q_off, req->len);
            std::string ips = "";
            int a_off = 12;
            unsigned short q_cnt =
                ntohs(*(unsigned short *)(resp_buf.data() + 4));
            for (int i = 0; i < q_cnt; i++) {
              GetDnsName(resp_buf.data(), a_off, rlen);
              a_off += 4;
            }
            unsigned short a_cnt =
                ntohs(*(unsigned short *)(resp_buf.data() + 6));
            std::string ipv6s = "";
            for (int i = 0; i < a_cnt; i++) {
              GetDnsName(resp_buf.data(), a_off, rlen);
              unsigned short type =
                  ntohs(*(unsigned short *)(resp_buf.data() + a_off));
              unsigned short dlen =
                  ntohs(*(unsigned short *)(resp_buf.data() + a_off + 8));
              if (type == 1 && dlen == 4 && a_off + 10 + 4 <= rlen) {
                char ip[16];
                unsigned char *p =
                    (unsigned char *)(resp_buf.data() + a_off + 10);
                sprintf_s(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
                if (!ips.empty())
                  ips += ", ";
                ips += ip;
                // Record IP-domain mapping for connect hook
                if (!domain.empty()) {
                  std::string clean_domain = domain;
                  if (!clean_domain.empty() && clean_domain.back() == '.') clean_domain.pop_back();
                  DWORD net_ip;
                  memcpy(&net_ip, p, 4);
                  RecordIpDomainMapping(net_ip, clean_domain);
                }
              } else if (type == 28 && dlen == 16 && a_off + 10 + 16 <= rlen) {
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, resp_buf.data() + a_off + 10, ip6, INET6_ADDRSTRLEN);
                if (!ipv6s.empty()) ipv6s += ", ";
                ipv6s += ip6;
              }
              a_off += 10 + dlen;
            }
            if (!ips.empty())
              NetLog("[DNS] Query: %s -> A: [%s]", domain.c_str(), ips.c_str());
            if (!ipv6s.empty())
              NetLog("[DNS] Query: %s -> AAAA: [%s]", domain.c_str(), ipv6s.c_str());
          }
        }
      }
    }
  }
  closesocket(tcp_sock);
  delete req;
  return 0;
}

DWORD WINAPI DnsProxyThread(LPVOID p) {
  if (g_DnsMode != DnsMode::Proxy) {
    NetLog("[DNS] Local DNS proxy disabled; using system DNS");
    return 0;
  }
  g_DnsProxyUdpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (g_DnsProxyUdpSocket == INVALID_SOCKET)
    return 0;
  sockaddr_in a;
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = inet_addr("127.0.0.1");
  a.sin_port = htons(0);
  bind(g_DnsProxyUdpSocket, (sockaddr *)&a, sizeof(a));
  int l = sizeof(a);
  getsockname(g_DnsProxyUdpSocket, (sockaddr *)&a, &l);
  g_DnsProxyPort = ntohs(a.sin_port);
  NetLog("[DNS] Local Gateway Ready on 127.0.0.1:%d -> %s:%d via %s proxy (dns_ipv6=%s)",
         g_DnsProxyPort, g_DnsServerIP.c_str(), g_DnsServerPort,
         g_ProxyType == ProxyType::Socks5 ? "SOCKS5" : "HTTP",
         g_DnsIpv6 ? "on" : "off");
  char buf[2048];
  sockaddr_in c_addr;
  int c_len = sizeof(c_addr);
  while (g_Running.load()) {
    c_len = sizeof(c_addr);
    int n = real_recvfrom(g_DnsProxyUdpSocket, buf, 2048, 0,
                          (sockaddr *)&c_addr, &c_len);
    if (n > 0) {
      DnsReq *r = new DnsReq();
      r->client_addr = c_addr;
      r->client_len = c_len;
      memcpy(r->buf, buf, n);
      r->len = n;
      CreateThread(NULL, 0, DnsWorkerThread, r, 0, NULL);
    }
  }
  return 0;
}

// --- Proxy DNS Resolution (DNS over TCP through proxy) ---
static std::atomic<unsigned short> g_DnsTxId{1};

// --- DNS Cache ---
struct DnsCacheEntry {
    std::vector<DWORD> ips4;
    std::vector<in6_addr> ips6;
    DWORD expire_tick; // GetTickCount() based
};
std::unordered_map<std::string, DnsCacheEntry> g_DnsCache;
std::mutex g_DnsCacheMutex;
const DWORD DNS_CACHE_TTL_MS = 300 * 1000; // 5 minutes

int BuildDnsQuery(const char* domain, unsigned short qtype, char* buf, int bufSize) {
    if (!domain || bufSize < 512) return 0;
    unsigned short txid = g_DnsTxId.fetch_add(1);
    buf[0] = (txid >> 8) & 0xFF;
    buf[1] = txid & 0xFF;
    buf[2] = 0x01; buf[3] = 0x00; // flags: recursion desired
    buf[4] = 0x00; buf[5] = 0x01; // 1 question
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    int pos = 12;
    const char* p = domain;
    while (*p) {
        const char* dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0) { p++; continue; }
        if (pos + 1 + len >= bufSize) return 0;
        buf[pos++] = (char)len;
        memcpy(buf + pos, p, len);
        pos += len;
        if (dot) p = dot + 1; else break;
    }
    if (pos + 5 > bufSize) return 0;
    buf[pos++] = 0; // end of name
    buf[pos++] = (char)((qtype >> 8) & 0xFF);
    buf[pos++] = (char)(qtype & 0xFF);
    buf[pos++] = 0x00; buf[pos++] = 0x01; // class IN
    return pos;
}

// --- DNS Connection Pool ---
const int DNS_POOL_MAX = 16;
const DWORD DNS_POOL_IDLE_MS = 60 * 1000; // 60s idle timeout

struct DnsPoolConn {
    SOCKET sock;
    DWORD last_used;
};
std::vector<DnsPoolConn> g_DnsPool;
std::mutex g_DnsPoolMutex;

SOCKET CreateDnsConn() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&DNS_SOCKET_TIMEOUT_MS, sizeof(DNS_SOCKET_TIMEOUT_MS));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&DNS_SOCKET_TIMEOUT_MS, sizeof(DNS_SOCKET_TIMEOUT_MS));
    sockaddr_in p_addr;
    p_addr.sin_family = AF_INET;
    p_addr.sin_addr.s_addr = inet_addr(g_ProxyIP.c_str());
    p_addr.sin_port = htons(g_ProxyPort);
    if (!real_connect || real_connect(s, (sockaddr*)&p_addr, sizeof(p_addr)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
    std::string empty;
    if (!PerformProxyConnect(s, g_DnsServerIP.c_str(), g_DnsServerPort, AF_INET, empty)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

SOCKET AcquireDnsConn() {
    std::lock_guard<std::mutex> lock(g_DnsPoolMutex);
    DWORD now = GetTickCount();
    while (!g_DnsPool.empty()) {
        DnsPoolConn conn = g_DnsPool.back();
        g_DnsPool.pop_back();
        if (now - conn.last_used < DNS_POOL_IDLE_MS) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(conn.sock, &rfds);
            timeval tv = {0, 0};
            if (select(0, &rfds, NULL, NULL, &tv) == 0) {
                return conn.sock;
            }
        }
        closesocket(conn.sock);
    }
    return INVALID_SOCKET;
}

void ReleaseDnsConn(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_DnsPoolMutex);
    if ((int)g_DnsPool.size() >= DNS_POOL_MAX) {
        closesocket(s);
        return;
    }
    g_DnsPool.push_back({s, GetTickCount()});
}

struct ProxyDnsResult {
    std::vector<DWORD> ips4;
    std::vector<in6_addr> ips6;
};

// --- DNS Query via Pooled Connection ---
bool DnsQueryOnSocket(SOCKET s, const char* query, int qlen, unsigned short qtype, ProxyDnsResult& results) {
    unsigned short len_n = htons((unsigned short)qlen);
    if (!SyncSend(s, (char*)&len_n, 2) || !SyncSend(s, query, qlen))
        return false;
    unsigned short rlen_n = 0;
    if (real_recv(s, (char*)&rlen_n, 2, 0) != 2)
        return false;
    int rlen = ntohs(rlen_n);
    if (rlen <= 0 || rlen > 4096)
        return false;
    std::vector<char> resp(rlen);
    int rvd = 0;
    while (rvd < rlen) {
        int c = real_recv(s, resp.data() + rvd, rlen - rvd, 0);
        if (c <= 0) return false;
        rvd += c;
    }
    int a_off = 12;
    unsigned short q_cnt = ntohs(*(unsigned short*)(resp.data() + 4));
    for (int i = 0; i < q_cnt && a_off < rlen; i++) {
        GetDnsName(resp.data(), a_off, rlen);
        a_off += 4;
    }
    unsigned short a_cnt = ntohs(*(unsigned short*)(resp.data() + 6));
    for (int i = 0; i < a_cnt && a_off < rlen; i++) {
        GetDnsName(resp.data(), a_off, rlen);
        if (a_off + 10 <= rlen) {
            unsigned short type = ntohs(*(unsigned short*)(resp.data() + a_off));
            unsigned short dlen = ntohs(*(unsigned short*)(resp.data() + a_off + 8));
            if (type == 1 && qtype == 1 && dlen == 4 && a_off + 10 + 4 <= rlen) {
                DWORD ip;
                memcpy(&ip, resp.data() + a_off + 10, 4);
                results.ips4.push_back(ip);
            } else if (type == 28 && qtype == 28 && dlen == 16 && a_off + 10 + 16 <= rlen) {
                in6_addr ip6;
                memcpy(&ip6, resp.data() + a_off + 10, 16);
                results.ips6.push_back(ip6);
            }
            a_off += 10 + dlen;
        } else break;
    }
    return true;
}

ProxyDnsResult ProxyDnsResolveTyped(const char* domain, unsigned short qtype) {
    ProxyDnsResult results;
    if (!domain || g_DnsMode != DnsMode::Proxy) return results;
    if (qtype == 28 && !g_DnsIpv6) return results;
    std::string key = std::string(domain) + "|" + std::to_string(qtype);
    {
        std::lock_guard<std::mutex> lock(g_DnsCacheMutex);
        auto it = g_DnsCache.find(key);
        if (it != g_DnsCache.end() && GetTickCount() < it->second.expire_tick) {
            NetLog("[DNS-Cache] HIT: %s type %u (A:%d AAAA:%d)", domain, qtype,
                   (int)it->second.ips4.size(), (int)it->second.ips6.size());
            results.ips4 = it->second.ips4;
            results.ips6 = it->second.ips6;
            return results;
        }
    }
    char query[512];
    int qlen = BuildDnsQuery(domain, qtype, query, sizeof(query));
    if (qlen == 0) return results;

    SOCKET s = AcquireDnsConn();
    if (s != INVALID_SOCKET) {
        if (DnsQueryOnSocket(s, query, qlen, qtype, results)) {
            ReleaseDnsConn(s);
        } else {
            closesocket(s);
            s = CreateDnsConn();
            if (s != INVALID_SOCKET) {
                if (DnsQueryOnSocket(s, query, qlen, qtype, results))
                    ReleaseDnsConn(s);
                else
                    closesocket(s);
            }
        }
    } else {
        s = CreateDnsConn();
        if (s != INVALID_SOCKET) {
            if (DnsQueryOnSocket(s, query, qlen, qtype, results))
                ReleaseDnsConn(s);
            else
                closesocket(s);
        }
    }

    if (!results.ips4.empty() || !results.ips6.empty()) {
        std::lock_guard<std::mutex> lock(g_DnsCacheMutex);
        g_DnsCache[key] = {results.ips4, results.ips6, GetTickCount() + DNS_CACHE_TTL_MS};
    }
    return results;
}

std::vector<DWORD> ProxyDnsResolve(const char* domain) {
    return ProxyDnsResolveTyped(domain, 1).ips4;
}

std::vector<in6_addr> ProxyDnsResolve6(const char* domain) {
    return ProxyDnsResolveTyped(domain, 28).ips6;
}

// --- Hook Implementations ---
BOOL PASCAL hook_ConnectEx(SOCKET s, const struct sockaddr *name, int namelen,
                           PVOID lpSendBuffer, DWORD dwSendDataLength,
                           LPDWORD lpBytesSent, LPOVERLAPPED lpOverlapped) {
  if (name && (name->sa_family == AF_INET || name->sa_family == AF_INET6)) {
    char ip[INET6_ADDRSTRLEN] = {0};
    int port = 0;
    bool is_local = false;
    std::string domain = "";
    if (name->sa_family == AF_INET) {
      sockaddr_in *t = (sockaddr_in *)name;
      port = ntohs(t->sin_port);
      inet_ntop(AF_INET, &(t->sin_addr), ip, INET_ADDRSTRLEN);
      GetDomainByRealIp(t->sin_addr.s_addr, domain);
      if (t->sin_addr.s_addr == inet_addr("127.0.0.1"))
        is_local = true;
    } else {
      sockaddr_in6 *t = (sockaddr_in6 *)name;
      port = ntohs(t->sin6_port);
      inet_ntop(AF_INET6, &(t->sin6_addr), ip, INET6_ADDRSTRLEN);
      if (strcmp(ip, "::1") == 0)
        is_local = true;
    }
    if (ShouldBlockDohConnect(name->sa_family, ip, port)) {
      NetLog("[hook] Blocking DoH server %s:%d to force DNS fallback", ip, port);
      WSASetLastError(WSAECONNREFUSED);
      return FALSE;
    }
    if (ShouldFastFailIpv6Connect(name->sa_family, is_local)) {
      NetLog("[hook] Fast-fail IPv6 connect: %s:%d (ipv6_connect=fail)", ip, port);
      WSASetLastError(WSAEHOSTUNREACH);
      return FALSE;
    }
    if (!ShouldDirectConnect(ip, port, domain, name->sa_family, is_local)) {
      NetLog("[hook] ConnectEx: %s:%d | %s", ip, port, domain.c_str());
      // Save target info + initial data for deferred handshake
      PendingProxy pp = {ip, port, name->sa_family, domain, {}};
      if (lpSendBuffer && dwSendDataLength > 0) {
        pp.initial_data.assign((char*)lpSendBuffer, (char*)lpSendBuffer + dwSendDataLength);
      }
      {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        g_PendingProxySockets[s] = std::move(pp);
      }
      // Redirect ConnectEx to proxy, suppress initial data (will be sent after handshake)
      sockaddr_storage p;
      int pLen = 0;
      if (!BuildProxySockaddrForSocket(s, name->sa_family, p, pLen)) {
        WSASetLastError(WSAEADDRNOTAVAIL);
        return FALSE;
      }
      return real_ConnectEx(s, (const sockaddr *)&p, pLen, NULL, 0, lpBytesSent, lpOverlapped);
    } else {
      LogDirectConnectIfUseful("ConnectEx", ip, port, domain, name->sa_family, is_local);
    }
  }
  return real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength,
                        lpBytesSent, lpOverlapped);
}

int WINAPI hook_WSAConnect(SOCKET s, const sockaddr *name, int namelen,
                           LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                           LPQOS lpSQOS, LPQOS lpGQOS) {
  if (name && (name->sa_family == AF_INET || name->sa_family == AF_INET6)) {
    char ip[INET6_ADDRSTRLEN] = {0};
    int port = 0;
    bool is_local = false;
    std::string domain = "";
    if (name->sa_family == AF_INET) {
      sockaddr_in *t = (sockaddr_in *)name;
      port = ntohs(t->sin_port);
      inet_ntop(AF_INET, &(t->sin_addr), ip, INET_ADDRSTRLEN);
      GetDomainByRealIp(t->sin_addr.s_addr, domain);
      if (t->sin_addr.s_addr == inet_addr("127.0.0.1"))
        is_local = true;
    } else {
      sockaddr_in6 *t = (sockaddr_in6 *)name;
      port = ntohs(t->sin6_port);
      inet_ntop(AF_INET6, &(t->sin6_addr), ip, INET6_ADDRSTRLEN);
      if (strcmp(ip, "::1") == 0)
        is_local = true;
    }
    if (ShouldBlockDohConnect(name->sa_family, ip, port)) {
      NetLog("[hook] Blocking DoH server %s:%d to force DNS fallback", ip, port);
      WSASetLastError(WSAECONNREFUSED);
      return SOCKET_ERROR;
    }
    if (ShouldFastFailIpv6Connect(name->sa_family, is_local)) {
      NetLog("[hook] Fast-fail IPv6 connect: %s:%d (ipv6_connect=fail)", ip, port);
      WSASetLastError(WSAEHOSTUNREACH);
      return SOCKET_ERROR;
    }
    if (!ShouldDirectConnect(ip, port, domain, name->sa_family, is_local)) {
      NetLog("[hook] WSAConnect: %s:%d | %s", ip, port, domain.c_str());
      // Save target info for deferred HTTP CONNECT handshake
      {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        g_PendingProxySockets[s] = {ip, port, name->sa_family, domain, {}};
      }
      // Redirect connect to proxy (keep original socket blocking mode)
      sockaddr_storage p;
      int pLen = 0;
      if (!BuildProxySockaddrForSocket(s, name->sa_family, p, pLen)) {
        WSASetLastError(WSAEADDRNOTAVAIL);
        return SOCKET_ERROR;
      }
      return real_WSAConnect(s, (const sockaddr *)&p, pLen, NULL, NULL, lpSQOS, lpGQOS);
    } else {
      LogDirectConnectIfUseful("WSAConnect", ip, port, domain, name->sa_family, is_local);
    }
  }
  return real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS,
                         lpGQOS);
}

int WINAPI hook_connect(SOCKET s, const sockaddr *name, int namelen) {
  if (name && (name->sa_family == AF_INET || name->sa_family == AF_INET6)) {
    char ip[INET6_ADDRSTRLEN] = {0};
    int port = 0;
    bool is_local = false;
    std::string domain = "";
    if (name->sa_family == AF_INET) {
      sockaddr_in *t = (sockaddr_in *)name;
      port = ntohs(t->sin_port);
      inet_ntop(AF_INET, &(t->sin_addr), ip, INET_ADDRSTRLEN);
      GetDomainByRealIp(t->sin_addr.s_addr, domain);
      int type = 0;
      int optlen = sizeof(type);
      getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &optlen);
      if (type == SOCK_DGRAM && port == 53 && g_DnsProxyPort > 0) {
        sockaddr_in l = *t;
        l.sin_addr.s_addr = inet_addr("127.0.0.1");
        l.sin_port = htons(g_DnsProxyPort);
        return real_connect(s, (sockaddr *)&l, sizeof(l));
      }
      if (t->sin_addr.s_addr == inet_addr("127.0.0.1"))
        is_local = true;
    } else {
      sockaddr_in6 *t = (sockaddr_in6 *)name;
      port = ntohs(t->sin6_port);
      inet_ntop(AF_INET6, &(t->sin6_addr), ip, INET6_ADDRSTRLEN);
      if (strcmp(ip, "::1") == 0)
        is_local = true;
    }
    if (ShouldBlockDohConnect(name->sa_family, ip, port)) {
      NetLog("[hook] Blocking DoH server %s:%d to force DNS fallback", ip, port);
      WSASetLastError(WSAECONNREFUSED);
      return SOCKET_ERROR;
    }
    if (ShouldFastFailIpv6Connect(name->sa_family, is_local)) {
      NetLog("[hook] Fast-fail IPv6 connect: %s:%d (ipv6_connect=fail)", ip, port);
      WSASetLastError(WSAEHOSTUNREACH);
      return SOCKET_ERROR;
    }
    if (!ShouldDirectConnect(ip, port, domain, name->sa_family, is_local)) {
      NetLog("[hook] connect: %s:%d | %s", ip, port, domain.c_str());
      // Save target info for deferred HTTP CONNECT handshake
      {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        g_PendingProxySockets[s] = {ip, port, name->sa_family, domain, {}};
      }
      // Redirect connect to proxy (keep original socket blocking mode)
      sockaddr_storage p;
      int pLen = 0;
      if (!BuildProxySockaddrForSocket(s, name->sa_family, p, pLen)) {
        WSASetLastError(WSAEADDRNOTAVAIL);
        return SOCKET_ERROR;
      }
      return real_connect(s, (const sockaddr *)&p, pLen);
    } else {
      LogDirectConnectIfUseful("connect", ip, port, domain, name->sa_family, is_local);
    }
  }
  return real_connect(s, name, namelen);
}

// --- Lazy handshake send hooks ---
int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
  if (!CompletePendingHandshake(s)) {
    WSASetLastError(WSAECONNRESET);
    return SOCKET_ERROR;
  }
  return real_send(s, buf, len, flags);
}

int WINAPI hook_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                         LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                         LPWSAOVERLAPPED lpOverlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  if (!CompletePendingHandshake(s)) {
    WSASetLastError(WSAECONNRESET);
    return SOCKET_ERROR;
  }
  return real_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                       dwFlags, lpOverlapped, lpCompletionRoutine);
}


int WINAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
  if (!CompletePendingHandshake(s)) {
    WSASetLastError(WSAECONNRESET);
    return SOCKET_ERROR;
  }
  return real_recv(s, buf, len, flags);
}

int WINAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                        LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                        LPWSAOVERLAPPED lpOverlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  if (!CompletePendingHandshake(s)) {
    WSASetLastError(WSAECONNRESET);
    return SOCKET_ERROR;
  }
  return real_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
                      lpOverlapped, lpCompletionRoutine);
}

int WINAPI hook_sendto(SOCKET s, const char *buf, int len, int flags,
                       const struct sockaddr *to, int tolen) {
  if (to && to->sa_family == AF_INET && g_DnsProxyPort > 0 &&
      ntohs(((sockaddr_in *)to)->sin_port) == 53) {
    sockaddr_in l = *(sockaddr_in *)to;
    l.sin_addr.s_addr = inet_addr("127.0.0.1");
    l.sin_port = htons(g_DnsProxyPort);
    NetLog("[DNS] hook_sendto: Translated to 127.0.0.1:%d", g_DnsProxyPort);
    return real_sendto(s, buf, len, flags, (sockaddr *)&l, sizeof(l));
  }
  return real_sendto(s, buf, len, flags, to, tolen);
}

int WINAPI hook_WSASendTo(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr *lpTo,
    int iTolen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  if (lpTo && lpTo->sa_family == AF_INET && g_DnsProxyPort > 0 &&
      ntohs(((sockaddr_in *)lpTo)->sin_port) == 53) {
    sockaddr_in l = *(sockaddr_in *)lpTo;
    l.sin_addr.s_addr = inet_addr("127.0.0.1");
    l.sin_port = htons(g_DnsProxyPort);
    NetLog("[DNS] hook_WSASendTo: Translated to 127.0.0.1:%d", g_DnsProxyPort);
    return real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                          dwFlags, (sockaddr *)&l, sizeof(l), lpOverlapped,
                          lpCompletionRoutine);
  }
  return real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                        dwFlags, lpTo, iTolen, lpOverlapped,
                        lpCompletionRoutine);
}

int WINAPI hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                         struct sockaddr *from, int *fromlen) {
  int ret = real_recvfrom(s, buf, len, flags, from, fromlen);
  if (ret > 0 && from && fromlen && *fromlen >= sizeof(sockaddr_in)) {
    sockaddr_in *f = (sockaddr_in *)from;
    if (f->sin_family == AF_INET &&
        f->sin_addr.s_addr == inet_addr("127.0.0.1") && g_DnsProxyPort > 0 &&
        ntohs(f->sin_port) == g_DnsProxyPort) {
      f->sin_addr.s_addr = inet_addr("8.8.8.8");
      f->sin_port = htons(53);

      std::string ips = "";
      if (ret >= 12) {
        int a_off = 12;
        unsigned short q_cnt = ntohs(*(unsigned short *)(buf + 4));
        std::string query_domain = "";
        for (int i = 0; i < q_cnt && a_off < ret; i++) {
          std::string d = GetDnsName(buf, a_off, ret);
          if (i == 0) query_domain = d;
          a_off += 4;
        }
        unsigned short a_cnt = ntohs(*(unsigned short *)(buf + 6));
        for (int i = 0; i < a_cnt && a_off < ret; i++) {
          GetDnsName(buf, a_off, ret);
          if (a_off + 10 <= ret) {
            unsigned short type = ntohs(*(unsigned short *)(buf + a_off));
            unsigned short dlen = ntohs(*(unsigned short *)(buf + a_off + 8));
            if (type == 1 && dlen == 4 && a_off + 10 + 4 <= ret) {
              char ip[16];
              unsigned char *p = (unsigned char *)(buf + a_off + 10);
              sprintf_s(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
              if (!ips.empty())
                ips += ", ";
              ips += ip;
              if (!query_domain.empty()) {
                  DWORD net_ip;
                  memcpy(&net_ip, p, 4);
                  RecordIpDomainMapping(net_ip, query_domain);
              }
            }
            a_off += 10 + dlen;
          } else
            break;
        }
      }
      NetLog("[DNS] hook_recvfrom: Translated 127.0.0.1:%d -> 8.8.8.8:53 (len: "
             "%d) A_Records: [%s]",
             g_DnsProxyPort, ret, ips.c_str());
    }
  }
  return ret;
}

int WINAPI hook_WSARecvFrom(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom,
    LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
  int ret = real_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                             lpFlags, lpFrom, lpFromlen, lpOverlapped,
                             lpCompletionRoutine);
  if (ret == 0 && lpFrom && lpFromlen && *lpFromlen >= sizeof(sockaddr_in)) {
    sockaddr_in *f = (sockaddr_in *)lpFrom;
    if (f->sin_family == AF_INET &&
        f->sin_addr.s_addr == inet_addr("127.0.0.1") && g_DnsProxyPort > 0 &&
        ntohs(f->sin_port) == g_DnsProxyPort) {
      f->sin_addr.s_addr = inet_addr("8.8.8.8");
      f->sin_port = htons(53);
      DWORD bytes = lpNumberOfBytesRecvd ? *lpNumberOfBytesRecvd : 0;

      std::string ips = "";
      if (bytes >= 12 && dwBufferCount > 0 && lpBuffers[0].buf) {
        char *buf = lpBuffers[0].buf;
        int a_off = 12;
        unsigned short q_cnt = ntohs(*(unsigned short *)(buf + 4));
        std::string query_domain = "";
        for (int i = 0; i < q_cnt && a_off < bytes; i++) {
          std::string d = GetDnsName(buf, a_off, bytes);
          if (i == 0) query_domain = d;
          a_off += 4;
        }
        unsigned short a_cnt = ntohs(*(unsigned short *)(buf + 6));
        for (int i = 0; i < a_cnt && a_off < bytes; i++) {
          GetDnsName(buf, a_off, bytes);
          if (a_off + 10 <= bytes) {
            unsigned short type = ntohs(*(unsigned short *)(buf + a_off));
            unsigned short dlen = ntohs(*(unsigned short *)(buf + a_off + 8));
            if (type == 1 && dlen == 4 && a_off + 10 + 4 <= bytes) {
              char ip[16];
              unsigned char *p = (unsigned char *)(buf + a_off + 10);
              sprintf_s(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
              if (!ips.empty())
                ips += ", ";
              ips += ip;
              if (!query_domain.empty()) {
                  DWORD net_ip;
                  memcpy(&net_ip, p, 4);
                  RecordIpDomainMapping(net_ip, query_domain);
              }
            }
            a_off += 10 + dlen;
          } else
            break;
        }
      }
      NetLog("[DNS] hook_WSARecvFrom: Translated 127.0.0.1:%d -> 8.8.8.8:53 "
             "(len: %d) A_Records: [%s]",
             g_DnsProxyPort, bytes, ips.c_str());
    }
  }
  return ret;
}

INT WSAAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult) {
    // If not a domain name (NULL or already an IP), pass through
    if (!pNodeName || IsIpLiteral(pNodeName)) {
        return real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }
    std::string domain = pNodeName;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    if (!g_DnsIpv6 && pHints && pHints->ai_family == AF_INET6) {
        NetLog("[DNS] getaddrinfo: fast-fail IPv6/AAAA for %s (dns_ipv6=off)", domain.c_str());
        return EAI_NONAME;
    }
    ADDRINFOA ipv4Hints;
    const ADDRINFOA *effectiveHints = Ipv4OnlyHintsA(pHints, ipv4Hints);
    if (g_DnsMode == DnsMode::System) {
        NetLog("[DNS] getaddrinfo: %s uses system DNS (dns=system)", domain.c_str());
        INT ret = real_getaddrinfo(pNodeName, pServiceName, effectiveHints, ppResult);
        if (ret == 0 && ppResult && *ppResult) {
            for (ADDRINFOA *ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
                if (ptr->ai_family == AF_INET) {
                    sockaddr_in *ipv4 = (sockaddr_in *)ptr->ai_addr;
                    RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
                }
            }
        }
        return ret;
    }
    if (IsDirectDomain(domain)) {
        NetLog("[Direct] getaddrinfo: %s uses system DNS", domain.c_str());
        INT ret = real_getaddrinfo(pNodeName, pServiceName, effectiveHints, ppResult);
        if (ret == 0 && ppResult && *ppResult) {
            for (ADDRINFOA *ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
                if (ptr->ai_family == AF_INET) {
                    sockaddr_in *ipv4 = (sockaddr_in *)ptr->ai_addr;
                    RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
                }
            }
        }
        return ret;
    }
    int requestedFamily = pHints ? pHints->ai_family : AF_UNSPEC;
    if (requestedFamily == AF_INET6) {
        std::vector<in6_addr> ips6 = ProxyDnsResolve6(domain.c_str());
        if (!ips6.empty()) {
            char ip6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ips6[0], ip6_str, INET6_ADDRSTRLEN);
            std::string all_ips;
            for (const auto &ip6 : ips6) {
                char s[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6, s, INET6_ADDRSTRLEN);
                if (!all_ips.empty()) all_ips += ", ";
                all_ips += s;
            }
            NetLog("[DNS-Proxy] getaddrinfo AAAA: %s -> [%s] (%d IPs)", domain.c_str(), all_ips.c_str(), (int)ips6.size());
            return real_getaddrinfo(ip6_str, pServiceName, effectiveHints, ppResult);
        }
    }
    std::vector<DWORD> ips = ProxyDnsResolve(domain.c_str());
    if (!ips.empty()) {
        // Use first resolved IP to call real function (no actual DNS happens)
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        NetLog("[DNS-Proxy] getaddrinfo: %s -> [%s] (%d IPs)", domain.c_str(), all_ips.c_str(), (int)ips.size());
        return real_getaddrinfo(ip_str, pServiceName, effectiveHints, ppResult);
    }
    // Fallback to system resolver if proxy DNS fails
    NetLog("[DNS-Proxy] getaddrinfo: proxy DNS failed for %s, fallback", pNodeName);
    INT ret = real_getaddrinfo(pNodeName, pServiceName, effectiveHints, ppResult);
    if (ret == 0 && ppResult && *ppResult) {
        for (ADDRINFOA *ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                sockaddr_in *ipv4 = (sockaddr_in *)ptr->ai_addr;
                RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
            }
        }
    }
    return ret;
}

INT WSAAPI hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW *pHints, PADDRINFOW *ppResult) {
    if (!pNodeName) {
        return real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    char ascii_node[1024] = {0};
    WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1, ascii_node, sizeof(ascii_node), NULL, NULL);
    // If already an IP address, pass through
    if (IsIpLiteral(ascii_node)) {
        return real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    std::string domain = ascii_node;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    if (!g_DnsIpv6 && pHints && pHints->ai_family == AF_INET6) {
        NetLog("[DNS] GetAddrInfoW: fast-fail IPv6/AAAA for %s (dns_ipv6=off)", domain.c_str());
        return EAI_NONAME;
    }
    ADDRINFOW ipv4Hints;
    const ADDRINFOW *effectiveHints = Ipv4OnlyHintsW(pHints, ipv4Hints);
    if (g_DnsMode == DnsMode::System) {
        NetLog("[DNS] GetAddrInfoW: %s uses system DNS (dns=system)", domain.c_str());
        INT ret = real_GetAddrInfoW(pNodeName, pServiceName, effectiveHints, ppResult);
        if (ret == 0 && ppResult && *ppResult) {
            for (ADDRINFOW *ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
                if (ptr->ai_family == AF_INET) {
                    sockaddr_in *ipv4 = (sockaddr_in *)ptr->ai_addr;
                    RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
                }
            }
        }
        return ret;
    }
    if (IsDirectDomain(domain)) {
        NetLog("[Direct] GetAddrInfoW: %s uses system DNS", domain.c_str());
        INT ret = real_GetAddrInfoW(pNodeName, pServiceName, effectiveHints, ppResult);
        if (ret == 0 && ppResult && *ppResult) {
            for (ADDRINFOW *ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
                if (ptr->ai_family == AF_INET) {
                    sockaddr_in *ipv4 = (sockaddr_in *)ptr->ai_addr;
                    RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
                }
            }
        }
        return ret;
    }
    int requestedFamily = pHints ? pHints->ai_family : AF_UNSPEC;
    if (requestedFamily == AF_INET6) {
        std::vector<in6_addr> ips6 = ProxyDnsResolve6(domain.c_str());
        if (!ips6.empty()) {
            char ip6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ips6[0], ip6_str, INET6_ADDRSTRLEN);
            std::string all_ips;
            for (const auto &ip6 : ips6) {
                char s[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6, s, INET6_ADDRSTRLEN);
                if (!all_ips.empty()) all_ips += ", ";
                all_ips += s;
            }
            NetLog("[DNS-Proxy] GetAddrInfoW AAAA: %s -> [%s] (%d IPs)", domain.c_str(), all_ips.c_str(), (int)ips6.size());
            wchar_t wip6[INET6_ADDRSTRLEN];
            MultiByteToWideChar(CP_UTF8, 0, ip6_str, -1, wip6, INET6_ADDRSTRLEN);
            return real_GetAddrInfoW(wip6, pServiceName, effectiveHints, ppResult);
        }
    }
    std::vector<DWORD> ips = ProxyDnsResolve(domain.c_str());
    if (!ips.empty()) {
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        NetLog("[DNS-Proxy] GetAddrInfoW: %s -> [%s] (%d IPs)", domain.c_str(), all_ips.c_str(), (int)ips.size());
        // Convert IP string to wide and call real function
        wchar_t wip[INET_ADDRSTRLEN];
        MultiByteToWideChar(CP_UTF8, 0, ip_str, -1, wip, INET_ADDRSTRLEN);
        return real_GetAddrInfoW(wip, pServiceName, effectiveHints, ppResult);
    }
    // Fallback to system resolver
    NetLog("[DNS-Proxy] GetAddrInfoW: proxy DNS failed for %s, fallback", ascii_node);
    INT ret = real_GetAddrInfoW(pNodeName, pServiceName, effectiveHints, ppResult);
    if (ret == 0 && ppResult && *ppResult) {
        for (ADDRINFOW *ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                sockaddr_in *ipv4 = (sockaddr_in *)ptr->ai_addr;
                RecordIpDomainMapping(ipv4->sin_addr.s_addr, domain);
            }
        }
    }
    return ret;
}

struct hostent* WSAAPI hook_gethostbyname(const char *name) {
    if (!name || inet_addr(name) != INADDR_NONE) {
        return real_gethostbyname(name);
    }
    std::string domain = name;
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    if (g_DnsMode == DnsMode::System) {
        NetLog("[DNS] gethostbyname: %s uses system DNS (dns=system)", domain.c_str());
        struct hostent* ret = real_gethostbyname(name);
        if (ret) {
            for (int i = 0; ret->h_addr_list[i] != 0; ++i) {
                struct in_addr addr;
                memcpy(&addr, ret->h_addr_list[i], sizeof(struct in_addr));
                RecordIpDomainMapping(addr.s_addr, domain);
            }
        }
        return ret;
    }
    if (IsDirectDomain(domain)) {
        NetLog("[Direct] gethostbyname: %s uses system DNS", domain.c_str());
        struct hostent* ret = real_gethostbyname(name);
        if (ret) {
            for (int i = 0; ret->h_addr_list[i] != 0; ++i) {
                struct in_addr addr;
                memcpy(&addr, ret->h_addr_list[i], sizeof(struct in_addr));
                RecordIpDomainMapping(addr.s_addr, domain);
            }
        }
        return ret;
    }
    std::vector<DWORD> ips = ProxyDnsResolve(domain.c_str());
    if (!ips.empty()) {
        // Record all IP-domain mappings
        std::string all_ips;
        for (DWORD ip : ips) {
            RecordIpDomainMapping(ip, domain);
            struct in_addr a; a.s_addr = ip;
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, s, INET_ADDRSTRLEN);
            if (!all_ips.empty()) all_ips += ", ";
            all_ips += s;
        }
        NetLog("[DNS-Proxy] gethostbyname: %s -> [%s] (%d IPs)", domain.c_str(), all_ips.c_str(), (int)ips.size());
        // Call real function with IP string to get properly allocated hostent
        struct in_addr first_addr;
        first_addr.s_addr = ips[0];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &first_addr, ip_str, INET_ADDRSTRLEN);
        return real_gethostbyname(ip_str);
    }
    // Fallback to system resolver
    NetLog("[DNS-Proxy] gethostbyname: proxy DNS failed for %s, fallback", name);
    struct hostent* ret = real_gethostbyname(name);
    if (ret) {
        for (int i = 0; ret->h_addr_list[i] != 0; ++i) {
            struct in_addr addr;
            memcpy(&addr, ret->h_addr_list[i], sizeof(struct in_addr));
            RecordIpDomainMapping(addr.s_addr, domain);
        }
    }
    return ret;
}

DWORD WINAPI SetupThread(LPVOID lpParam) {
  __try {
  LoadConfig();
  MH_Initialize();
  HMODULE h = GetModuleHandleA("ws2_32.dll");
  real_send = (send_t)GetProcAddress(h, "send");
  real_recv = (recv_t)GetProcAddress(h, "recv");
  real_sendto = (sendto_t)GetProcAddress(h, "sendto");
  real_WSASendTo = (WSASendTo_t)GetProcAddress(h, "WSASendTo");
  real_recvfrom = (recvfrom_t)GetProcAddress(h, "recvfrom");
  real_WSARecvFrom = (WSARecvFrom_t)GetProcAddress(h, "WSARecvFrom");
  real_connect = (connect_t)GetProcAddress(h, "connect");
  MH_CreateHook((void *)real_connect, (void *)hook_connect,
                (void **)&real_connect);
  real_WSAConnect = (WSAConnect_t)GetProcAddress(h, "WSAConnect");
  if (real_WSAConnect)
    MH_CreateHook((void *)real_WSAConnect, (void *)hook_WSAConnect,
                  (void **)&real_WSAConnect);
  real_getaddrinfo = (getaddrinfo_t)GetProcAddress(h, "getaddrinfo");
  if (real_getaddrinfo) MH_CreateHook((void *)real_getaddrinfo, (void *)hook_getaddrinfo, (void **)&real_getaddrinfo);
  
  real_GetAddrInfoW = (GetAddrInfoW_t)GetProcAddress(h, "GetAddrInfoW");
  if (real_GetAddrInfoW) MH_CreateHook((void *)real_GetAddrInfoW, (void *)hook_GetAddrInfoW, (void **)&real_GetAddrInfoW);
  
  real_gethostbyname = (gethostbyname_t)GetProcAddress(h, "gethostbyname");
  if (real_gethostbyname) MH_CreateHook((void *)real_gethostbyname, (void *)hook_gethostbyname, (void **)&real_gethostbyname);

  SOCKET d = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  GUID g = WSAID_CONNECTEX;
  DWORD b = 0;
  ConnectEx_t pCE = NULL;
  if (WSAIoctl(d, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &pCE,
               sizeof(pCE), &b, NULL, NULL) == 0) {
    if (pCE)
      MH_CreateHook((void *)pCE, (void *)hook_ConnectEx,
                    (void **)&real_ConnectEx);
  }
  closesocket(d);
  // Hook send/WSASend for lazy proxy handshake
  MH_CreateHook((void *)real_send, (void *)hook_send, (void **)&real_send);
  if (real_recv)
    MH_CreateHook((void *)real_recv, (void *)hook_recv, (void **)&real_recv);
  real_WSARecv = (WSARecv_t)GetProcAddress(h, "WSARecv");
  if (real_WSARecv)
    MH_CreateHook((void *)real_WSARecv, (void *)hook_WSARecv, (void **)&real_WSARecv);
  real_WSASend = (WSASend_t)GetProcAddress(h, "WSASend");
  if (real_WSASend)
    MH_CreateHook((void *)real_WSASend, (void *)hook_WSASend, (void **)&real_WSASend);
  MH_CreateHook((void *)real_sendto, (void *)hook_sendto,
                (void **)&real_sendto);
  MH_CreateHook((void *)real_WSASendTo, (void *)hook_WSASendTo,
                (void **)&real_WSASendTo);
  if (real_recvfrom)
    MH_CreateHook((void *)real_recvfrom, (void *)hook_recvfrom,
                  (void **)&real_recvfrom);
  if (real_WSARecvFrom)
    MH_CreateHook((void *)real_WSARecvFrom, (void *)hook_WSARecvFrom,
                  (void **)&real_WSARecvFrom);
  if (g_DnsMode == DnsMode::Proxy)
    CreateThread(NULL, 0, DnsProxyThread, NULL, 0, NULL);
  MH_EnableHook(MH_ALL_HOOKS);
  const char *ipv6ConnectMode = g_Ipv6ConnectMode == Ipv6ConnectMode::Direct ? "direct" :
                                (g_Ipv6ConnectMode == Ipv6ConnectMode::Fail ? "fail" : "proxy");
  NetLog("[Init] Hooks installed successfully (PID: %d, proxy: %s://%s:%d, dns: %s, dns_server: %s:%d, dns_ipv6: %s, ipv6_connect: %s, direct domains: %d, direct IP rules: %d)",
         GetCurrentProcessId(), g_ProxyType == ProxyType::Socks5 ? "socks5" : "http",
         g_ProxyIP.c_str(), g_ProxyPort, g_DnsMode == DnsMode::Proxy ? "proxy" : "system",
         g_DnsServerIP.c_str(), g_DnsServerPort, g_DnsIpv6 ? "on" : "off", ipv6ConnectMode,
         (int)g_DirectDomains.size(), (int)g_DirectIpRules.size());
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    // Silently absorb any crash during initialization
    // This prevents crashing the host process (e.g., Chrome Network Service)
  }
  return 0;
}

DWORD WINAPI CleanupThread(LPVOID lpParam) {
  g_Running.store(false);
  MH_DisableHook(MH_ALL_HOOKS);
  MH_Uninitialize();
  if (g_DnsProxyUdpSocket != INVALID_SOCKET) {
    closesocket(g_DnsProxyUdpSocket);
    g_DnsProxyUdpSocket = INVALID_SOCKET;
    g_DnsProxyPort = 0;
  }
  {
    std::lock_guard<std::mutex> lock(g_DnsPoolMutex);
    for (auto &conn : g_DnsPool) closesocket(conn.sock);
    g_DnsPool.clear();
  }
  if (g_LogSocket != INVALID_SOCKET) {
    closesocket(g_LogSocket);
    g_LogSocket = INVALID_SOCKET;
  }
  return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    CreateThread(NULL, 0, SetupThread, NULL, 0, NULL);
  } else if (reason == DLL_PROCESS_DETACH) {
    CleanupThread(NULL);
  }
  return TRUE;
}
