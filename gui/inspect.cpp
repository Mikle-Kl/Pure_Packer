#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>

#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

// ============================================================
// PurePacker format
// ============================================================

static const DWORD FORMAT_VERSION = 1;

static const unsigned char MAGIC[8] =
{
    'P', 'U', 'R', 'E',
    'P', 'K', '0', '2'
};

#pragma pack(push, 1)

struct PayloadHeader
{
    unsigned char magic[8];
    DWORD version;
    DWORD stubSize;
    DWORD originalSize;
    DWORD compressedSize;
    unsigned char sha256[32];
};

#pragma pack(pop)

static_assert(
    sizeof(PayloadHeader) == 56,
    "Invalid PayloadHeader size"
);

// ============================================================
// GUI
// ============================================================

#define IDC_FILE       1001
#define IDC_BROWSE     1002
#define IDC_INSPECT    1003
#define IDC_INFO       1004
#define IDC_STATUS     1005

static HFONT gTitleFont = NULL;
static HFONT gButtonFont = NULL;
static HFONT gDefaultFont = NULL;

// ============================================================
// Helpers
// ============================================================

static std::wstring FormatBytes(uint64_t bytes)
{
    std::wstringstream ss;

    if (bytes >= 1024ULL * 1024ULL * 1024ULL)
    {
        double gb = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
        ss << std::fixed << std::setprecision(2) << gb << L" GB";
    }
    else if (bytes >= 1024ULL * 1024ULL)
    {
        double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
        ss << std::fixed << std::setprecision(2) << mb << L" MB";
    }
    else if (bytes >= 1024ULL)
    {
        double kb = static_cast<double>(bytes) / 1024.0;
        ss << std::fixed << std::setprecision(2) << kb << L" KB";
    }
    else
    {
        ss << bytes << L" bytes";
    }

    return ss.str();
}

static std::wstring ToHex(const unsigned char* data, size_t size)
{
    std::wstringstream ss;
    for (size_t i = 0; i < size; ++i)
    {
        ss << std::uppercase << std::hex
           << std::setw(2) << std::setfill(L'0')
           << static_cast<int>(data[i]);
    }
    return ss.str();
}

static bool CheckMagic(const unsigned char* magic)
{
    for (int i = 0; i < 8; ++i)
    {
        if (magic[i] != MAGIC[i])
            return false;
    }
    return true;
}

// ============================================================
// PE architecture
// ============================================================

static std::wstring DetectPEArchitecture(const std::wstring& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return L"Failed to open file";

    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));

    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return L"Unknown format";

    if (dos.e_lfanew <= 0)
        return L"Unknown format";

    file.seekg(dos.e_lfanew, std::ios::beg);

    DWORD signature = 0;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));

    if (!file || signature != IMAGE_NT_SIGNATURE)
        return L"Unknown PE";

    IMAGE_FILE_HEADER fileHeader{};
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    if (!file)
        return L"Unknown PE";

    if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        return L"PE32 (x86)";

    if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return L"PE64 (x64)";

    return L"Unknown architecture";
}

// ============================================================
// Read header
// ============================================================

static bool ReadPayloadHeader(const std::wstring& path, PayloadHeader& header,
                              uint64_t& fileSize, std::wstring& error)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        error = L"Failed to open file.";
        return false;
    }

    std::streampos end = file.tellg();
    if (end <= 0)
    {
        error = L"Failed to determine file size.";
        return false;
    }

    fileSize = static_cast<uint64_t>(end);

    if (fileSize < sizeof(PayloadHeader))
    {
        error = L"File is too small for PurePacker.";
        return false;
    }

    file.seekg(-static_cast<std::streamoff>(sizeof(PayloadHeader)), std::ios::end);
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (!file)
    {
        error = L"Failed to read PayloadHeader.";
        return false;
    }

    return true;
}

// ============================================================
// Inspect
// ============================================================

static std::wstring InspectFile(const std::wstring& path)
{
    PayloadHeader header{};
    uint64_t fileSize = 0;
    std::wstring error;

    if (!ReadPayloadHeader(path, header, fileSize, error))
    {
        return
            L"ERROR\r\n"
            L"------------------------------\r\n" +
            error;
    }

    std::wstringstream out;

    // --------------------------------------------------------
    // MAGIC
    // --------------------------------------------------------

    bool magicValid = CheckMagic(header.magic);

    out << L"PurePacker Inspector\r\n";
    out << L"==============================\r\n\r\n";

    out << L"File:\r\n";
    out << L"  " << path << L"\r\n\r\n";

    out << L"Format:\r\n";
    out << L"  MAGIC: ";

    for (int i = 0; i < 8; ++i)
        out << static_cast<wchar_t>(header.magic[i]);

    out << L"\r\n";

    out << L"  MAGIC check: "
        << (magicValid ? L"OK" : L"ERROR")
        << L"\r\n";

    if (!magicValid)
    {
        out << L"\r\nFile is not a valid PurePacker file.\r\n";
        return out.str();
    }

    // --------------------------------------------------------
    // Version
    // --------------------------------------------------------

    out << L"  Format version: "
        << header.version
        << L"\r\n";

    if (header.version != FORMAT_VERSION)
    {
        out << L"  Version status: UNSUPPORTED\r\n";
    }
    else
    {
        out << L"  Version status: OK\r\n";
    }

    // --------------------------------------------------------
    // File size
    // --------------------------------------------------------

    out << L"\r\nSizes\r\n";
    out << L"------------------------------\r\n";

    out << L"Packed file size: "
        << FormatBytes(fileSize)
        << L" ("
        << fileSize
        << L")\r\n";

    out << L"Header size: "
        << sizeof(PayloadHeader)
        << L" bytes\r\n";

    // --------------------------------------------------------
    // Stub
    // --------------------------------------------------------

    out << L"\r\nStub\r\n";
    out << L"------------------------------\r\n";

    out << L"Stub size: "
        << FormatBytes(header.stubSize)
        << L" ("
        << header.stubSize
        << L")\r\n";

    out << L"Stub offset: 0\r\n";

    std::wstring architecture = DetectPEArchitecture(path);
    out << L"Stub architecture: "
        << architecture
        << L"\r\n";

    // --------------------------------------------------------
    // Payload
    // --------------------------------------------------------

    uint64_t headerOffset = fileSize - sizeof(PayloadHeader);
    uint64_t payloadOffset = header.stubSize;
    uint64_t actualPayloadSize = 0;
    bool layoutValid = false;

    if (headerOffset >= payloadOffset)
    {
        actualPayloadSize = headerOffset - payloadOffset;
        layoutValid = actualPayloadSize == header.compressedSize;
    }

    out << L"\r\nPayload\r\n";
    out << L"------------------------------\r\n";

    out << L"Payload offset: "
        << payloadOffset
        << L"\r\n";

    out << L"Compressed size: "
        << FormatBytes(header.compressedSize)
        << L" ("
        << header.compressedSize
        << L")\r\n";

    out << L"Actual payload size: "
        << FormatBytes(actualPayloadSize)
        << L" ("
        << actualPayloadSize
        << L")\r\n";

    out << L"Payload layout: "
        << (layoutValid ? L"OK" : L"ERROR")
        << L"\r\n";

    // --------------------------------------------------------
    // Original
    // --------------------------------------------------------

    out << L"\r\nOriginal EXE\r\n";
    out << L"------------------------------\r\n";

    out << L"Original size: "
        << FormatBytes(header.originalSize)
        << L" ("
        << header.originalSize
        << L")\r\n";

    // --------------------------------------------------------
    // Compression ratio
    // --------------------------------------------------------

    if (header.originalSize != 0)
    {
        double ratio = static_cast<double>(header.compressedSize) /
                       static_cast<double>(header.originalSize) * 100.0;
        double saved = 100.0 - ratio;

        out << L"Compression ratio: "
            << std::fixed << std::setprecision(2)
            << ratio
            << L"%\r\n";

        out << L"Size reduced by approximately: "
            << std::fixed << std::setprecision(2)
            << saved
            << L"%\r\n";
    }

    // --------------------------------------------------------
    // Header position
    // --------------------------------------------------------

    out << L"\r\nHeader\r\n";
    out << L"------------------------------\r\n";

    out << L"Header offset: "
        << headerOffset
        << L"\r\n";

    out << L"Header size: "
        << sizeof(PayloadHeader)
        << L" bytes\r\n";

    // --------------------------------------------------------
    // SHA-256
    // --------------------------------------------------------

    out << L"\r\nOriginal EXE SHA-256\r\n";
    out << L"------------------------------\r\n";

    out << ToHex(header.sha256, 32);
    out << L"\r\n";

    // --------------------------------------------------------
    // Final validation
    // --------------------------------------------------------

    bool sizesValid = header.stubSize > 0 &&
                      header.originalSize > 0 &&
                      header.compressedSize > 0 &&
                      headerOffset >= header.stubSize &&
                      actualPayloadSize == header.compressedSize;

    out << L"\r\nStructure Check\r\n";
    out << L"==============================\r\n";

    out << L"MAGIC: "
        << (magicValid ? L"OK" : L"FAIL")
        << L"\r\n";

    out << L"Version: "
        << (header.version == FORMAT_VERSION ? L"OK" : L"FAIL")
        << L"\r\n";

    out << L"Sizes: "
        << (sizesValid ? L"OK" : L"FAIL")
        << L"\r\n";

    out << L"\r\nResult: ";

    if (magicValid && header.version == FORMAT_VERSION && sizesValid)
    {
        out << L"VALID PUREPACKER FILE";
    }
    else
    {
        out << L"INVALID PUREPACKER FILE";
    }

    out << L"\r\n";

    return out.str();
}

// ============================================================
// File dialog
// ============================================================

static bool OpenFileDialog(HWND hwnd, std::wstring& result)
{
    wchar_t fileName[MAX_PATH] = {};

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (!GetOpenFileNameW(&ofn))
        return false;

    result = fileName;
    return true;
}

// ============================================================
// GUI controls
// ============================================================

static HWND gFileEdit;
static HWND gInfoEdit;
static HWND gStatus;

// ============================================================
// Set status
// ============================================================

static void SetStatus(HWND hwnd, const wchar_t* text)
{
    HWND statusCtrl = GetDlgItem(hwnd, IDC_STATUS);
    RedrawWindow(statusCtrl, NULL, NULL, RDW_ERASE | RDW_INVALIDATE);
    SetWindowTextW(statusCtrl, text);
    UpdateWindow(statusCtrl);
}

// ============================================================
// Command handler
// ============================================================

static void OnCommand(HWND hwnd, WPARAM wParam)
{
    int id = LOWORD(wParam);

    // --------------------------------------------------------
    // Browse
    // --------------------------------------------------------

    if (id == IDC_BROWSE)
    {
        std::wstring path;
        if (OpenFileDialog(hwnd, path))
        {
            SetWindowTextW(gFileEdit, path.c_str());
            SetStatus(hwnd, L"[+] File selected");
            
            // Auto-inspect
            std::wstring info = InspectFile(path);
            SetWindowTextW(gInfoEdit, info.c_str());
            SetStatus(hwnd, L"[+] Inspection completed");
        }
        return;
    }

    // --------------------------------------------------------
    // Inspect
    // --------------------------------------------------------

    if (id == IDC_INSPECT)
    {
        wchar_t buffer[32768] = {};
        GetWindowTextW(gFileEdit, buffer, 32768);

        if (buffer[0] == L'\0')
        {
            MessageBoxW(hwnd,
                       L"Please select a packed EXE first.",
                       L"PurePacker Inspector",
                       MB_OK | MB_ICONWARNING);
            return;
        }

        std::wstring path = buffer;
        SetStatus(hwnd, L"[*] Inspecting...");

        std::wstring info = InspectFile(path);
        SetWindowTextW(gInfoEdit, info.c_str());

        if (info.find(L"VALID PUREPACKER FILE") != std::wstring::npos)
        {
            SetStatus(hwnd, L"[+] Inspection completed successfully");
        }
        else
        {
            SetStatus(hwnd, L"[-] Inspection completed with errors");
        }

        return;
    }
}

// ============================================================
// Window procedure
// ============================================================

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_COMMAND:
        {
            OnCommand(hwnd, wParam);
            return 0;
        }

        case WM_CTLCOLORSTATIC:
        {
            HDC hdc = (HDC)wParam;
            HWND control = (HWND)lParam;
            int ctrlId = GetDlgCtrlID(control);

            if (ctrlId == IDC_STATUS)
            {
                SetBkColor(hdc, GetSysColor(COLOR_WINDOW));

                wchar_t text[256];
                GetWindowTextW(control, text, 256);

                if (wcsstr(text, L"[+]") != NULL)
                {
                    SetTextColor(hdc, RGB(0, 150, 0));
                }
                else if (wcsstr(text, L"[-]") != NULL)
                {
                    SetTextColor(hdc, RGB(200, 0, 0));
                }
                else if (wcsstr(text, L"[*]") != NULL)
                {
                    SetTextColor(hdc, RGB(0, 100, 200));
                }
                else
                {
                    SetTextColor(hdc, RGB(80, 80, 80));
                }

                SetBkMode(hdc, TRANSPARENT);
                static HBRUSH hBrush = NULL;
                if (hBrush == NULL)
                    hBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
                return (LRESULT)hBrush;
            }

            break;
        }

        case WM_DESTROY:
        {
            if (gTitleFont) DeleteObject(gTitleFont);
            if (gButtonFont) DeleteObject(gButtonFont);
            if (gDefaultFont) DeleteObject(gDefaultFont);
            PostQuitMessage(0);
            return 0;
        }
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ============================================================
// WinMain
// ============================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    // --------------------------------------------------------
    // Initialize common controls
    // --------------------------------------------------------

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    // --------------------------------------------------------
    // Fonts
    // --------------------------------------------------------

    LOGFONTA lfDefault{};
    lfDefault.lfHeight = -14;
    lfDefault.lfWeight = FW_NORMAL;
    lfDefault.lfCharSet = DEFAULT_CHARSET;
    lfDefault.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfDefault.lfFaceName, "Segoe UI");
    gDefaultFont = CreateFontIndirectA(&lfDefault);

    LOGFONTA lfTitle{};
    lfTitle.lfHeight = -28;
    lfTitle.lfWeight = FW_BOLD;
    lfTitle.lfCharSet = DEFAULT_CHARSET;
    lfTitle.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfTitle.lfFaceName, "Segoe UI");
    gTitleFont = CreateFontIndirectA(&lfTitle);

    LOGFONTA lfButton{};
    lfButton.lfHeight = -14;
    lfButton.lfWeight = FW_BOLD;
    lfButton.lfCharSet = DEFAULT_CHARSET;
    lfButton.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfButton.lfFaceName, "Segoe UI");
    gButtonFont = CreateFontIndirectA(&lfButton);

    LOGFONTA lfStatus{};
    lfStatus.lfHeight = -16;
    lfStatus.lfWeight = FW_BOLD;
    lfStatus.lfCharSet = DEFAULT_CHARSET;
    lfStatus.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfStatus.lfFaceName, "Consolas");
    HFONT statusFont = CreateFontIndirectA(&lfStatus);

    // --------------------------------------------------------
    // Window class
    // --------------------------------------------------------

    const wchar_t CLASS_NAME[] = L"PurePackerInspector";

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (!RegisterClassW(&wc))
        return 1;

    // --------------------------------------------------------
    // Main window
    // --------------------------------------------------------

    HWND hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        CLASS_NAME,
        L"PurePacker Inspector",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 700,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd)
        return 1;

    // Set window icon
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIconW(NULL, IDI_SHIELD));
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadIconW(NULL, IDI_SHIELD));

    // --------------------------------------------------------
    // Title
    // --------------------------------------------------------

    HWND title = CreateWindowExW(
        0, L"STATIC", L"PurePacker Inspector",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        25, 15, 840, 40,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageW(title, WM_SETFONT, (WPARAM)gTitleFont, TRUE);

    // Subtitle
    HWND subtitle = CreateWindowExW(
        0, L"STATIC", L"Packed Executable Analyzer",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        25, 52, 840, 20,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageW(subtitle, WM_SETFONT, (WPARAM)gDefaultFont, TRUE);

    // --------------------------------------------------------
    // File group
    // --------------------------------------------------------

    HWND groupFile = CreateWindowExW(
        0, L"BUTTON", L"Input File",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        20, 85, 850, 75,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageW(groupFile, WM_SETFONT, (WPARAM)gDefaultFont, TRUE);

    // File label
    HWND label = CreateWindowExW(
        0, L"STATIC", L"EXE:",
        WS_CHILD | WS_VISIBLE,
        35, 110, 40, 25,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageW(label, WM_SETFONT, (WPARAM)gDefaultFont, TRUE);

    // File edit
    gFileEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        80, 108, 620, 28,
        hwnd, reinterpret_cast<HMENU>(IDC_FILE), hInstance, NULL
    );
    SendMessageW(gFileEdit, WM_SETFONT, (WPARAM)gDefaultFont, TRUE);

    // Browse button
    HWND browse = CreateWindowExW(
        0, L"BUTTON", L"Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        710, 108, 140, 28,
        hwnd, reinterpret_cast<HMENU>(IDC_BROWSE), hInstance, NULL
    );
    SendMessageW(browse, WM_SETFONT, (WPARAM)gDefaultFont, TRUE);

    // --------------------------------------------------------
    // Information area
    // --------------------------------------------------------

    HWND groupInfo = CreateWindowExW(
        0, L"BUTTON", L"Analysis Result",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        20, 185, 850, 455,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageW(groupInfo, WM_SETFONT, (WPARAM)gDefaultFont, TRUE);

    gInfoEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"Select a packed EXE and click 'Inspect'.",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        35, 218, 820, 400,
        hwnd, reinterpret_cast<HMENU>(IDC_INFO), hInstance, NULL
    );
    SendMessageW(gInfoEdit, WM_SETFONT, (WPARAM)statusFont, TRUE);



    // --------------------------------------------------------
    // Show
    // --------------------------------------------------------

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // --------------------------------------------------------
    // Message loop
    // --------------------------------------------------------

    MSG msg{};
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}