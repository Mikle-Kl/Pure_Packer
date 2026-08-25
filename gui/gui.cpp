#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <string>
#include <fstream>
#include <vector>

#pragma comment(lib, "comctl32.lib")

// ============================================================
// Paths
// ============================================================

static std::string g_selectedFile;
static std::string g_outputFile;
static HWND g_progressBar;
static HFONT g_titleFont;
static HFONT g_buttonFont;

// ============================================================
// GUI control IDs
// ============================================================

#define IDC_INPUT      1001
#define IDC_OUTPUT     1002
#define IDC_BROWSE     1003
#define IDC_SAVE       1004
#define IDC_PACK       1005
#define IDC_STATUS     1006
#define IDC_PROGRESS   1007

// ============================================================
// Get directory where gui.exe is located
// ============================================================

static std::string GetProgramDirectory()
{
    char path[MAX_PATH] = {};
    DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH);
    
    if (length == 0)
        return ".";
    
    std::string fullPath(path, length);
    size_t pos = fullPath.find_last_of("\\/");
    
    if (pos == std::string::npos)
        return ".";
    
    return fullPath.substr(0, pos);
}

// ============================================================
// Check PE and detect architecture
// ============================================================

static int DetectPEArchitecture(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return 0;

    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    
    if (dos.e_lfanew <= 0)
        return 0;

    file.seekg(dos.e_lfanew, std::ios::beg);
    
    DWORD signature = 0;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    
    if (!file || signature != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_FILE_HEADER fileHeader{};
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    
    if (!file)
        return 0;

    if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        return 32;
    
    if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return 64;

    return 0;
}

// ============================================================
// Generate default output filename with _packed suffix
// ============================================================

static std::string GenerateOutputFilename(const std::string& inputPath)
{
    size_t pos = inputPath.find_last_of("\\/");
    std::string directory;
    std::string filename;
    
    if (pos != std::string::npos) {
        directory = inputPath.substr(0, pos + 1);
        filename = inputPath.substr(pos + 1);
    } else {
        filename = inputPath;
    }
    
    // Find last dot for extension
    size_t dotPos = filename.find_last_of(".");
    std::string baseName;
    std::string extension;
    
    if (dotPos != std::string::npos) {
        baseName = filename.substr(0, dotPos);
        extension = filename.substr(dotPos);
    } else {
        baseName = filename;
        extension = ".exe";
    }
    
    // Add _packed suffix
    return directory + baseName + "_packed" + extension;
}

// ============================================================
// Open input file dialog
// ============================================================

static bool BrowseForInput(HWND hwnd)
{
    OPENFILENAMEA ofn{};
    char fileName[MAX_PATH] = {};

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = "Select executable";

    if (!GetOpenFileNameA(&ofn))
        return false;

    g_selectedFile = fileName;
    
    // Auto-generate output filename
    g_outputFile = GenerateOutputFilename(g_selectedFile);
    SetWindowTextA(GetDlgItem(hwnd, IDC_OUTPUT), g_outputFile.c_str());
    
    return true;
}

// ============================================================
// Save output file dialog
// ============================================================

static bool BrowseForOutput(HWND hwnd)
{
    OPENFILENAMEA ofn{};
    char fileName[MAX_PATH] = {};
    
    // Use current output file as default or generate from input
    if (g_outputFile.empty() && !g_selectedFile.empty()) {
        g_outputFile = GenerateOutputFilename(g_selectedFile);
    }
    
    strcpy_s(fileName, g_outputFile.c_str());

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = "Save packed executable";

    if (!GetSaveFileNameA(&ofn))
        return false;

    g_outputFile = fileName;
    return true;
}

// ============================================================
// Run packer
// ============================================================

static bool RunPacker(const std::string& packer, const std::string& stub, 
                      const std::string& input, const std::string& output)
{
    std::string command = "\"" + packer + "\" \"" + stub + "\" \"" + input + "\" \"" + output + "\"";
    
    std::vector<char> commandLine(command.begin(), command.end());
    commandLine.push_back('\0');

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL result = CreateProcessA(NULL, commandLine.data(), NULL, NULL, FALSE, 
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (!result)
        return false;

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return exitCode == 0;
}

// ============================================================
// Set status text with color
// ============================================================

static void SetStatus(HWND hwnd, const char* text)
{
    HWND statusCtrl = GetDlgItem(hwnd, IDC_STATUS);
    
    // Redraw the entire control to clear any previous text
    RedrawWindow(statusCtrl, NULL, NULL, RDW_ERASE | RDW_INVALIDATE);
    
    // Set new text
    SetWindowTextA(statusCtrl, text);
    
    // Force repaint
    UpdateWindow(statusCtrl);
}

// ============================================================
// Update progress
// ============================================================

static void SetProgressState(bool isActive, bool isError = false)
{
    if (g_progressBar) {
        if (isActive) {
            SendMessageA(g_progressBar, PBM_SETMARQUEE, TRUE, 0);
            SendMessageA(g_progressBar, PBM_SETSTATE, PBST_NORMAL, 0);
        } else {
            SendMessageA(g_progressBar, PBM_SETMARQUEE, FALSE, 0);
            if (isError) {
                SendMessageA(g_progressBar, PBM_SETSTATE, PBST_ERROR, 0);
                SendMessageA(g_progressBar, PBM_SETPOS, 100, 0);
            } else {
                SendMessageA(g_progressBar, PBM_SETSTATE, PBST_NORMAL, 0);
                SendMessageA(g_progressBar, PBM_SETPOS, 100, 0);
            }
        }
    }
}

// ============================================================
// Handle commands
// ============================================================

static void OnCommand(HWND hwnd, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
        case IDC_BROWSE:
        {
            if (!BrowseForInput(hwnd))
                return;

            SetWindowTextA(GetDlgItem(hwnd, IDC_INPUT), g_selectedFile.c_str());

            int architecture = DetectPEArchitecture(g_selectedFile);
            
            if (architecture == 32) {
                SetStatus(hwnd, "[+] Detected PE32 (x86)");
            } else if (architecture == 64) {
                SetStatus(hwnd, "[+] Detected PE64 (x64)");
            } else {
                SetStatus(hwnd, "[-] Error: invalid or unsupported PE");
                MessageBoxA(hwnd, 
                           "The selected file is not a supported PE32 or PE64 executable.",
                           "PurePacker - Error", 
                           MB_OK | MB_ICONERROR);
            }
            break;
        }

        case IDC_SAVE:
        {
            if (!BrowseForOutput(hwnd))
                return;

            SetWindowTextA(GetDlgItem(hwnd, IDC_OUTPUT), g_outputFile.c_str());
            break;
        }

        case IDC_PACK:
        {
            // Check input
            if (g_selectedFile.empty()) {
                MessageBoxA(hwnd, 
                           "Please select an executable first.",
                           "PurePacker",
                           MB_OK | MB_ICONWARNING);
                return;
            }

            // Detect architecture
            int architecture = DetectPEArchitecture(g_selectedFile);
            if (architecture == 0) {
                MessageBoxA(hwnd,
                           "The selected file is not a supported PE32 or PE64 executable.",
                           "PurePacker - Error",
                           MB_OK | MB_ICONERROR);
                return;
            }

            // Auto-create output path if empty
            if (g_outputFile.empty()) {
                g_outputFile = GenerateOutputFilename(g_selectedFile);
                SetWindowTextA(GetDlgItem(hwnd, IDC_OUTPUT), g_outputFile.c_str());
            }

            // PurePacker root directory
            std::string root = GetProgramDirectory();

            // Select packer and stub automatically
            std::string packer;
            std::string stub;
            
            if (architecture == 32) {
                packer = root + "\\build\\x86\\exe\\packer32.exe";
                stub = root + "\\build\\x86\\exe\\stub32.exe";
            } else {
                packer = root + "\\build\\x64\\exe\\packer64.exe";
                stub = root + "\\build\\x64\\exe\\stub64.exe";
            }

            // Check packer
            if (GetFileAttributesA(packer.c_str()) == INVALID_FILE_ATTRIBUTES) {
                std::string errorMsg = "The required packer was not found.\n\nExpected: " + packer;
                MessageBoxA(hwnd,
                           errorMsg.c_str(),
                           "PurePacker - Error",
                           MB_OK | MB_ICONERROR);
                return;
            }

            // Check stub
            if (GetFileAttributesA(stub.c_str()) == INVALID_FILE_ATTRIBUTES) {
                std::string errorMsg = "The required stub was not found.\n\nExpected: " + stub;
                MessageBoxA(hwnd,
                           errorMsg.c_str(),
                           "PurePacker - Error",
                           MB_OK | MB_ICONERROR);
                return;
            }

            // Disable pack button
            EnableWindow(GetDlgItem(hwnd, IDC_PACK), FALSE);
            SetProgressState(true, false);
            
            if (architecture == 32) {
                SetStatus(hwnd, "[*] Packing PE32 (x86)...");
            } else {
                SetStatus(hwnd, "[*] Packing PE64 (x64)...");
            }

            // Run packer
            bool success = RunPacker(packer, stub, g_selectedFile, g_outputFile);

            // Enable pack button
            EnableWindow(GetDlgItem(hwnd, IDC_PACK), TRUE);
            SetProgressState(false, !success);

            // Result
            if (success) {
                SetStatus(hwnd, "[+] Packing completed successfully!");
                
                std::string message = 
                    "The executable was packed successfully!\n\n"
                    "Output: " + g_outputFile + "\n"
                    "Architecture: " + std::string(architecture == 32 ? "x86" : "x64");
                
                MessageBoxA(hwnd,
                           message.c_str(),
                           "PurePacker - Success",
                           MB_OK | MB_ICONINFORMATION);
            } else {
                SetStatus(hwnd, "[-] Packing failed");
                MessageBoxA(hwnd,
                           "The packer exited with an error.\n\n"
                           "Please check the input file and try again.",
                           "PurePacker - Error",
                           MB_OK | MB_ICONERROR);
            }
            break;
        }
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
            
            // Status control - special handling
            if (ctrlId == IDC_STATUS) {
                // Set background to window color
                SetBkColor(hdc, GetSysColor(COLOR_WINDOW));
                
                char text[256];
                GetWindowTextA(control, text, 256);
                
                if (strstr(text, "[+]") != NULL) {
                    SetTextColor(hdc, RGB(0, 150, 0)); // Green
                } else if (strstr(text, "[-]") != NULL) {
                    SetTextColor(hdc, RGB(200, 0, 0)); // Red
                } else if (strstr(text, "[*]") != NULL) {
                    SetTextColor(hdc, RGB(0, 100, 200)); // Blue
                } else {
                    SetTextColor(hdc, RGB(80, 80, 80)); // Gray
                }
                
                SetBkMode(hdc, TRANSPARENT);
                
                // Return a brush for the background
                static HBRUSH hBrush = NULL;
                if (hBrush == NULL) {
                    hBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
                }
                return (LRESULT)hBrush;
            }
            
            // Title
            if (ctrlId == 0 && control == GetDlgItem(hwnd, 0)) {
                SetBkColor(hdc, GetSysColor(COLOR_WINDOW));
                SetTextColor(hdc, RGB(0, 50, 150));
                SetBkMode(hdc, TRANSPARENT);
                
                static HBRUSH hBrush = NULL;
                if (hBrush == NULL) {
                    hBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
                }
                return (LRESULT)hBrush;
            }
            
            break;
        }

        case WM_DESTROY:
        {
            // Cleanup fonts
            if (g_titleFont) DeleteObject(g_titleFont);
            if (g_buttonFont) DeleteObject(g_buttonFont);
            
            PostQuitMessage(0);
            return 0;
        }
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ============================================================
// WinMain
// ============================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    const char CLASS_NAME[] = "PurePackerGUI";

    // Initialize common controls
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    // Register window class
    WNDCLASSA wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);

    if (!RegisterClassA(&wc))
        return 1;

    // Create main window
    HWND hwnd = CreateWindowExA(
        WS_EX_APPWINDOW,
        CLASS_NAME,
        "PurePacker",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        700, 400,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd)
        return 1;

    // Set window icon
    SendMessageA(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIconA(NULL, IDI_SHIELD));
    SendMessageA(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadIconA(NULL, IDI_SHIELD));

    // ============================================================
    // НАСТРОЙКА ШРИФТОВ
    // ============================================================
    
    // 1. Базовый шрифт для всех элементов
    LOGFONTA lfDefault{};
    lfDefault.lfHeight = -16;
    lfDefault.lfWeight = FW_NORMAL;
    lfDefault.lfCharSet = DEFAULT_CHARSET;
    lfDefault.lfOutPrecision = OUT_DEFAULT_PRECIS;
    lfDefault.lfClipPrecision = CLIP_DEFAULT_PRECIS;
    lfDefault.lfQuality = CLEARTYPE_QUALITY;
    lfDefault.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
    strcpy_s(lfDefault.lfFaceName, "Segoe UI");
    HFONT defaultFont = CreateFontIndirectA(&lfDefault);
    
    // 2. Шрифт для заголовка (большой, жирный)
    LOGFONTA lfTitle{};
    lfTitle.lfHeight = -32;
    lfTitle.lfWeight = FW_BOLD;
    lfTitle.lfCharSet = DEFAULT_CHARSET;
    lfTitle.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfTitle.lfFaceName, "Segoe UI");
    g_titleFont = CreateFontIndirectA(&lfTitle);
    
    // 3. Шрифт для кнопки PACK (МЕНЬШЕ)
    LOGFONTA lfButton{};
    lfButton.lfHeight = -15;
    lfButton.lfWeight = FW_BOLD;
    lfButton.lfCharSet = DEFAULT_CHARSET;
    lfButton.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfButton.lfFaceName, "Segoe UI");
    g_buttonFont = CreateFontIndirectA(&lfButton);
    
    // 4. Шрифт для статуса (БОЛЬШЕ и ЖИРНЫЙ)
    LOGFONTA lfStatus{};
    lfStatus.lfHeight = -19;
    lfStatus.lfWeight = FW_BOLD;
    lfStatus.lfCharSet = DEFAULT_CHARSET;
    lfStatus.lfQuality = CLEARTYPE_QUALITY;
    strcpy_s(lfStatus.lfFaceName, "Consolas");
    HFONT statusFont = CreateFontIndirectA(&lfStatus);

    // ============================================================
    // СОЗДАНИЕ ЭЛЕМЕНТОВ УПРАВЛЕНИЯ
    // ============================================================

    // Title
    HWND title = CreateWindowExA(
        0, "STATIC", "PurePacker",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        25, 10, 640, 45,
        hwnd, (HMENU)0, hInstance, NULL
    );
    SendMessageA(title, WM_SETFONT, (WPARAM)g_titleFont, TRUE);

    // Input group
    HWND groupInput = CreateWindowExA(
        0, "BUTTON", "Input File",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        20, 75, 650, 75,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageA(groupInput, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Input label
    HWND inputLabel = CreateWindowExA(
        0, "STATIC", "EXE:",
        WS_CHILD | WS_VISIBLE,
        35, 100, 40, 25,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageA(inputLabel, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Input edit
    HWND inputEdit = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        80, 98, 420, 28,
        hwnd, reinterpret_cast<HMENU>(IDC_INPUT), hInstance, NULL
    );
    SendMessageA(inputEdit, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Browse button
    HWND browseButton = CreateWindowExA(
        0, "BUTTON", "Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        510, 98, 140, 28,
        hwnd, reinterpret_cast<HMENU>(IDC_BROWSE), hInstance, NULL
    );
    SendMessageA(browseButton, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Output group
    HWND groupOutput = CreateWindowExA(
        0, "BUTTON", "Output File",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        20, 160, 650, 75,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageA(groupOutput, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Output label
    HWND outputLabel = CreateWindowExA(
        0, "STATIC", "Save:",
        WS_CHILD | WS_VISIBLE,
        35, 185, 40, 25,
        hwnd, NULL, hInstance, NULL
    );
    SendMessageA(outputLabel, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Output edit
    HWND outputEdit = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        80, 183, 420, 28,
        hwnd, reinterpret_cast<HMENU>(IDC_OUTPUT), hInstance, NULL
    );
    SendMessageA(outputEdit, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Save button
    HWND saveButton = CreateWindowExA(
        0, "BUTTON", "Save as...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        510, 183, 140, 28,
        hwnd, reinterpret_cast<HMENU>(IDC_SAVE), hInstance, NULL
    );
    SendMessageA(saveButton, WM_SETFONT, (WPARAM)defaultFont, TRUE);

    // Pack button
    HWND packButton = CreateWindowExA(
        0, "BUTTON", "PACK",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        250, 250, 150, 40,
        hwnd, reinterpret_cast<HMENU>(IDC_PACK), hInstance, NULL
    );
    SendMessageA(packButton, WM_SETFONT, (WPARAM)g_buttonFont, TRUE);

    // Status - с увеличенной высотой
    HWND status = CreateWindowExA(
        WS_EX_CLIENTEDGE, "STATIC", "[+] Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN,
        25, 305, 640, 35,
        hwnd, reinterpret_cast<HMENU>(IDC_STATUS), hInstance, NULL
    );
    SendMessageA(status, WM_SETFONT, (WPARAM)statusFont, TRUE);

    // Show window
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Message loop
    MSG msg{};
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return static_cast<int>(msg.wParam);
}
