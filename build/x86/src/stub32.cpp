#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

typedef LONG NTSTATUS;
static const DWORD FORMAT_VERSION = 1;

// ============================================================
// LZNT1
// ============================================================

typedef NTSTATUS (NTAPI* RtlDecompressBuffer_t)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize
);

static RtlDecompressBuffer_t
    pRtlDecompressBuffer = NULL;


// ============================================================
// MAGIC
// ============================================================

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


// ============================================================
// Простая функция сравнения MAGIC
// ============================================================

static bool IsMagic(
    const unsigned char* data)
{
    for (int i = 0; i < 8; ++i)
    {
        if (data[i] != MAGIC[i])
            return false;
    }

    return true;
}


// ============================================================
// Вывод ошибки
// ============================================================

static void ShowError(
    const char* text)
{
    MessageBoxA(
        NULL,
        text,
        "PurePacker",
        MB_OK | MB_ICONERROR
    );
}


// ============================================================
// Инициализация LZNT1
// ============================================================

static bool InitDecompression()
{
    HMODULE ntdll =
        GetModuleHandleW(
            L"ntdll.dll"
        );

    if (!ntdll)
        return false;

    pRtlDecompressBuffer =
        reinterpret_cast<RtlDecompressBuffer_t>(
            GetProcAddress(
                ntdll,
                "RtlDecompressBuffer"
            )
        );

    return
        pRtlDecompressBuffer != NULL;
}


// ============================================================
// LZNT1 decompression
// ============================================================

static unsigned char*
DecompressPayload(
    const unsigned char* compressed,
    DWORD compressedSize,
    DWORD originalSize)
{
    if (!compressed)
        return NULL;

    if (compressedSize == 0 ||
        originalSize == 0)
    {
        return NULL;
    }

    // --------------------------------------------------------
    // Выделяем память под распакованный файл
    // --------------------------------------------------------

    unsigned char* output =
        static_cast<unsigned char*>(
            VirtualAlloc(
                NULL,
                originalSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        );

    if (!output)
        return NULL;

    // --------------------------------------------------------
    // Распаковываем
    // --------------------------------------------------------

    ULONG finalSize = 0;

    NTSTATUS status =
        pRtlDecompressBuffer(
            COMPRESSION_FORMAT_LZNT1 |
            COMPRESSION_ENGINE_STANDARD,

            output,

            originalSize,

            const_cast<PUCHAR>(
                compressed
            ),

            compressedSize,

            &finalSize
        );

    // --------------------------------------------------------
    // Проверяем результат
    // --------------------------------------------------------

    if (status != 0 ||
        finalSize != originalSize)
    {
        VirtualFree(
            output,
            0,
            MEM_RELEASE
        );

        return NULL;
    }

    return output;
}


// ============================================================
// SHA-256
//
// Здесь нет std::vector.
// Рабочая память выделяется через VirtualAlloc.
// ============================================================

static bool CalculateSHA256(
    const unsigned char* data,
    DWORD size,
    unsigned char hash[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hashHandle = NULL;

    DWORD objectSize = 0;
    DWORD resultSize = 0;

    // --------------------------------------------------------
    // Открываем SHA-256
    // --------------------------------------------------------

    if (BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0) != 0)
    {
        return false;
    }

    // --------------------------------------------------------
    // Получаем размер внутреннего объекта hash
    // --------------------------------------------------------

    if (BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(
                &objectSize
            ),
            sizeof(objectSize),
            &resultSize,
            0) != 0)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    // --------------------------------------------------------
    // Память вместо std::vector
    // --------------------------------------------------------

    unsigned char* hashObject =
        static_cast<unsigned char*>(
            VirtualAlloc(
                NULL,
                objectSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        );

    if (!hashObject)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    // --------------------------------------------------------
    // Создаём hash
    // --------------------------------------------------------

    if (BCryptCreateHash(
            algorithm,
            &hashHandle,
            hashObject,
            objectSize,
            NULL,
            0,
            0) != 0)
    {
        VirtualFree(
            hashObject,
            0,
            MEM_RELEASE
        );

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    // --------------------------------------------------------
    // Передаём данные
    // --------------------------------------------------------

    if (BCryptHashData(
            hashHandle,
            const_cast<PUCHAR>(data),
            size,
            0) != 0)
    {
        BCryptDestroyHash(
            hashHandle
        );

        VirtualFree(
            hashObject,
            0,
            MEM_RELEASE
        );

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    // --------------------------------------------------------
    // Получаем SHA-256
    // --------------------------------------------------------

    bool success =
        BCryptFinishHash(
            hashHandle,
            hash,
            32,
            0
        ) == 0;

    // --------------------------------------------------------
    // Освобождение
    // --------------------------------------------------------

    BCryptDestroyHash(
        hashHandle
    );

    VirtualFree(
        hashObject,
        0,
        MEM_RELEASE
    );

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    return success;
}


// ============================================================
// Точка входа
// ============================================================
static bool RunUnpackedExe(
    const unsigned char* data,
    DWORD size)
{
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];

    // --------------------------------------------------------
    // Получаем TEMP
    // --------------------------------------------------------

    DWORD pathLen = GetTempPathA(
        MAX_PATH,
        tempPath
    );

    if (pathLen == 0 || pathLen >= MAX_PATH)
        return false;

    // --------------------------------------------------------
    // Создаём уникальное имя
    // --------------------------------------------------------

    UINT fileLen = GetTempFileNameA(
        tempPath,
        "PP",
        0,
        tempFile
    );

    if (fileLen == 0)
        return false;

    // --------------------------------------------------------
    // Записываем распакованный EXE
    // --------------------------------------------------------

    HANDLE file = CreateFileA(
        tempFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    DWORD written = 0;

    BOOL writeResult = WriteFile(
        file,
        data,
        size,
        &written,
        NULL
    );

    CloseHandle(file);

    if (!writeResult || written != size)
    {
        DeleteFileA(tempFile);
        return false;
    }

    // --------------------------------------------------------
    // STARTUPINFO
    // --------------------------------------------------------

    STARTUPINFOA si;

    unsigned char* psi =
        reinterpret_cast<unsigned char*>(&si);

    for (DWORD i = 0; i < sizeof(si); ++i)
        psi[i] = 0;

    si.cb = sizeof(si);

    // --------------------------------------------------------
    // PROCESS_INFORMATION
    // --------------------------------------------------------

    PROCESS_INFORMATION pi;

    unsigned char* ppi =
        reinterpret_cast<unsigned char*>(&pi);

    for (DWORD i = 0; i < sizeof(pi); ++i)
        ppi[i] = 0;

    // --------------------------------------------------------
    // Запускаем EXE
    // --------------------------------------------------------

    BOOL result = CreateProcessA(
        tempFile,
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!result)
    {
        DeleteFileA(tempFile);
        return false;
    }

    // --------------------------------------------------------
    // Ждём завершения дочернего процесса
    // --------------------------------------------------------

    WaitForSingleObject(
        pi.hProcess,
        INFINITE
    );

    // --------------------------------------------------------
    // Закрываем handles
    // --------------------------------------------------------

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // --------------------------------------------------------
    // Удаляем временный EXE
    // --------------------------------------------------------

    BOOL deleted =
        DeleteFileA(tempFile);

    return deleted != FALSE;
}


static bool IsValidPE32(
    const unsigned char* data,
    DWORD size)
{
    if (!data || size < sizeof(IMAGE_DOS_HEADER))
        return false;

    const IMAGE_DOS_HEADER* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(data);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (dos->e_lfanew <= 0)
        return false;

    if (static_cast<DWORD>(dos->e_lfanew) >
        size - sizeof(IMAGE_NT_HEADERS32))
        return false;

    const IMAGE_NT_HEADERS32* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS32*>(
            data + dos->e_lfanew
        );

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        return false;

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;

    if (nt->OptionalHeader.SizeOfImage == 0)
        return false;

    if (nt->OptionalHeader.SizeOfHeaders == 0)
        return false;

    if (nt->FileHeader.NumberOfSections == 0)
        return false;

    return true;
}

extern "C" void Start()
{
    // ========================================================
    // 1. Инициализация LZNT1
    // ========================================================

    if (!InitDecompression())
    {
        ShowError(
            "Cannot initialize LZNT1 decompression."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 2. Получаем путь к packed.exe
    // ========================================================

    char path[MAX_PATH];

    DWORD pathLength =
        GetModuleFileNameA(
            NULL,
            path,
            MAX_PATH
        );

    if (pathLength == 0 ||
        pathLength >= MAX_PATH)
    {
        ShowError(
            "GetModuleFileNameA failed."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 3. Открываем собственный EXE
    // ========================================================

    HANDLE file =
        CreateFileA(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

    if (file == INVALID_HANDLE_VALUE)
    {
        ShowError(
            "Cannot open packed file."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 4. Получаем размер файла
    // ========================================================

    DWORD fileSize =
        GetFileSize(
            file,
            NULL
        );

    if (fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(file);

        ShowError(
            "Cannot get file size."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 5. Проверяем минимальный размер
    // ========================================================

    if (fileSize <
        sizeof(PayloadHeader))
    {
        CloseHandle(file);

        ShowError(
            "Packed file is too small."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 6. Header находится в конце файла
    // ========================================================

    DWORD headerPosition =
        fileSize -
        static_cast<DWORD>(
            sizeof(PayloadHeader)
        );
    

    // ========================================================
    // 7. Читаем Header
    //
    // НЕ используем:
    // PayloadHeader header{};
    //
    // чтобы компилятор не генерировал memset.
    // ========================================================

    PayloadHeader header;

    SetFilePointer(
        file,
        headerPosition,
        NULL,
        FILE_BEGIN
    );

    DWORD bytesRead = 0;

    if (!ReadFile(
            file,
            &header,
            sizeof(PayloadHeader),
            &bytesRead,
            NULL) ||
        bytesRead != sizeof(PayloadHeader))
    {
        CloseHandle(file);

        ShowError(
            "Cannot read payload header."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 8. Проверяем MAGIC
    // ========================================================

    if (!IsMagic(header.magic))
    {
        CloseHandle(file);

        ShowError(
            "Invalid payload header."
        );

        ExitProcess(1);
    }

    if (header.version != FORMAT_VERSION)
    {
        CloseHandle(file);

        ShowError(
            "Unsupported payload version."
        );

        ExitProcess(1);
    }

    // ========================================================
    // 9. Проверяем размеры
    // ========================================================

    // ========================================================
// Проверяем размеры и расположение компонентов
// ========================================================

if (header.stubSize == 0 ||
    header.originalSize == 0 ||
    header.compressedSize == 0)
{
    CloseHandle(file);

    ShowError(
        "Invalid payload sizes."
    );

    ExitProcess(1);
}

// Header должен идти после STUB + compressed payload.
if (headerPosition < header.stubSize)
{
    CloseHandle(file);

    ShowError(
        "Invalid stub size."
    );

    ExitProcess(1);
}

DWORD payloadSize =
    headerPosition - header.stubSize;

if (header.compressedSize != payloadSize)
{
    CloseHandle(file);

    ShowError(
        "Invalid compressed payload size."
    );

    ExitProcess(1);
}

DWORD payloadPosition =
    header.stubSize;
    // ========================================================
    // 12. Выделяем память
    // ========================================================

    unsigned char* compressed =
        static_cast<unsigned char*>(
            VirtualAlloc(
                NULL,
                header.compressedSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        );

    if (!compressed)
    {
        CloseHandle(file);

        ShowError(
            "Cannot allocate compressed buffer."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 13. Читаем compressed payload
    // ========================================================

    SetFilePointer(
        file,
        payloadPosition,
        NULL,
        FILE_BEGIN
    );

    bytesRead = 0;

    if (!ReadFile(
            file,
            compressed,
            header.compressedSize,
            &bytesRead,
            NULL) ||
        bytesRead != header.compressedSize)
    {
        VirtualFree(
            compressed,
            0,
            MEM_RELEASE
        );

        CloseHandle(file);

        ShowError(
            "Cannot read compressed payload."
        );

        ExitProcess(1);
    }

    CloseHandle(file);


    // ========================================================
    // 14. Распаковываем
    // ========================================================

    unsigned char* unpacked =
        DecompressPayload(
            compressed,
            header.compressedSize,
            header.originalSize
        );


    // ========================================================
    // 15. compressed больше не нужен
    // ========================================================

    VirtualFree(
        compressed,
        0,
        MEM_RELEASE
    );


    // ========================================================
    // 16. Проверяем decompression
    // ========================================================

    if (!unpacked)
    {
        ShowError(
            "LZNT1 decompression failed."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 17. Считаем SHA-256 распакованных данных
    // ========================================================

    unsigned char unpackedHash[32];

    if (!CalculateSHA256(
            unpacked,
            header.originalSize,
            unpackedHash))
    {
        VirtualFree(
            unpacked,
            0,
            MEM_RELEASE
        );

        ShowError(
            "Failed to calculate decompressed SHA-256."
        );

        ExitProcess(1);
    }


    // ========================================================
    // 18. Сравниваем SHA-256
    // ========================================================

    bool hashMatch = true;

    for (int i = 0; i < 32; ++i)
    {
        if (unpackedHash[i] !=
            header.sha256[i])
        {
            hashMatch = false;
            break;
        }
    }


    // ========================================================
    // 19. Проверяем совпадение
    // ========================================================

    if (!hashMatch)
    {
        VirtualFree(
            unpacked,
            0,
            MEM_RELEASE
        );

        ShowError(
            "SHA-256 mismatch!"
        );

        ExitProcess(1);
    }

    if (!IsValidPE32(
            unpacked,
            header.originalSize))
    {
        VirtualFree(
            unpacked,
            0,
            MEM_RELEASE
        );

        ShowError(
            "Decompressed data is not a valid PE32 executable."
        );

        ExitProcess(1);
    }
    // ========================================================
    // 20. Успешная проверка
    // ========================================================

    if (!RunUnpackedExe(
            unpacked,
            header.originalSize))
    {
        VirtualFree(
            unpacked,
            0,
            MEM_RELEASE
        );

        ShowError(
            "Cannot start unpacked EXE."
        );

        ExitProcess(1);
    }

    VirtualFree(
        unpacked,
        0,
        MEM_RELEASE
    );

    ExitProcess(0);
}