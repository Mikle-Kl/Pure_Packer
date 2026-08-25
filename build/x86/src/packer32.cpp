#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
typedef LONG NTSTATUS;

typedef NTSTATUS (WINAPI* RtlGetCompressionWorkSpaceSize_t)(
    USHORT CompressionFormat,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize
);

typedef NTSTATUS (WINAPI* RtlCompressBuffer_t)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID WorkSpace
);

// ------------------------------------------------------------
// Формат payload
// ------------------------------------------------------------
static const DWORD FORMAT_VERSION = 1;

static const unsigned char MAGIC[8] = {
    'P', 'U', 'R', 'E', 'P', 'K', '0', '2'
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

// ------------------------------------------------------------
// Указатели на функции ntdll.dll
// ------------------------------------------------------------

static RtlGetCompressionWorkSpaceSize_t
    pRtlGetCompressionWorkSpaceSize = nullptr;

static RtlCompressBuffer_t
    pRtlCompressBuffer = nullptr;

// ------------------------------------------------------------
// Чтение файла
// ------------------------------------------------------------

static std::vector<unsigned char>
ReadFileData(const std::string& path)
{
    std::ifstream file(
        path,
        std::ios::binary | std::ios::ate
    );

    if (!file)
        return {};

    std::streamsize size = file.tellg();

    if (size <= 0)
        return {};

    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> data(
        static_cast<size_t>(size)
    );

    if (!file.read(
            reinterpret_cast<char*>(data.data()),
            size))
    {
        return {};
    }

    return data;
}

// ------------------------------------------------------------
// Запись файла
// ------------------------------------------------------------

static bool
WriteFileData(
    const std::string& path,
    const std::vector<unsigned char>& data)
{
    std::ofstream file(
        path,
        std::ios::binary
    );

    if (!file)
        return false;

    file.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    return file.good();
}

// ------------------------------------------------------------
// Инициализация LZNT1
// ------------------------------------------------------------

static bool InitCompression()
{
    HMODULE ntdll =
        GetModuleHandleW(L"ntdll.dll");

    if (!ntdll)
        return false;

    pRtlGetCompressionWorkSpaceSize =
        reinterpret_cast<RtlGetCompressionWorkSpaceSize_t>(
            GetProcAddress(
                ntdll,
                "RtlGetCompressionWorkSpaceSize"
            )
        );

    pRtlCompressBuffer =
        reinterpret_cast<RtlCompressBuffer_t>(
            GetProcAddress(
                ntdll,
                "RtlCompressBuffer"
            )
        );

    return
        pRtlGetCompressionWorkSpaceSize != nullptr &&
        pRtlCompressBuffer != nullptr;
}

// ------------------------------------------------------------
// LZNT1 compression
// ------------------------------------------------------------

static std::vector<unsigned char>
CompressLZNT1(
    const std::vector<unsigned char>& input)
{
    if (input.empty())
        return {};

    ULONG workspaceSize = 0;
    ULONG fragmentWorkspaceSize = 0;

    NTSTATUS status =
        pRtlGetCompressionWorkSpaceSize(
            COMPRESSION_FORMAT_LZNT1 |
            COMPRESSION_ENGINE_STANDARD,

            &workspaceSize,
            &fragmentWorkspaceSize
        );

    if (status != 0)
    {
        std::cerr
            << "RtlGetCompressionWorkSpaceSize failed: 0x"
            << std::hex
            << static_cast<unsigned long>(status)
            << std::dec
            << "\n";

        return {};
    }

    std::vector<unsigned char> workspace(
        workspaceSize
    );

    // LZNT1 использует чанки по 4096 байт.
    const ULONG chunkSize = 4096;

    // Выделяем буфер немного больше исходного.
    size_t maxCompressedSize =
        input.size() +
        input.size() / 16 +
        4096;

    if (maxCompressedSize > 0xFFFFFFFFULL)
    {
        std::cerr
            << "Input is too large.\n";

        return {};
    }

    std::vector<unsigned char> compressed(
        maxCompressedSize
    );

    ULONG finalCompressedSize = 0;

    status =
        pRtlCompressBuffer(
            COMPRESSION_FORMAT_LZNT1 |
            COMPRESSION_ENGINE_STANDARD,

            const_cast<PUCHAR>(
                input.data()
            ),

            static_cast<ULONG>(
                input.size()
            ),

            compressed.data(),

            static_cast<ULONG>(
                compressed.size()
            ),

            chunkSize,

            &finalCompressedSize,

            workspace.data()
        );

    if (status != 0)
    {
        std::cerr
            << "RtlCompressBuffer failed: 0x"
            << std::hex
            << static_cast<unsigned long>(status)
            << std::dec
            << "\n";

        return {};
    }

    compressed.resize(finalCompressedSize);

    return compressed;
}

static bool CalculateSHA256(
    const std::vector<unsigned char>& data,
    unsigned char hash[32])
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;

    DWORD objectSize = 0;
    DWORD resultSize = 0;

    if (BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0) != 0)
    {
        return false;
    }

    if (BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
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

    std::vector<unsigned char> hashObject(
        objectSize
    );

    if (BCryptCreateHash(
            algorithm,
            &hashHandle,
            hashObject.data(),
            objectSize,
            nullptr,
            0,
            0) != 0)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    if (!data.empty())
    {
        if (BCryptHashData(
                hashHandle,
                const_cast<PUCHAR>(
                    data.data()
                ),
                static_cast<ULONG>(
                    data.size()
                ),
                0) != 0)
        {
            BCryptDestroyHash(hashHandle);
            BCryptCloseAlgorithmProvider(
                algorithm,
                0
            );

            return false;
        }
    }

    bool success =
        BCryptFinishHash(
            hashHandle,
            hash,
            32,
            0
        ) == 0;

    BCryptDestroyHash(hashHandle);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    return success;
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

    DWORD ntOffset =
        static_cast<DWORD>(dos->e_lfanew);

    if (ntOffset > size - sizeof(IMAGE_NT_HEADERS32))
        return false;

    const IMAGE_NT_HEADERS32* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS32*>(
            data + ntOffset
        );

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        return false;

    if (nt->OptionalHeader.Magic !=
        IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;

    if (nt->OptionalHeader.SizeOfImage == 0)
        return false;

    if (nt->OptionalHeader.SizeOfHeaders == 0)
        return false;

    if (nt->FileHeader.NumberOfSections == 0)
        return false;

    const IMAGE_SECTION_HEADER* sections =
        IMAGE_FIRST_SECTION(nt);

    WORD sectionCount =
        nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < sectionCount; ++i)
    {
        const IMAGE_SECTION_HEADER* section =
            &sections[i];

        if (section->VirtualAddress >=
            nt->OptionalHeader.SizeOfImage)
        {
            return false;
        }

        if (section->SizeOfRawData != 0)
        {
            if (section->PointerToRawData >= size)
                return false;

            if (section->SizeOfRawData >
                size - section->PointerToRawData)
            {
                return false;
            }
        }
    }

    return true;
}
// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cout
            << "Usage:\n"
            << "  packer.exe stub.exe input.exe output.exe\n\n"
            << "Example:\n"
            << "  packer.exe ..\\stub\\stub32.exe "
               "..\\hello.exe ..\\packed32.exe\n";

        return 1;
    }

    // --------------------------------------------------------
    // Инициализация compression API
    // --------------------------------------------------------

    if (!InitCompression())
    {
        std::cerr
            << "Failed to initialize LZNT1 compression API.\n";

        return 1;
    }

    const std::string stubPath   = argv[1];
    const std::string inputPath  = argv[2];
    const std::string outputPath = argv[3];

    // --------------------------------------------------------
    // Читаем stub
    // --------------------------------------------------------

    std::cout
        << "[1] Reading stub...\n";

    auto stub =
        ReadFileData(stubPath);

    if (stub.empty())
    {
        std::cerr
            << "Cannot read stub: "
            << stubPath
            << "\n";

        return 1;
    }

    std::cout
        << "    Stub size: "
        << stub.size()
        << " bytes\n";

    // --------------------------------------------------------
    // Читаем исходный EXE
    // --------------------------------------------------------

    std::cout
        << "[2] Reading input...\n";

    auto input =
        ReadFileData(inputPath);

    if (input.empty())
    {
        std::cerr
            << "Cannot read input file: "
            << inputPath
            << "\n";

        return 1;
    }

    if (input.size() > 0xFFFFFFFFULL)
    {
        std::cerr
            << "Input file is too large.\n";

        return 1;
    }

    if (!IsValidPE32(
            input.data(),
            static_cast<DWORD>(input.size())))
    {
        std::cerr
            << "Error: input file is not a valid PE32 executable.\n";

        return 1;
    }
    std::cout << "    PE32 validation: OK\n";
    unsigned char originalHash[32];

    if (!CalculateSHA256(
            input,
            originalHash))
    {
        std::cerr
            << "Failed to calculate SHA-256.\n";

        return 1;
    }

    std::cout << "    SHA-256: ";
    for (int i = 0; i < 32; ++i)
    {
        printf(
            "%02X",
            originalHash[i]
        );
    }
    std::cout << "\n";

    std::cout
        << "    Original size: "
        << input.size()
        << " bytes\n";

    // --------------------------------------------------------
    // Сжимаем
    // --------------------------------------------------------

    std::cout
        << "[3] Compressing with LZNT1...\n";

    auto compressed =
        CompressLZNT1(input);

    if (compressed.empty())
    {
        std::cerr
            << "Compression failed.\n";

        return 1;
    }

    if (compressed.size() > 0xFFFFFFFFULL)
    {
        std::cerr
            << "Compressed data is too large.\n";

        return 1;
    }

    std::cout
        << "    Compressed size: "
        << compressed.size()
        << " bytes\n";

    // --------------------------------------------------------
    // Формируем header
    // --------------------------------------------------------

    PayloadHeader header{};

    for (int i = 0; i < 8; ++i)
    {
        header.magic[i] = MAGIC[i];
    }

    header.version = FORMAT_VERSION;
    header.stubSize = static_cast<DWORD>(stub.size());
    header.originalSize = static_cast<DWORD>(input.size());
    header.compressedSize = static_cast<DWORD>(compressed.size());
    
    for (int i = 0; i < 32; ++i)
    {
        header.sha256[i] =
            originalHash[i];
    }
    // --------------------------------------------------------
    // Формируем packed.exe
    //
    // Формат:
    //
    // [STUB]
    // [COMPRESSED PAYLOAD]
    // [PAYLOAD HEADER]
    //
    // Header находится в самом конце файла.
    // --------------------------------------------------------

    std::cout
        << "[4] Building packed file...\n";

    std::vector<unsigned char> output;

    output.reserve(
        stub.size() +
        compressed.size() +
        sizeof(PayloadHeader)
    );

    // --------------------------------------------------------
    // 1. Stub
    // --------------------------------------------------------

    output.insert(
        output.end(),
        stub.begin(),
        stub.end()
    );

    // --------------------------------------------------------
    // 2. Compressed payload
    // --------------------------------------------------------

    output.insert(
        output.end(),
        compressed.begin(),
        compressed.end()
    );

    // --------------------------------------------------------
    // 3. Header — ПОСЛЕДНИМ
    // --------------------------------------------------------

    const unsigned char* headerBytes =
        reinterpret_cast<const unsigned char*>(
            &header
        );

    output.insert(
        output.end(),
        headerBytes,
        headerBytes + sizeof(PayloadHeader)
    );

    // --------------------------------------------------------
    // Проверяем итоговый размер
    // --------------------------------------------------------

    std::cout
        << "    Header size: "
        << sizeof(PayloadHeader)
        << " bytes\n";

    std::cout
        << "    Payload size: "
        << compressed.size()
        << " bytes\n";

    std::cout
        << "    Final size: "
        << output.size()
        << " bytes\n";

    std::cout
        << "\n--- Layout ---\n";

    std::cout
        << "Stub offset:       0\n";

    std::cout
        << "Stub size:         "
        << header.stubSize
        << " bytes\n";

    std::cout
        << "Payload offset:    "
        << header.stubSize
        << "\n";

    std::cout
        << "Payload size:      "
        << header.compressedSize
        << " bytes\n";

    std::cout
        << "Header offset:     "
        << (output.size() - sizeof(PayloadHeader))
        << "\n";

    std::cout
        << "Header size:       "
        << sizeof(PayloadHeader)
        << " bytes\n";
    // --------------------------------------------------------
    // Записываем
    // --------------------------------------------------------

    std::cout
        << "[5] Writing output...\n";

    if (!WriteFileData(
            outputPath,
            output))
    {
        std::cerr
            << "Cannot write output file: "
            << outputPath
            << "\n";

        return 1;
    }

    std::cout
        << "\n"
        << "Packed successfully!\n"
        << "Output: "
        << outputPath
        << "\n";

    return 0;
}