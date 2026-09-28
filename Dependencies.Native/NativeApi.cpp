#include <ph.h>
#include <phconfig.h>
#include <mapimg.h>
#include <ApiSetNative.h>
#include <llvm/Demangle/Demangle.h>
#include <dbghelp.h>

#include <algorithm>
#include <cwchar>
#include <mutex>
#include <string>
#include <vector>

extern "C" char* __cxa_demangle(const char*, char*, size_t*, int*);

struct DN_PE_PROPERTIES
{
    SHORT Machine;
    SHORT Magic;
    LONGLONG ImageBase;
    LONG SizeOfImage;
    LONGLONG EntryPoint;
    LONG Checksum;
    LONG CorrectChecksum;
    SHORT Subsystem;
    SHORT SubsystemMajor;
    SHORT SubsystemMinor;
    SHORT Characteristics;
    SHORT DllCharacteristics;
    ULONGLONG FileSize;
    ULONG TimeDateStamp;
};

struct DN_EXPORT
{
    USHORT Ordinal;
    LONG ExportByOrdinal;
    LONGLONG VirtualAddress;
    WCHAR Name[512];
    WCHAR ForwardedName[512];
};

struct DN_IMPORT_DLL
{
    LONGLONG Flags;
    LONGLONG NumberOfEntries;
    WCHAR Name[512];
};

struct DN_IMPORT
{
    USHORT Hint;
    USHORT Ordinal;
    LONG ImportByOrdinal;
    LONG DelayImport;
    WCHAR Name[512];
    WCHAR ModuleName[512];
};

struct ApiSetEntry
{
    std::wstring Name;
    std::vector<std::wstring> Targets;
};

struct PeHandle
{
    PH_MAPPED_IMAGE Image{};
    PH_MAPPED_IMAGE_EXPORTS Exports{};
    PH_MAPPED_IMAGE_IMPORTS Imports{};
    PH_MAPPED_IMAGE_IMPORTS DelayImports{};
    bool HasExports = false;
    bool HasImports = false;
    bool HasDelayImports = false;
    std::vector<ApiSetEntry> ApiSet;
    bool ApiSetLoaded = false;
};

static std::once_flag InitializationOnce;
static LONG InitializationResult = 0;
static std::once_flag KnownDllsOnce;
static std::vector<std::wstring> KnownDlls64;
static std::vector<std::wstring> KnownDlls32;
static std::vector<ApiSetEntry> ProcessApiSet;
static std::once_flag ProcessApiSetOnce;

static void CopyText(const std::wstring& value, WCHAR* buffer, int capacity)
{
    if (!buffer || capacity <= 0)
        return;

    const size_t count = (std::min)(value.size(), static_cast<size_t>(capacity - 1));
    if (count != 0)
        std::wmemcpy(buffer, value.data(), count);
    buffer[count] = L'\0';
}

static void CopyAnsiText(const char* value, WCHAR* buffer, int capacity)
{
    if (!buffer || capacity <= 0)
        return;

    buffer[0] = L'\0';
    if (!value)
        return;

    MultiByteToWideChar(CP_ACP, 0, value, -1, buffer, capacity);
}

static std::wstring ReadWideString(ULONG_PTR base, ULONG offset, ULONG length)
{
    const auto buffer = reinterpret_cast<const WCHAR*>(base + offset);
    return std::wstring(buffer, length / sizeof(WCHAR));
}

static void ParseApiSet(ApiSetEntry* entry, const DN_API_SET_NAMESPACE* apiSetMap)
{
    if (!apiSetMap)
        return;

    const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(apiSetMap);
    switch (apiSetMap->Version)
    {
    case 2:
    {
        const auto map = &apiSetMap->ApiSetNameSpaceV2;
        for (ULONG i = 0; i < map->Count; ++i)
        {
            const auto& item = map->Array[i];
            auto* values = reinterpret_cast<DN_API_SET_VALUE_ENTRY_V2*>(base + item.DataOffset);
            ApiSetEntry result;
            result.Name = ReadWideString(base, item.NameOffset, item.NameLength);
            for (ULONG j = 0; j < values->NumberOfRedirections; ++j)
            {
                const auto& redirect = values->Redirections[j];
                result.Targets.push_back(ReadWideString(base, redirect.ValueOffset, redirect.ValueLength));
            }
            entry[i] = std::move(result);
        }
        break;
    }
    case 4:
    {
        const auto map = &apiSetMap->ApiSetNameSpaceV4;
        for (ULONG i = 0; i < map->Count; ++i)
        {
            const auto& item = map->Array[i];
            auto* values = reinterpret_cast<DN_API_SET_VALUE_ENTRY_V4*>(base + item.DataOffset);
            ApiSetEntry result;
            result.Name = ReadWideString(base, item.NameOffset, item.NameLength);
            for (ULONG j = 0; j < values->NumberOfRedirections; ++j)
            {
                const auto& redirect = values->Redirections[j];
                result.Targets.push_back(ReadWideString(base, redirect.ValueOffset, redirect.ValueLength));
            }
            entry[i] = std::move(result);
        }
        break;
    }
    case 6:
    {
        const auto map = &apiSetMap->ApiSetNameSpaceV6;
        const auto items = reinterpret_cast<DN_API_SET_NAMESPACE_ENTRY_V6*>(base + map->EntryOffset);
        for (ULONG i = 0; i < map->Count; ++i)
        {
            const auto& item = items[i];
            const auto values = reinterpret_cast<DN_API_SET_VALUE_ENTRY_V6*>(base + item.ValueOffset);
            ApiSetEntry result;
            result.Name = ReadWideString(base, item.NameOffset, item.NameLength);
            for (ULONG j = 0; j < item.ValueCount; ++j)
            {
                const auto& value = values[j];
                result.Targets.push_back(ReadWideString(base, value.ValueOffset, value.ValueLength));
            }
            entry[i] = std::move(result);
        }
        break;
    }
    default:
        break;
    }
}

static std::vector<ApiSetEntry>& GetProcessApiSet()
{
    std::call_once(ProcessApiSetOnce, []
    {
        auto map = static_cast<PDN_API_SET_NAMESPACE>(NtCurrentPeb()->ApiSetMap);
        if (!map)
            return;

        ULONG count = 0;
        if (map->Version == 2)
            count = map->ApiSetNameSpaceV2.Count;
        else if (map->Version == 4)
            count = map->ApiSetNameSpaceV4.Count;
        else if (map->Version == 6)
            count = map->ApiSetNameSpaceV6.Count;

        ProcessApiSet.resize(count);
        ParseApiSet(ProcessApiSet.data(), map);
    });
    return ProcessApiSet;
}

static std::vector<ApiSetEntry>& GetApiSet(PeHandle* pe)
{
    if (!pe)
        return GetProcessApiSet();

    if (!pe->ApiSetLoaded)
    {
        pe->ApiSetLoaded = true;
        for (ULONG i = 0; i < pe->Image.NumberOfSections; ++i)
        {
            const auto& section = pe->Image.Sections[i];
            if (strncmp(".apiset", reinterpret_cast<const char*>(section.Name), IMAGE_SIZEOF_SHORT_NAME) == 0)
            {
                const auto map = reinterpret_cast<PDN_API_SET_NAMESPACE>(
                    static_cast<BYTE*>(pe->Image.ViewBase) + section.PointerToRawData);
                ULONG count = map->Version == 2 ? map->ApiSetNameSpaceV2.Count :
                    map->Version == 4 ? map->ApiSetNameSpaceV4.Count :
                    map->Version == 6 ? map->ApiSetNameSpaceV6.Count : 0;
                pe->ApiSet.resize(count);
                ParseApiSet(pe->ApiSet.data(), map);
                break;
            }
        }
    }
    return pe->ApiSet;
}

static BOOLEAN NTAPI KnownDllCallback(PPH_STRINGREF name, PPH_STRINGREF, PVOID context)
{
    auto list = static_cast<std::vector<std::wstring>*>(context);
    list->emplace_back(name->Buffer, name->Length / sizeof(WCHAR));
    return TRUE;
}

static void BuildKnownDlls()
{
    std::call_once(KnownDllsOnce, []
    {
        const WCHAR* paths[] = { L"\\KnownDlls", L"\\KnownDlls32" };
        std::vector<std::wstring>* lists[] = { &KnownDlls64, &KnownDlls32 };
        for (int i = 0; i < 2; ++i)
        {
            UNICODE_STRING name;
            RtlInitUnicodeString(&name, const_cast<PWSTR>(paths[i]));
            OBJECT_ATTRIBUTES attributes;
            InitializeObjectAttributes(&attributes, &name, 0, nullptr, nullptr);
            HANDLE directory = nullptr;
            if (NT_SUCCESS(NtOpenDirectoryObject(&directory, DIRECTORY_QUERY, &attributes)))
            {
                PhEnumDirectoryObjects(directory, KnownDllCallback, lists[i]);
                NtClose(directory);
                std::sort(lists[i]->begin(), lists[i]->end());
            }
        }
    });
}

static std::string ToUtf8(const WCHAR* value)
{
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1)
        return {};
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), length, nullptr, nullptr);
    result.resize(static_cast<size_t>(length - 1));
    return result;
}

static std::wstring FromUtf8(const char* value)
{
    const int length = MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
    if (length <= 1)
        return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value, -1, result.data(), length);
    result.resize(static_cast<size_t>(length - 1));
    return result;
}

static bool TryDemangle(const std::wstring& input, int mode, int* actualMode, std::wstring* output)
{
    const auto utf8 = ToUtf8(input.c_str());
    if (utf8.empty())
        return false;

    if (mode == 1 || mode == 5)
    {
        size_t length = 0;
        int status = 0;
        char* result = __cxa_demangle(utf8.c_str(), nullptr, &length, &status);
        if (status == 0 && result)
        {
            *output = FromUtf8(result);
            *actualMode = 1;
            free(result);
            return true;
        }
        free(result);
        if (mode == 1)
            return false;
    }

    if ((mode == 2 || mode == 5) && input.rfind(L"_Z", 0) == 0)
    {
        size_t length = 0;
        int status = 0;
        char* result = llvm::itaniumDemangle(utf8.c_str(), nullptr, &length, &status);
        if (status == 0 && result)
        {
            *output = FromUtf8(result);
            *actualMode = 2;
            free(result);
            return true;
        }
        free(result);
        if (mode == 2)
            return false;
    }

    if (mode == 4 || mode == 5)
    {
        WCHAR buffer[4096]{};
        using UndecorateSymbolNameFn = DWORD(WINAPI*)(PCWSTR, PWSTR, DWORD, DWORD);
        static const auto dbghelp = LoadLibraryExW(L"dbghelp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        static const auto undecorate = dbghelp ? reinterpret_cast<UndecorateSymbolNameFn>(
            GetProcAddress(dbghelp, "UnDecorateSymbolNameW")) : nullptr;
        if (undecorate && undecorate(input.c_str(), buffer, ARRAYSIZE(buffer), UNDNAME_COMPLETE) != 0 &&
            wcscmp(input.c_str(), buffer) != 0)
        {
            *output = buffer;
            *actualMode = 4;
            return true;
        }
        if (mode == 4)
            return false;
    }

    if (mode == 3 || mode == 5)
    {
        size_t length = 0;
        int status = 0;
        char* result = llvm::microsoftDemangle(utf8.c_str(), nullptr, &length, &status);
        if (status == 0 && result)
        {
            *output = FromUtf8(result);
            *actualMode = 3;
            free(result);
            return true;
        }
        free(result);
    }
    return false;
}

extern "C" __declspec(dllexport) int __cdecl DN_Initialize()
{
    std::call_once(InitializationOnce, [] { InitializationResult = PhInitializePhLib(); });
    return NT_SUCCESS(InitializationResult);
}

extern "C" __declspec(dllexport) int __cdecl DN_FileExists(const WCHAR* path, int folders)
{
    if (!path)
        return 0;
    const DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (folders || !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

extern "C" __declspec(dllexport) PeHandle* __cdecl DN_PE_Open(const WCHAR* path)
{
    if (!path || !DN_Initialize())
        return nullptr;
    auto pe = new PeHandle();
    if (!NT_SUCCESS(PhLoadMappedImage(const_cast<PWSTR>(path), nullptr, TRUE, &pe->Image)))
    {
        delete pe;
        return nullptr;
    }
    return pe;
}

extern "C" __declspec(dllexport) void __cdecl DN_PE_Close(PeHandle* pe)
{
    if (pe)
    {
        PhUnloadMappedImage(&pe->Image);
        delete pe;
    }
}

extern "C" __declspec(dllexport) int __cdecl DN_PE_GetProperties(PeHandle* pe, DN_PE_PROPERTIES* result)
{
    if (!pe || !result || !pe->Image.NtHeaders)
        return 0;

    const auto headers = pe->Image.NtHeaders;
    result->Machine = headers->FileHeader.Machine;
    result->Magic = pe->Image.Magic;
    result->Checksum = headers->OptionalHeader.CheckSum;
    result->CorrectChecksum = result->Checksum == PhCheckSumMappedImage(&pe->Image);
    result->TimeDateStamp = headers->FileHeader.TimeDateStamp;
    result->Subsystem = headers->OptionalHeader.Subsystem;
    result->SubsystemMajor = headers->OptionalHeader.MajorSubsystemVersion;
    result->SubsystemMinor = headers->OptionalHeader.MinorSubsystemVersion;
    result->Characteristics = headers->FileHeader.Characteristics;
    result->DllCharacteristics = headers->OptionalHeader.DllCharacteristics;
    result->FileSize = pe->Image.Size;

    if (pe->Image.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        const auto optional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&headers->OptionalHeader);
        result->ImageBase = optional->ImageBase;
        result->SizeOfImage = optional->SizeOfImage;
        result->EntryPoint = optional->AddressOfEntryPoint;
    }
    else
    {
        const auto optional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&headers->OptionalHeader);
        result->ImageBase = static_cast<LONGLONG>(optional->ImageBase);
        result->SizeOfImage = optional->SizeOfImage;
        result->EntryPoint = optional->AddressOfEntryPoint;
    }
    return 1;
}

extern "C" __declspec(dllexport) ULONG __cdecl DN_PE_ExportCount(PeHandle* pe)
{
    if (!pe || !pe->HasExports)
        if (!pe || !NT_SUCCESS(PhGetMappedImageExports(&pe->Exports, &pe->Image)))
            return 0;
        else
            pe->HasExports = true;
    return pe->Exports.NumberOfEntries;
}

extern "C" __declspec(dllexport) int __cdecl DN_PE_GetExport(PeHandle* pe, ULONG index, DN_EXPORT* result)
{
    if (!pe || !result || index >= DN_PE_ExportCount(pe))
        return 0;
    PH_MAPPED_IMAGE_EXPORT_ENTRY entry{};
    PH_MAPPED_IMAGE_EXPORT_FUNCTION function{};
    if (!NT_SUCCESS(PhGetMappedImageExportEntry(&pe->Exports, index, &entry)) ||
        !NT_SUCCESS(PhGetMappedImageExportFunction(&pe->Exports, nullptr, entry.Ordinal, &function)))
        return 0;
    ZeroMemory(result, sizeof(*result));
    result->Ordinal = entry.Ordinal;
    result->ExportByOrdinal = entry.Name == nullptr;
    result->VirtualAddress = reinterpret_cast<LONGLONG>(function.Function);
    CopyAnsiText(entry.Name, result->Name, ARRAYSIZE(result->Name));
    CopyAnsiText(function.ForwardedName, result->ForwardedName, ARRAYSIZE(result->ForwardedName));
    return 1;
}

static ULONG GetImportDllCount(PeHandle* pe)
{
    if (!pe->HasImports)
    {
        pe->HasImports = NT_SUCCESS(PhGetMappedImageImports(&pe->Imports, &pe->Image));
        pe->HasDelayImports = NT_SUCCESS(PhGetMappedImageDelayImports(&pe->DelayImports, &pe->Image));
    }
    return (pe->HasImports ? pe->Imports.NumberOfDlls : 0) +
        (pe->HasDelayImports ? pe->DelayImports.NumberOfDlls : 0);
}

static bool GetImportDll(PeHandle* pe, ULONG index, PH_MAPPED_IMAGE_IMPORT_DLL* result)
{
    const ULONG count = GetImportDllCount(pe);
    if (!pe || index >= count)
        return false;
    const ULONG regularCount = pe->HasImports ? pe->Imports.NumberOfDlls : 0;
    if (index < regularCount)
        return NT_SUCCESS(PhGetMappedImageImportDll(&pe->Imports, index, result));
    return NT_SUCCESS(PhGetMappedImageImportDll(&pe->DelayImports, index - regularCount, result));
}

extern "C" __declspec(dllexport) ULONG __cdecl DN_PE_ImportDllCount(PeHandle* pe)
{
    return pe ? GetImportDllCount(pe) : 0;
}

extern "C" __declspec(dllexport) int __cdecl DN_PE_GetImportDll(PeHandle* pe, ULONG index, DN_IMPORT_DLL* result)
{
    if (!pe || !result)
        return 0;
    PH_MAPPED_IMAGE_IMPORT_DLL dll{};
    if (!GetImportDll(pe, index, &dll))
        return 0;
    ZeroMemory(result, sizeof(*result));
    result->Flags = dll.Flags;
    result->NumberOfEntries = dll.NumberOfEntries;
    CopyAnsiText(dll.Name, result->Name, ARRAYSIZE(result->Name));
    return 1;
}

extern "C" __declspec(dllexport) int __cdecl DN_PE_GetImport(PeHandle* pe, ULONG dllIndex, ULONG index, DN_IMPORT* result)
{
    if (!pe || !result)
        return 0;
    PH_MAPPED_IMAGE_IMPORT_DLL dll{};
    PH_MAPPED_IMAGE_IMPORT_ENTRY entry{};
    if (!GetImportDll(pe, dllIndex, &dll) || index >= dll.NumberOfEntries ||
        !NT_SUCCESS(PhGetMappedImageImportEntry(&dll, index, &entry)))
        return 0;
    ZeroMemory(result, sizeof(*result));
    result->Hint = entry.NameHint;
    result->Ordinal = entry.Ordinal;
    result->ImportByOrdinal = entry.Name == nullptr;
    result->DelayImport = (dll.Flags & PH_MAPPED_IMAGE_DELAY_IMPORTS) != 0;
    CopyAnsiText(entry.Name, result->Name, ARRAYSIZE(result->Name));
    CopyAnsiText(dll.Name, result->ModuleName, ARRAYSIZE(result->ModuleName));
    return 1;
}

extern "C" __declspec(dllexport) int __cdecl DN_PE_GetManifest(PeHandle* pe, BYTE* buffer, int capacity)
{
    if (!pe)
        return 0;
    PH_MAPPED_IMAGE_RESOURCES resources{};
    if (!NT_SUCCESS(PhGetMappedImageResources(&resources, &pe->Image)))
        return 0;
    const BYTE* manifest = nullptr;
    ULONG size = 0;
    for (ULONG i = 0; i < resources.NumberOfEntries; ++i)
    {
        if (resources.ResourceEntries[i].Type == reinterpret_cast<ULONG_PTR>(RT_MANIFEST))
        {
            manifest = static_cast<const BYTE*>(resources.ResourceEntries[i].Data);
            size = resources.ResourceEntries[i].Size;
            break;
        }
    }
    if (manifest && buffer && capacity >= static_cast<int>(size))
        memcpy(buffer, manifest, size);
    PhFree(resources.ResourceEntries);
    return static_cast<int>(size);
}

extern "C" __declspec(dllexport) ULONG __cdecl DN_ApiSet_Count(PeHandle* pe)
{
    return static_cast<ULONG>(GetApiSet(pe).size());
}

extern "C" __declspec(dllexport) int __cdecl DN_ApiSet_GetName(PeHandle* pe, ULONG index, WCHAR* buffer, int capacity)
{
    auto& schema = GetApiSet(pe);
    if (index >= schema.size())
        return 0;
    CopyText(schema[index].Name, buffer, capacity);
    return 1;
}

extern "C" __declspec(dllexport) ULONG __cdecl DN_ApiSet_TargetCount(PeHandle* pe, ULONG index)
{
    auto& schema = GetApiSet(pe);
    return index < schema.size() ? static_cast<ULONG>(schema[index].Targets.size()) : 0;
}

extern "C" __declspec(dllexport) int __cdecl DN_ApiSet_GetTarget(PeHandle* pe, ULONG index, ULONG targetIndex, WCHAR* buffer, int capacity)
{
    auto& schema = GetApiSet(pe);
    if (index >= schema.size() || targetIndex >= schema[index].Targets.size())
        return 0;
    CopyText(schema[index].Targets[targetIndex], buffer, capacity);
    return 1;
}

extern "C" __declspec(dllexport) ULONG __cdecl DN_KnownDll_Count(int wow64)
{
    BuildKnownDlls();
    return static_cast<ULONG>((wow64 ? KnownDlls32 : KnownDlls64).size());
}

extern "C" __declspec(dllexport) int __cdecl DN_KnownDll_Get(int wow64, ULONG index, WCHAR* buffer, int capacity)
{
    BuildKnownDlls();
    const auto& list = wow64 ? KnownDlls32 : KnownDlls64;
    if (index >= list.size())
        return 0;
    CopyText(list[index], buffer, capacity);
    return 1;
}

extern "C" __declspec(dllexport) int __cdecl DN_Demangle(const WCHAR* decoratedName, int mode, WCHAR* buffer, int capacity, int* actualMode)
{
    if (!decoratedName || !buffer || capacity <= 0 || !actualMode)
        return 0;
    std::wstring output;
    int selectedMode = 0;
    if (!TryDemangle(decoratedName, mode, &selectedMode, &output))
        return 0;
    CopyText(output, buffer, capacity);
    *actualMode = selectedMode;
    return 1;
}