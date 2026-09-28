using System.Runtime.InteropServices;

namespace Dependencies.ClrPh;

internal static partial class NativeMethods
{
    private const string LibraryName = "DependenciesNative.dll";

    [LibraryImport(LibraryName, EntryPoint = "DN_Initialize")]
    internal static partial int Initialize();

    [LibraryImport(LibraryName, EntryPoint = "DN_FileExists", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int FileExists(string path, int folders);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_Open", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial nint OpenPe(string path);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_Close")]
    internal static partial void ClosePe(nint pe);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_GetProperties")]
    internal static unsafe partial int GetPeProperties(nint pe, NativePeProperties* properties);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_ExportCount")]
    internal static partial uint GetExportCount(nint pe);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_GetExport")]
    internal static unsafe partial int GetExport(nint pe, uint index, NativePeExport* export);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_ImportDllCount")]
    internal static partial uint GetImportDllCount(nint pe);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_GetImportDll")]
    internal static unsafe partial int GetImportDll(nint pe, uint index, NativePeImportDll* importDll);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_GetImport")]
    internal static unsafe partial int GetImport(nint pe, uint dllIndex, uint index, NativePeImport* import);

    [LibraryImport(LibraryName, EntryPoint = "DN_PE_GetManifest")]
    internal static unsafe partial int GetManifest(nint pe, byte* buffer, int capacity);

    [LibraryImport(LibraryName, EntryPoint = "DN_ApiSet_Count")]
    internal static partial uint GetApiSetCount(nint pe);

    [LibraryImport(LibraryName, EntryPoint = "DN_ApiSet_GetName")]
    internal static unsafe partial int GetApiSetName(nint pe, uint index, char* buffer, int capacity);

    [LibraryImport(LibraryName, EntryPoint = "DN_ApiSet_TargetCount")]
    internal static partial uint GetApiSetTargetCount(nint pe, uint index);

    [LibraryImport(LibraryName, EntryPoint = "DN_ApiSet_GetTarget")]
    internal static unsafe partial int GetApiSetTarget(nint pe, uint index, uint targetIndex, char* buffer, int capacity);

    [LibraryImport(LibraryName, EntryPoint = "DN_KnownDll_Count")]
    internal static partial uint GetKnownDllCount(int wow64);

    [LibraryImport(LibraryName, EntryPoint = "DN_KnownDll_Get")]
    internal static unsafe partial int GetKnownDll(int wow64, uint index, char* buffer, int capacity);

    [LibraryImport(LibraryName, EntryPoint = "DN_Demangle", StringMarshalling = StringMarshalling.Utf16)]
    internal static unsafe partial int Demangle(string decoratedName, int mode, char* buffer, int capacity, int* actualMode);
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativePeProperties
{
    internal short Machine;
    internal short Magic;
    internal long ImageBase;
    internal int SizeOfImage;
    internal long EntryPoint;
    internal int Checksum;
    internal int CorrectChecksum;
    internal short Subsystem;
    internal short SubsystemMajor;
    internal short SubsystemMinor;
    internal short Characteristics;
    internal short DllCharacteristics;
    internal ulong FileSize;
    internal uint TimeDateStamp;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct NativePeExport
{
    internal ushort Ordinal;
    internal int ExportByOrdinal;
    internal long VirtualAddress;
    internal fixed char Name[512];
    internal fixed char ForwardedName[512];
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct NativePeImportDll
{
    internal long Flags;
    internal long NumberOfEntries;
    internal fixed char Name[512];
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct NativePeImport
{
    internal ushort Hint;
    internal ushort Ordinal;
    internal int ImportByOrdinal;
    internal int DelayImport;
    internal fixed char Name[512];
    internal fixed char ModuleName[512];
}