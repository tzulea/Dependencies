using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Dependencies.ClrPh;

public enum CLRPH_ARCH
{
    x86,
    x64,
    WOW64
}

public enum CLRPH_DEMANGLER
{
    None,
    Demumble,
    LLVMItanium,
    LLVMMicrosoft,
    Microsoft,
    Default
}

public sealed class ApiSetTarget : List<string>
{
}

public abstract class ApiSetSchema
{
    public abstract List<KeyValuePair<string, ApiSetTarget>> GetAll();
    public abstract ApiSetTarget Lookup(string name);
}

public static class Phlib
{
    private static readonly Lazy<List<string>> KnownDlls64Value = new(() => ReadKnownDlls(false));
    private static readonly Lazy<List<string>> KnownDlls32Value = new(() => ReadKnownDlls(true));

    public static List<string> KnownDll64List => KnownDlls64Value.Value;
    public static List<string> KnownDll32List => KnownDlls32Value.Value;

    public static CLRPH_ARCH GetClrPhArch() => Environment.Is64BitProcess ? CLRPH_ARCH.x64 : CLRPH_ARCH.x86;

    public static bool InitializePhLib() => NativeMethods.Initialize() != 0;

    public static List<string> GetKnownDlls(bool wow64Dlls) =>
        new(wow64Dlls ? KnownDll32List : KnownDll64List);

    public static ApiSetSchema GetApiSetSchema()
    {
        InitializePhLib();
        return new NativeApiSetSchema(0);
    }

    private static List<string> ReadKnownDlls(bool wow64)
    {
        InitializePhLib();
        var result = new List<string>();
        var count = NativeMethods.GetKnownDllCount(wow64 ? 1 : 0);
        unsafe
        {
            char* buffer = stackalloc char[512];
            for (uint i = 0; i < count; i++)
            {
                buffer[0] = '\0';
                if (NativeMethods.GetKnownDll(wow64 ? 1 : 0, i, buffer, 512) != 0)
                    result.Add(new string(buffer));
            }
        }
        return result;
    }
}

public sealed class PeProperties
{
    public short Machine;
    public DateTime Time;
    public short Magic;
    public long ImageBase;
    public int SizeOfImage;
    public long EntryPoint;
    public int Checksum;
    public bool CorrectChecksum;
    public short Subsystem;
    public Tuple<short, short> SubsystemVersion;
    public short Characteristics;
    public short DllCharacteristics;
    public ulong FileSize;
}

public sealed class PeImport
{
    public ushort Hint;
    public ushort Ordinal;
    public string Name;
    public string ModuleName;
    public bool ImportByOrdinal;
    public bool DelayImport;
}

public sealed class PeImportDll
{
    public long Flags;
    public string Name;
    public long NumberOfEntries;
    public List<PeImport> ImportList;

    public bool IsDelayLoad() => (Flags & 1) != 0;
}

public sealed class PeExport
{
    public ushort Ordinal;
    public string Name;
    public bool ExportByOrdinal;
    public long VirtualAddress;
    public string ForwardedName;
}

public sealed class PE : IDisposable
{
    private nint _nativeHandle;
    private List<PeExport> _exports;
    private List<PeImportDll> _imports;

    public PE(string filepath)
    {
        Filepath = filepath;
    }

    public PeProperties Properties { get; private set; }
    public bool LoadSuccessful { get; private set; }
    public string Filepath { get; set; }

    public bool Load()
    {
        Unload();
        if (!Phlib.InitializePhLib())
            return false;

        _nativeHandle = NativeMethods.OpenPe(Filepath);
        if (_nativeHandle == 0)
            return false;

        unsafe
        {
            NativePeProperties nativeProperties = default;
            if (NativeMethods.GetPeProperties(_nativeHandle, &nativeProperties) == 0)
            {
                Unload();
                return false;
            }

            Properties = new PeProperties
            {
                Machine = nativeProperties.Machine,
                Magic = nativeProperties.Magic,
                ImageBase = nativeProperties.ImageBase,
                SizeOfImage = nativeProperties.SizeOfImage,
                EntryPoint = nativeProperties.EntryPoint,
                Checksum = nativeProperties.Checksum,
                CorrectChecksum = nativeProperties.CorrectChecksum != 0,
                Subsystem = nativeProperties.Subsystem,
                SubsystemVersion = Tuple.Create(nativeProperties.SubsystemMajor, nativeProperties.SubsystemMinor),
                Characteristics = nativeProperties.Characteristics,
                DllCharacteristics = nativeProperties.DllCharacteristics,
                FileSize = nativeProperties.FileSize,
                Time = DateTimeOffset.FromUnixTimeSeconds(nativeProperties.TimeDateStamp).LocalDateTime
            };
        }

        LoadSuccessful = true;
        return true;
    }

    public void Unload()
    {
        if (_nativeHandle != 0)
        {
            NativeMethods.ClosePe(_nativeHandle);
            _nativeHandle = 0;
        }
        LoadSuccessful = false;
        _exports = null;
        _imports = null;
    }

    public bool IsWow64Dll() => Properties != null && Properties.Machine == 0x14c;
    public bool IsArm32Dll() => Properties != null && Properties.Machine == 0x1c4;

    public string GetProcessor() => Properties?.Machine switch
    {
        0x14c => "x86",
        0x1c4 => "arm",
        unchecked((short)0xaa64) => "arm64",
        _ => "unknown"
    };

    public ApiSetSchema GetApiSetSchema() => new NativeApiSetSchema(_nativeHandle);

    public List<PeExport> GetExports()
    {
        if (_exports != null)
            return _exports;
        _exports = new List<PeExport>();
        if (!LoadSuccessful)
            return _exports;

        unsafe
        {
            var count = NativeMethods.GetExportCount(_nativeHandle);
            for (uint i = 0; i < count; i++)
            {
                NativePeExport nativeExport = default;
                if (NativeMethods.GetExport(_nativeHandle, i, &nativeExport) == 0)
                    continue;
                char* name = nativeExport.Name;
                char* forwardedName = nativeExport.ForwardedName;
                {
                    _exports.Add(new PeExport
                    {
                        Ordinal = nativeExport.Ordinal,
                        ExportByOrdinal = nativeExport.ExportByOrdinal != 0,
                        VirtualAddress = nativeExport.VirtualAddress,
                        Name = new string(name),
                        ForwardedName = new string(forwardedName)
                    });
                }
            }
        }
        return _exports;
    }

    public List<PeImportDll> GetImports()
    {
        if (_imports != null)
            return _imports;
        _imports = new List<PeImportDll>();
        if (!LoadSuccessful)
            return _imports;

        unsafe
        {
            var dllCount = NativeMethods.GetImportDllCount(_nativeHandle);
            for (uint dllIndex = 0; dllIndex < dllCount; dllIndex++)
            {
                NativePeImportDll nativeDll = default;
                if (NativeMethods.GetImportDll(_nativeHandle, dllIndex, &nativeDll) == 0)
                    continue;

                var importDll = new PeImportDll
                {
                    Flags = nativeDll.Flags,
                    NumberOfEntries = nativeDll.NumberOfEntries,
                    ImportList = new List<PeImport>()
                };
                char* name = nativeDll.Name;
                importDll.Name = new string(name);

                for (uint importIndex = 0; importIndex < nativeDll.NumberOfEntries; importIndex++)
                {
                    NativePeImport nativeImport = default;
                    if (NativeMethods.GetImport(_nativeHandle, dllIndex, importIndex, &nativeImport) == 0)
                        continue;
                    char* importName = nativeImport.Name;
                    char* moduleName = nativeImport.ModuleName;
                    {
                        importDll.ImportList.Add(new PeImport
                        {
                            Hint = nativeImport.Hint,
                            Ordinal = nativeImport.Ordinal,
                            ImportByOrdinal = nativeImport.ImportByOrdinal != 0,
                            DelayImport = nativeImport.DelayImport != 0,
                            Name = new string(importName),
                            ModuleName = new string(moduleName)
                        });
                    }
                }
                _imports.Add(importDll);
            }
        }
        return _imports;
    }

    public string GetManifest()
    {
        if (!LoadSuccessful)
            return string.Empty;
        unsafe
        {
            var byteCount = NativeMethods.GetManifest(_nativeHandle, null, 0);
            if (byteCount <= 0)
                return string.Empty;
            var bytes = new byte[byteCount];
            fixed (byte* buffer = bytes)
                NativeMethods.GetManifest(_nativeHandle, buffer, bytes.Length);
            return Encoding.UTF8.GetString(bytes);
        }
    }

    public void Dispose()
    {
        Unload();
        GC.SuppressFinalize(this);
    }

    ~PE() => Unload();
}

public sealed class NativeApiSetSchema : ApiSetSchema
{
    private readonly List<KeyValuePair<string, ApiSetTarget>> _entries = new();

    internal NativeApiSetSchema(nint pe)
    {
        unsafe
        {
            var count = NativeMethods.GetApiSetCount(pe);
            char* buffer = stackalloc char[512];
            for (uint i = 0; i < count; i++)
            {
                buffer[0] = '\0';
                if (NativeMethods.GetApiSetName(pe, i, buffer, 512) == 0)
                    continue;
                var name = new string(buffer).ToLowerInvariant();
                var targets = new ApiSetTarget();
                var targetCount = NativeMethods.GetApiSetTargetCount(pe, i);
                for (uint j = 0; j < targetCount; j++)
                {
                    buffer[0] = '\0';
                    if (NativeMethods.GetApiSetTarget(pe, i, j, buffer, 512) != 0)
                        targets.Add(new string(buffer));
                }
                _entries.Add(new KeyValuePair<string, ApiSetTarget>(name, targets));
            }
        }
    }

    public override List<KeyValuePair<string, ApiSetTarget>> GetAll() => new(_entries);

    public override ApiSetTarget Lookup(string name)
    {
        if (string.IsNullOrEmpty(name))
            return null;
        var normalized = name.ToLowerInvariant();
        foreach (var entry in _entries)
        {
            if (string.Equals(normalized, entry.Key, StringComparison.Ordinal) ||
                normalized.StartsWith(entry.Key, StringComparison.Ordinal))
                return entry.Value;
        }
        return null;
    }
}

public static class NativeFile
{
    public static bool Exists(string path) => Exists(path, false);
    public static bool Exists(string path, bool isFolder) => NativeMethods.FileExists(path, isFolder ? 1 : 0) != 0;

    public static void Copy(string sourceFileName, string destFileName) => File.Copy(sourceFileName, destFileName, true);

    public static string GetPartialHashFile(string path, long fileSize)
    {
        try
        {
            if (fileSize < 0 || fileSize > int.MaxValue)
                return string.Empty;
            var buffer = new byte[(int)fileSize];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = stream.Read(buffer, totalRead, buffer.Length - totalRead);
                if (read == 0)
                    return string.Empty;
                totalRead += read;
            }
            return Convert.ToHexString(SHA256.HashData(buffer));
        }
        catch
        {
            return string.Empty;
        }
    }
}

public class PhSymbolProvider : IDisposable
{
    public virtual Tuple<CLRPH_DEMANGLER, string> UndecorateName(string decoratedName)
    {
        return Undecorate(decoratedName, (int)CLRPH_DEMANGLER.Default);
    }

    protected string UndecorateNameDemumble(string decoratedName) => Undecorate(decoratedName, 1).Item2;
    protected string UndecorateNameLLVMItanium(string decoratedName) => Undecorate(decoratedName, 2).Item2;
    protected string UndecorateNameLLVMMicrosoft(string decoratedName) => Undecorate(decoratedName, 3).Item2;
    protected string UndecorateNamePh(string decoratedName) => Undecorate(decoratedName, 4).Item2;

    private static Tuple<CLRPH_DEMANGLER, string> Undecorate(string decoratedName, int mode)
    {
        if (string.IsNullOrEmpty(decoratedName))
            return Tuple.Create(CLRPH_DEMANGLER.None, string.Empty);
        unsafe
        {
            char* buffer = stackalloc char[4096];
            int actualMode = 0;
            if (NativeMethods.Demangle(decoratedName, mode, buffer, 4096, &actualMode) == 0)
                return Tuple.Create(CLRPH_DEMANGLER.None, string.Empty);
            return Tuple.Create((CLRPH_DEMANGLER)actualMode, new string(buffer));
        }
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}