// Endpoint Outpost: content prefilter coupled to php-detect.yar SHA-256.
// C# 5 / .NET Framework 4.6+: works in Windows PowerShell 5.1 without installs.
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class PhpFilterStats
{
    public long Files, Directories, Candidates, CandidateBytes, PrefilterBytes, HeaderFiltered;
    public long SizeSkipped, LinksSkipped, CloudSkipped, Errors, VanishedSkipped, ExpectedSkipped;
    public long StructuralSkipped, StructuralBytes, ExcludedDirectories, DataFilesSkipped, NameSkipped;
    public long CustomExcludedTrees, CustomDirectDirectories, CustomExcludedFiles;
    public double Seconds;
    public string BudgetReason = "";
    public bool BackgroundMode;
    public List<string> ErrorSamples = new List<string>();
}

// Shared normalization and literal-plus-asterisk matching. No regex evaluation,
// shell expansion, filesystem access or environment-variable expansion of user input.
public sealed class PhpDirectoryExclusions
{
    public readonly List<string> Patterns = new List<string>();
    private readonly List<string> trees = new List<string>();
    private readonly List<string> direct = new List<string>();

    public PhpDirectoryExclusions(string encoded)
    {
        if (encoded == null || encoded.Length > 8193 || encoded.Length % 2 != 1 || encoded[0] != 'x')
            throw new ArgumentException("Invalid encoded directory exclusions");
        byte[] bytes = new byte[(encoded.Length - 1) / 2];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(encoded.Substring(1 + i * 2, 2), 16);
        string text = new UTF8Encoding(false, true).GetString(bytes);
        foreach (char value in text) if (value < 32 || value == 127) throw new ArgumentException("Control character in exclusions");
        foreach (string entry in text.Split(','))
        {
            string pattern = entry.Trim().Replace('\\', '/');
            if (pattern.Length == 0) continue;
            if (Patterns.Count >= 32) throw new ArgumentException("At most 32 exclusions allowed");
            while (pattern.Contains("//")) pattern = pattern.Replace("//", "/");
            while (pattern.Contains("**")) pattern = pattern.Replace("**", "*");
            if (!(pattern.StartsWith("*/", StringComparison.Ordinal) ||
                  (pattern.Length >= 3 && Char.IsLetter(pattern[0]) && pattern[1] == ':' && pattern[2] == '/')))
                throw new ArgumentException("Windows exclusions need a drive path or leading */");
            foreach (string part in pattern.Split('/'))
                if (part == "." || part == "..") throw new ArgumentException("Relative path segments are not allowed");
            Patterns.Add(pattern);
            bool subtree = pattern.EndsWith("/*", StringComparison.Ordinal);
            string basis = (subtree ? pattern.Substring(0, pattern.Length - 2) : pattern).TrimEnd('/').ToUpperInvariant();
            (subtree ? trees : direct).Add(basis);
        }
    }

    private static bool Match(string path, string pattern)
    {
        // Iterative glob matcher avoids regex backtracking and treats ?[] as literals.
        int p = 0, t = 0, star = -1, retry = 0;
        while (p < path.Length)
        {
            if (t < pattern.Length && pattern[t] != '*' && pattern[t] == path[p]) { p++; t++; }
            else if (t < pattern.Length && pattern[t] == '*') { star = t++; retry = p; }
            else if (star >= 0) { t = star + 1; p = ++retry; }
            else return false;
        }
        while (t < pattern.Length && pattern[t] == '*') t++;
        return t == pattern.Length;
    }

    public int Mode(string directory)
    {
        if (Patterns.Count == 0) return 0;
        if (directory.StartsWith(@"\\?\", StringComparison.Ordinal)) directory = directory.Substring(4);
        directory = directory.Replace('\\', '/').TrimEnd('/').ToUpperInvariant();
        // Match descendants too: separately ordered app roots cannot bypass an excluded ancestor.
        foreach (string pattern in trees)
            if (Match(directory, pattern) || Match(directory, pattern + "/*")) return 2;
        foreach (string pattern in direct) if (Match(directory, pattern)) return 1;
        return 0;
    }
}

public static class PhpCandidateFilter
{
    // PHP core, CGI/FPM/CLI/debug SAPIs, Apache modules and common embedded distributions.
    // Script/source files do not identify an installed runtime. Broad mode restores renamed binaries.
    public static bool StandardRuntimeName(string path)
    {
        string name = Path.GetFileName(path);
        string extension = Path.GetExtension(name);
        if (extension.Length != 0 && !extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) && !extension.Equals(".so", StringComparison.OrdinalIgnoreCase) &&
            !System.Text.RegularExpressions.Regex.IsMatch(extension, @"^\.[0-9][a-zA-Z0-9_-]*$")) return false;
        return System.Text.RegularExpressions.Regex.IsMatch(name,
            @"^(?:(?:php|phpdbg|libphp|mod_php|lsphp|frankenphp)(?:[0-9][0-9.]*(?:[-_][a-z0-9_.-]+)?|[-_][a-z0-9_.-]+)?(?:ts|nts|apache[0-9_]*)?)(?:\.exe|\.dll|\.so(?:\.[0-9]+)*)?$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    private const int CloudMask = 0x1000 | 0x40000 | 0x400000;
    private static readonly string WindowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string ProfilesDirectory = Path.Combine(Path.GetPathRoot(WindowsDirectory), "Users") + "\\";
    private static readonly string ServiceProfilesDirectory = Path.Combine(WindowsDirectory, "ServiceProfiles") + "\\";
    private static readonly string SystemProfileDirectory = Path.Combine(WindowsDirectory, @"System32\config\systemprofile") + "\\";
    private static readonly string ProgramFilesDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86Directory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    // Filename-based inventory scope, not a claim that these formats cannot
    // contain executable bytes. The broader-locations option restores them.
    private static readonly HashSet<string> DataExtensions = new HashSet<string>(new[] {
        ".mdf", ".ndf", ".ldf", ".ibd", ".myd", ".myi", ".sqlite", ".sqlite3",
        ".db", ".db3", ".bak", ".trn", ".dmp", ".dump", ".vhd", ".vhdx",
        ".vmdk", ".vdi", ".wim", ".esd", ".iso"
    }, StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> DefaultRelativeDirectories = new HashSet<string>(new[] {
        "Windows", "Windows.old", "$Windows.~BT", "$Windows.~WS", "Recovery", "$Recycle.Bin",
        "System Volume Information", "WindowsImageBackup", "FileHistory", @"Program Files\WindowsApps",
        @"Program Files (x86)\WindowsApps", @"ProgramData\Microsoft\Windows\WER"
    }, StringComparer.OrdinalIgnoreCase);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetPriorityClass(IntPtr process, uint priorityClass);

    private static string Extended(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Network root excluded");
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) throw new ArgumentException("Network root excluded");
        return @"\\?\" + Path.GetFullPath(path);
    }

    private static string Normal(string path)
    {
        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path.Substring(4) : path;
    }

    private static void RecordError(PhpFilterStats stats, string operation, string path, Exception error)
    {
        if (operation != "root" && (error is FileNotFoundException || error is DirectoryNotFoundException))
        {
            stats.VanishedSkipped++;
            return;
        }
        int code = error.HResult & 65535;
        if (operation == "read" && error is IOException && (code == 32 || code == 33) && (ExpectedLockedMetadata(path) || IsSmallLockFile(path)))
        {
            stats.ExpectedSkipped++;
            return;
        }
        stats.Errors++;
        if (stats.ErrorSamples.Count >= 200) return;
        string safe = Normal(path).Replace("\r", "\\r").Replace("\n", "\\n");
        if (safe.Length > 600) safe = safe.Substring(0, 600) + "...[truncated]";
        stats.ErrorSamples.Add(operation + " | type=" + error.GetType().Name + " | code=" + (error.HResult & 65535) + " | path=" + safe);
    }

    private static string ProfileRelativePath(string normal)
    {
        string prefix = ProfilesDirectory;
        if (normal.StartsWith(SystemProfileDirectory, StringComparison.OrdinalIgnoreCase)) return normal.Substring(SystemProfileDirectory.Length);
        if (normal.StartsWith(ServiceProfilesDirectory, StringComparison.OrdinalIgnoreCase)) prefix = ServiceProfilesDirectory;
        else if (!normal.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return "";
        string remainder = normal.Substring(prefix.Length);
        int separator = remainder.IndexOf('\\');
        return separator >= 0 ? remainder.Substring(separator + 1) : "";
    }

    private static bool IsSmallLockFile(string path)
    {
        string name = Path.GetFileName(Normal(path));
        if (!name.Equals("LOCK", StringComparison.OrdinalIgnoreCase) && !name.Equals(".lock", StringComparison.OrdinalIgnoreCase) && !name.Equals(".sLock", StringComparison.OrdinalIgnoreCase)) return false;
        try { return new FileInfo(path).Length <= 4096; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static bool ExpectedLockedMetadata(string path)
    {
        string normal = Normal(path);
        string windows = WindowsDirectory;
        if (normal.Equals(Path.Combine(Path.GetPathRoot(windows), "DumpStack.log.tmp"), StringComparison.OrdinalIgnoreCase)) return true;
        string relative = normal.StartsWith(windows + "\\", StringComparison.OrdinalIgnoreCase) ? normal.Substring(windows.Length + 1) : "";
        string extension = Path.GetExtension(normal);
        // SQL's canonical temporary transaction log is data, including when the
        // administrator puts TEMPDB outside Program Files. Other custom DB paths
        // remain coverage gaps when unreadable.
        if (Path.GetFileName(normal).Equals("templog.ldf", StringComparison.OrdinalIgnoreCase) &&
            Path.GetFileName(Path.GetDirectoryName(normal)).Equals("TEMPDB", StringComparison.OrdinalIgnoreCase)) return true;
        if ((extension.Equals(".mdf", StringComparison.OrdinalIgnoreCase) || extension.Equals(".ndf", StringComparison.OrdinalIgnoreCase) || extension.Equals(".ldf", StringComparison.OrdinalIgnoreCase)) &&
            Path.GetDirectoryName(normal).EndsWith(@"\MSSQL\DATA", StringComparison.OrdinalIgnoreCase))
        {
            foreach (string basePath in new[] { ProgramFilesDirectory, ProgramFilesX86Directory })
                if (basePath.Length != 0 && normal.StartsWith(Path.Combine(basePath, "Microsoft SQL Server") + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        string userRelative = ProfileRelativePath(normal);
        const string packagePrefix = @"AppData\Local\Packages\";
        if (userRelative.StartsWith(packagePrefix, StringComparison.OrdinalIgnoreCase))
        {
            string[] parts = userRelative.Substring(packagePrefix.Length).Split('\\');
            if (parts.Length == 3 && parts[1].Equals("Settings", StringComparison.OrdinalIgnoreCase) &&
                (parts[2].Equals("settings.dat", StringComparison.OrdinalIgnoreCase) || parts[2].Equals("settings.dat.LOG1", StringComparison.OrdinalIgnoreCase) || parts[2].Equals("settings.dat.LOG2", StringComparison.OrdinalIgnoreCase))) return true;
            if (parts.Length == 4 && parts[1].Equals("AppData", StringComparison.OrdinalIgnoreCase) && parts[2].Equals("CacheStorage", StringComparison.OrdinalIgnoreCase) &&
                (parts[3].Equals("CacheStorage.edb", StringComparison.OrdinalIgnoreCase) || parts[3].Equals("CacheStorage.jfm", StringComparison.OrdinalIgnoreCase))) return true;
        }
        const string chromePrefix = @"AppData\Local\Google\Chrome\User Data\";
        if (userRelative.StartsWith(chromePrefix, StringComparison.OrdinalIgnoreCase))
        {
            string[] parts = userRelative.Substring(chromePrefix.Length).Split('\\');
            if (parts.Length == 3 && parts[1].Equals("Network", StringComparison.OrdinalIgnoreCase) &&
                (parts[2].Equals("Cookies", StringComparison.OrdinalIgnoreCase) || parts[2].Equals("Cookies-journal", StringComparison.OrdinalIgnoreCase))) return true;
            if (parts.Length == 3 && (parts[1].Equals("Sessions", StringComparison.OrdinalIgnoreCase) || parts[1].Equals("Sessions_Encrypted", StringComparison.OrdinalIgnoreCase)))
            {
                string leaf = parts[2];
                string number = leaf.StartsWith("Session_", StringComparison.Ordinal) ? leaf.Substring(8) : leaf.StartsWith("Tabs_", StringComparison.Ordinal) ? leaf.Substring(5) : "";
                long sessionId;
                if (number.Length > 0 && long.TryParse(number, out sessionId) && sessionId >= 0) return true;
            }
        }
        foreach (string known in new[] { @"AppData\Local\Microsoft\Windows\Notifications\WPNPRMRY.tmp", @"AppData\Local\Microsoft\Internet Explorer\CacheStorage\edb.log" })
            if (userRelative.Equals(known, StringComparison.OrdinalIgnoreCase)) return true;
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string defender = Path.Combine(programData, @"Microsoft\Windows Defender") + "\\";
        if (normal.StartsWith(defender, StringComparison.OrdinalIgnoreCase))
        {
            string dataPath = normal.Substring(defender.Length);
            if (dataPath.Equals(@"Scans\MpDiag.bin", StringComparison.OrdinalIgnoreCase)) return true;
            Guid identity;
            if (dataPath.StartsWith("IMpService", StringComparison.OrdinalIgnoreCase) && dataPath.EndsWith(".lock", StringComparison.OrdinalIgnoreCase) &&
                Guid.TryParse(dataPath.Substring(10, dataPath.Length - 15), out identity)) return true;
            const string manager = @"Scans\History\CacheManager\";
            if (dataPath.StartsWith(manager, StringComparison.OrdinalIgnoreCase))
            {
                string leaf = dataPath.Substring(manager.Length);
                long sequence;
                if (leaf.Length > 41 && leaf[36] == '-' && leaf.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) &&
                    Guid.TryParse(leaf.Substring(0, 36), out identity) && long.TryParse(leaf.Substring(37, leaf.Length - 41), out sequence) && sequence >= 0) return true;
            }
        }
        if (normal.Equals(Path.Combine(programData, @"BigFixScanner\bf-scanner.lock"), StringComparison.OrdinalIgnoreCase)) return true;
        foreach (string cache in new[] { @"AppData\Local\Microsoft\Windows\WebCacheLock.dat", @"AppData\Local\Microsoft\Windows\WebCache\V01.log", @"AppData\Local\Microsoft\Windows\WebCache\V01tmp.log", @"AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat", @"AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.jfm" })
            if (userRelative.Equals(cache, StringComparison.OrdinalIgnoreCase)) return true;
        if (relative.StartsWith(@"System32\catroot2\", StringComparison.OrdinalIgnoreCase))
        {
            string leaf = Path.GetFileName(relative);
            if (leaf.EndsWith(".log", StringComparison.OrdinalIgnoreCase) || leaf.EndsWith(".jfm", StringComparison.OrdinalIgnoreCase) || leaf.EndsWith(".edb", StringComparison.OrdinalIgnoreCase) || leaf.Equals("catdb", StringComparison.OrdinalIgnoreCase)) return true;
        }
        foreach (string known in new[] {
            @"SystemTemp\Velociraptor_Buffer.bin",
            @"System32\LogFiles\Sum\Current.jfm", @"System32\LogFiles\Sum\Current.mdb", @"System32\LogFiles\Sum\Svc.log", @"System32\LogFiles\Sum\Svctmp.log",
            @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\WebCacheLock.dat",
            @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\WebCache\V01.log",
            @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\WebCache\V01tmp.log",
            @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat",
            @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.jfm",
            @"System32\config\systemprofile\AppData\Local\DataSharing\Storage\DSS.log",
            @"System32\config\systemprofile\AppData\Local\DataSharing\Storage\DSTokenDB2.dat",
            @"System32\config\systemprofile\AppData\Local\DataSharing\Storage\DSTokenDB2.jfm" })
            if (relative.Equals(known, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool ExpectedSystemFile(string path)
    {
        // Only exact OS paging/registry metadata names are intentionally skipped.
        // Generic extensions, access denied and sharing violations are NOT ignored.
        string normal = Normal(path);
        string name = Path.GetFileName(normal);
        string parent = Path.GetDirectoryName(normal).TrimEnd('\\');
        bool volumeRoot = parent.Equals(Path.GetPathRoot(normal).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        if (volumeRoot && (name.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase))) return true;
        string profileRelative = ProfileRelativePath(normal);
        if (profileRelative.Length != 0)
        {
                foreach (string known in new[] { "NTUSER.DAT", "NTUSER.DAT.LOG1", "NTUSER.DAT.LOG2", @"AppData\Local\Microsoft\Windows\UsrClass.dat", @"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1", @"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2" })
                    if (profileRelative.Equals(known, StringComparison.OrdinalIgnoreCase)) return true;
        }
        string config = Path.Combine(WindowsDirectory, @"System32\config");
        if (!parent.Equals(config, StringComparison.OrdinalIgnoreCase) && !parent.Equals(Path.Combine(config, "RegBack"), StringComparison.OrdinalIgnoreCase)) return false;
        foreach (string hive in new[] { "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "BBI" })
            if (name.Equals(hive, StringComparison.OrdinalIgnoreCase) || name.Equals(hive + ".LOG1", StringComparison.OrdinalIgnoreCase) || name.Equals(hive + ".LOG2", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool IsExecutable(byte[] data, int count)
    {
        if (count >= 2 && data[0] == 77 && data[1] == 90) return true;
        if (count < 4) return false;
        uint word = (uint)(data[0] | data[1] << 8 | data[2] << 16 | data[3] << 24);
        return word == 0x464C457F || word == 0xFEEDFACE || word == 0xFEEDFACF ||
               word == 0xCEFAEDFE || word == 0xCFFAEDFE || word == 0xBEBAFECA;
    }

    private static bool Contains(string text, string value)
    {
        return text.IndexOf(value, StringComparison.Ordinal) >= 0;
    }

    private static bool ReadAt(FileStream stream, long offset, byte[] buffer, int count, PhpFilterStats stats)
    {
        if (offset < 0 || count < 0 || count > buffer.Length || offset > stream.Length - count) return false;
        stream.Position = offset;
        int total = 0, read;
        while (total < count && (read = stream.Read(buffer, total, count - total)) > 0) total += read;
        stats.StructuralBytes += total;
        stats.PrefilterBytes += total;
        return total == count;
    }

    // A bounded structural proof, independent of pathname/extension. Unknown,
    // malformed, truncated, mixed/native and executable-section images stay in
    // YARA. Resource/metadata images must declare NO native code or entrypoint.
    private static bool KnownNonRuntime(FileStream stream, byte[] buffer, PhpFilterStats stats)
    {
        if (!ReadAt(stream, 0, buffer, 64, stats)) return false;
        if (buffer[0] == 0x7f && buffer[1] == 69 && buffer[2] == 76 && buffer[3] == 70)
        {
            if ((buffer[4] != 1 && buffer[4] != 2) || (buffer[5] != 1 && buffer[5] != 2) || buffer[6] != 1) return false;
            int type = buffer[5] == 1 ? buffer[16] | buffer[17] << 8 : buffer[16] << 8 | buffer[17];
            int headerOffset = buffer[4] == 1 ? 40 : 52;
            int headerSize = buffer[5] == 1 ? buffer[headerOffset] | buffer[headerOffset + 1] << 8 : buffer[headerOffset] << 8 | buffer[headerOffset + 1];
            return headerSize == (buffer[4] == 1 ? 52 : 64) && (type == 1 || type == 4); // object/core, never ET_EXEC/ET_DYN
        }
        if (buffer[0] != 77 || buffer[1] != 90) return false;
        uint pe = BitConverter.ToUInt32(buffer, 60);
        if (pe < 64 || pe > 1048576 || !ReadAt(stream, pe, buffer, 24, stats)) return false;
        if (BitConverter.ToUInt32(buffer, 0) != 0x00004550) return false;
        int sections = BitConverter.ToUInt16(buffer, 6), optionalSize = BitConverter.ToUInt16(buffer, 20);
        if (sections < 1 || sections > 96 || optionalSize < 96 || optionalSize > 512) return false;
        if (!ReadAt(stream, pe + 24L, buffer, optionalSize + sections * 40, stats)) return false;
        int magic = BitConverter.ToUInt16(buffer, 0);
        int directories = magic == 0x10b ? 96 : magic == 0x20b ? 112 : 0;
        if (directories == 0 || optionalSize < directories) return false;
        if (BitConverter.ToUInt32(buffer, 4) != 0 || BitConverter.ToUInt32(buffer, 16) != 0) return false;
        uint count = BitConverter.ToUInt32(buffer, directories - 4);
        if (count > 16 || optionalSize < directories + count * 8) return false;
        // Native exports/imports/TLS are contradictory evidence: retain the file.
        foreach (int index in new[] { 0, 1, 9 })
            if (count > index && (BitConverter.ToUInt32(buffer, directories + index * 8) != 0 || BitConverter.ToUInt32(buffer, directories + index * 8 + 4) != 0)) return false;
        uint resource = count > 2 ? BitConverter.ToUInt32(buffer, directories + 16) : 0;
        uint resourceSize = count > 2 ? BitConverter.ToUInt32(buffer, directories + 20) : 0;
        uint cli = count > 14 ? BitConverter.ToUInt32(buffer, directories + 112) : 0;
        uint cliSize = count > 14 ? BitConverter.ToUInt32(buffer, directories + 116) : 0;
        long resourceOffset = -1, cliOffset = -1;
        var rvas = new uint[sections]; var sizes = new uint[sections]; var offsets = new uint[sections];
        for (int index = 0; index < sections; index++)
        {
            int row = optionalSize + index * 40;
            uint size = BitConverter.ToUInt32(buffer, row + 16), offset = BitConverter.ToUInt32(buffer, row + 20);
            uint rva = BitConverter.ToUInt32(buffer, row + 12), flags = BitConverter.ToUInt32(buffer, row + 36);
            if ((flags & 0x20000000U) != 0 || (long)offset + size > stream.Length) return false;
            rvas[index] = rva; sizes[index] = size; offsets[index] = offset;
            if (resource != 0 && resourceSize >= 16 && resource >= rva && (long)resource - rva + resourceSize <= size) resourceOffset = offset + (long)resource - rva;
            if (cli != 0 && cliSize >= 72 && cli >= rva && (long)cli - rva + cliSize <= size) cliOffset = offset + (long)cli - rva;
        }
        if (cli != 0)
        {
            if (cliOffset < 0 || !ReadAt(stream, cliOffset, buffer, 72, stats)) return false;
            uint flags = BitConverter.ToUInt32(buffer, 16), metadata = BitConverter.ToUInt32(buffer, 8), metadataSize = BitConverter.ToUInt32(buffer, 12);
            if (BitConverter.ToUInt32(buffer, 0) < 72 || (flags & 1) == 0 || (flags & 0x10) != 0 || BitConverter.ToUInt32(buffer, 20) != 0) return false;
            // Retain managed/native images, fixups and exported native stubs.
            for (int field = 40; field < 72; field += 4) if (BitConverter.ToUInt32(buffer, field) != 0) return false;
            if (metadataSize < 16) return false;
            for (int index = 0; index < sections; index++)
                if (metadata >= rvas[index] && (long)metadata - rvas[index] + metadataSize <= sizes[index])
                    return ReadAt(stream, offsets[index] + (long)metadata - rvas[index], buffer, 4, stats) && BitConverter.ToUInt32(buffer, 0) == 0x424a5342;
            return false;
        }
        return resourceOffset >= 0 && ReadAt(stream, resourceOffset, buffer, 16, stats);
    }

    private static bool CacheDirectory(string normal)
    {
        foreach (string relative in new[] { "Installer", "Logs", "Minidump", "LiveKernelReports", @"System32\LogFiles" })
            if (normal.Equals(Path.Combine(WindowsDirectory, relative), StringComparison.OrdinalIgnoreCase)) return true;
        foreach (string basePath in new[] { ProgramFilesDirectory, ProgramFilesX86Directory })
            foreach (string product in new[] { "BES Server", "BES Relay" })
                if (basePath.Length != 0 && normal.Equals(Path.Combine(basePath, @"BigFix Enterprise\" + product + @"\wwwrootbes\bfmirror\downloads\sha1"), StringComparison.OrdinalIgnoreCase)) return true;
        string relativeProfile = ProfileRelativePath(normal);
        if (relativeProfile.Equals(@"AppData\Local\CrashDumps", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (string browser in new[] { @"AppData\Local\Google\Chrome\User Data\", @"AppData\Local\Microsoft\Edge\User Data\" })
        {
            if (!relativeProfile.StartsWith(browser, StringComparison.OrdinalIgnoreCase)) continue;
            string[] parts = relativeProfile.Substring(browser.Length).Split('\\');
            if (parts.Length == 2 && (parts[1].Equals("Cache", StringComparison.OrdinalIgnoreCase) || parts[1].Equals("Code Cache", StringComparison.OrdinalIgnoreCase) || parts[1].Equals("GPUCache", StringComparison.OrdinalIgnoreCase))) return true;
            if (parts.Length == 2 && parts[0].Equals("Crashpad", StringComparison.OrdinalIgnoreCase) && parts[1].Equals("reports", StringComparison.OrdinalIgnoreCase)) return true;
        }
        const string firefox = @"AppData\Local\Mozilla\Firefox\Profiles\";
        if (relativeProfile.StartsWith(firefox, StringComparison.OrdinalIgnoreCase))
        {
            string[] parts = relativeProfile.Substring(firefox.Length).Split('\\');
            if (parts.Length == 2 && parts[1].Equals("cache2", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool DefaultScopeDirectory(string normal)
    {
        normal = Normal(normal).TrimEnd('\\');
        string volume = Path.GetPathRoot(normal);
        if (DefaultRelativeDirectories.Contains(normal.Substring(volume.Length))) return true;
        if (normal.Equals(WindowsDirectory, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (string basePath in new[] { ProgramFilesDirectory, ProgramFilesX86Directory })
            if (basePath.Length != 0 && normal.Equals(Path.Combine(basePath, "WindowsApps"), StringComparison.OrdinalIgnoreCase)) return true;
        if (CacheDirectory(normal)) return true;
        // Only immediate personal media folders: never all Users, AppData,
        // Documents, Downloads, Scoop apps or Herd's PHP binaries.
        string relativeProfile = ProfileRelativePath(normal);
        string profiles = Path.Combine(volume, "Users") + "\\";
        if (relativeProfile.Length == 0 && normal.StartsWith(profiles, StringComparison.OrdinalIgnoreCase))
        {
            string remainder = normal.Substring(profiles.Length);
            int separator = remainder.IndexOf('\\');
            if (separator >= 0) relativeProfile = remainder.Substring(separator + 1);
        }
        foreach (string media in new[] { "Pictures", "Music", "Videos" })
            if (relativeProfile.Equals(media, StringComparison.OrdinalIgnoreCase)) return true;
        return relativeProfile.Equals(@"scoop\cache", StringComparison.OrdinalIgnoreCase);
    }

    private static bool DefaultScopeFile(string path)
    {
        return DataExtensions.Contains(Path.GetExtension(path));
    }

    private static bool PossiblePhp(FileStream stream, byte[] buffer, PhpFilterStats stats, bool includeBuildText)
    {
        int count = stream.Read(buffer, 0, 4);
        stats.PrefilterBytes += count;
        if (IsExecutable(buffer, count))
        {
            if (KnownNonRuntime(stream, buffer, stats)) { stats.StructuralSkipped++; return false; }
            return true;
        }
        // Runtime-only mode needs just the header; avoid reading/decoding small text files.
        if (!includeBuildText || stream.Length >= 65536) return false;
        int read;
        while (count < 65536 && (read = stream.Read(buffer, count, 65536 - count)) > 0)
        {
            count += read;
            stats.PrefilterBytes += read;
        }
        string text = Encoding.ASCII.GetString(buffer, 0, count);
        return (Contains(text, "version=\"") && Contains(text, "php_cli_binary=") && Contains(text, "--php-binary")) ||
               (Contains(text, "#define PHP_VERSION \"") && Contains(text, "#define PHP_MAJOR_VERSION"));
    }

    public static PhpFilterStats WriteCandidates(string[] roots, string excludedOutput,
        string listPath, long maxFiles, long maxFileBytes, long maxCandidateBytes, int maxSeconds, bool gentleDisk = false,
        bool includeBuildText = false, bool includeBroaderLocations = false, bool includeNonstandardNames = false,
        PhpDirectoryExclusions customExclusions = null)
    {
        var stats = new PhpFilterStats();
        // Current-process background mode lowers CPU, disk-I/O and memory
        // scheduling priorities; it changes no persistent host policy.
        if (!gentleDisk) SetPriorityClass(Process.GetCurrentProcess().Handle, 0x00200000);
        stats.BackgroundMode = gentleDisk && SetPriorityClass(Process.GetCurrentProcess().Handle, 0x00100000);
        var watch = Stopwatch.StartNew();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string privateRoot = Normal(Path.GetFullPath(excludedOutput)).TrimEnd('\\');
        skip.Add(privateRoot);
        if (Path.GetFileName(privateRoot).Equals("YARA_PHP", StringComparison.OrdinalIgnoreCase))
            skip.Add(Path.Combine(Path.GetDirectoryName(privateRoot), "__BESData"));
        // Only the identified client's persistent download cache, not its live action folders.
        if (!includeBroaderLocations && Path.GetFileName(privateRoot).Equals("PHP-YARA-Discovery", StringComparison.OrdinalIgnoreCase) &&
            Path.GetFileName(Path.GetDirectoryName(privateRoot)).Equals("__Global", StringComparison.OrdinalIgnoreCase))
            skip.Add(Path.Combine(Path.GetDirectoryName(privateRoot), @"__Cache\Downloads"));
        var buffer = new byte[65536];
        var encoding = new UTF8Encoding(false, true);
        using (var writer = new StreamWriter(listPath, false, encoding))
        {
            Action<FileInfo> consider = file =>
            {
                if (stats.BudgetReason.Length != 0) return;
                if (watch.Elapsed.TotalSeconds >= maxSeconds || stats.Files >= maxFiles)
                {
                    stats.BudgetReason = "enumeration_budget";
                    return;
                }
                stats.Files++;
                try
                {
                    bool buildName = file.Name.Equals("php-config", StringComparison.OrdinalIgnoreCase) || file.Name.Equals("php_version.h", StringComparison.OrdinalIgnoreCase);
                    if (!includeNonstandardNames && !StandardRuntimeName(file.Name) && !(includeBuildText && buildName)) { stats.NameSkipped++; return; }
                    if (!includeBuildText && buildName) { stats.NameSkipped++; return; }
                    int attributes = (int)file.Attributes;
                    if ((attributes & CloudMask) != 0) { stats.CloudSkipped++; return; }
                    // File symlinks can target remote paths. Treat all file reparse
                    // points as outside scope, including deduplicated-file tags.
                    if ((attributes & (int)FileAttributes.ReparsePoint) != 0) { stats.LinksSkipped++; return; }
                    if (!includeBroaderLocations && DefaultScopeFile(file.FullName)) { stats.DataFilesSkipped++; return; }
                    if (file.Length >= maxFileBytes) { stats.SizeSkipped++; return; }
                    if (ExpectedSystemFile(file.FullName)) { stats.ExpectedSkipped++; return; }
                    using (var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.None))
                    {
                        if (stream.Length >= maxFileBytes) { stats.SizeSkipped++; return; }
                        if (!PossiblePhp(stream, buffer, stats, includeBuildText)) { stats.HeaderFiltered++; return; }
                        if (stats.CandidateBytes + stream.Length > maxCandidateBytes)
                        {
                            stats.BudgetReason = "candidate_byte_budget";
                            return;
                        }
                        if (file.FullName.IndexOfAny(new[] {'\r', '\n'}) >= 0) { RecordError(stats, "path", file.FullName, new ArgumentException()); return; }
                        // Test strict UTF-8 encoding before publishing a scan-list row.
                        encoding.GetByteCount(file.FullName);
                        writer.WriteLine(file.FullName);
                        stats.Candidates++;
                        stats.CandidateBytes += stream.Length;
                    }
                }
                catch (IOException error) { RecordError(stats, "read", file.FullName, error); }
                catch (UnauthorizedAccessException error) { RecordError(stats, "read", file.FullName, error); }
                catch (System.Security.SecurityException error) { RecordError(stats, "read", file.FullName, error); }
                catch (EncoderFallbackException error) { RecordError(stats, "encode_path", file.FullName, error); }
            };

            // Cover likely app/bundle locations across EVERY fixed drive before
            // a large OS tree can consume the shared search budget. The global
            // seen-directory set prevents a second pass through these locations.
            var orderedRoots = new List<string>();
            var volumeRoots = new List<string>();
            var explicitRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string suppliedRoot in roots)
            {
                string full = Normal(Extended(suppliedRoot)).TrimEnd('\\');
                string volumeRoot = Path.GetPathRoot(full).TrimEnd('\\');
                if (!full.Equals(volumeRoot, StringComparison.OrdinalIgnoreCase)) { explicitRoots.Add(full); continue; }
                volumeRoots.Add(full + "\\");
            }
            foreach (string likely in new[] { "PHP", "xampp", "wamp64", "wamp", "inetpub", "www", "web", "websites", "Apache24", "Apps", "Applications", @"ProgramData\chocolatey", "Program Files", "Program Files (x86)", "Users", "Tools", "Portable", "Code", "Dev", "ProgramData" })
            {
                foreach (string volume in volumeRoots)
                {
                    string candidate = Path.Combine(volume, likely);
                    if (Directory.Exists(candidate)) orderedRoots.Add(candidate);
                }
            }
            orderedRoots.AddRange(roots);
            var deferred = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string volume in volumeRoots)
                foreach (string relative in new[] { @"Program Files\WindowsApps", @"Program Files (x86)\WindowsApps", "Windows" })
                {
                    string path = Path.Combine(volume, relative).TrimEnd('\\');
                    if (Directory.Exists(path) && deferred.Add(path)) orderedRoots.Add(path);
                }
            foreach (string suppliedRoot in orderedRoots)
            {
                if (stats.BudgetReason.Length != 0) break;
                string root = Extended(suppliedRoot);
                string volume = Path.GetPathRoot(Normal(root));
                if (File.Exists(root))
                {
                    int rootMode = customExclusions == null ? 0 : customExclusions.Mode(Path.GetDirectoryName(root));
                    if (rootMode == 0) consider(new FileInfo(root)); else stats.CustomExcludedFiles++;
                    continue;
                }
                if (!Directory.Exists(root)) { RecordError(stats, "root", root, new DirectoryNotFoundException()); continue; }
                var stack = new Stack<string>();
                stack.Push(root);
                while (stack.Count > 0 && stats.BudgetReason.Length == 0)
                {
                    if (watch.Elapsed.TotalSeconds >= maxSeconds) { stats.BudgetReason = "enumeration_budget"; break; }
                    string directory = stack.Pop();
                    string normalized = Normal(directory).TrimEnd('\\');
                    if (deferred.Contains(normalized) && !normalized.Equals(Normal(root).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) continue;
                    if (!seen.Add(normalized)) continue;
                    int customMode = customExclusions == null ? 0 : customExclusions.Mode(normalized);
                    if (customMode == 2) { stats.CustomExcludedTrees++; continue; }
                    if (customMode == 1) stats.CustomDirectDirectories++;
                    // Explicit non-volume roots can intentionally point inside a
                    // default exclusion. Fixed-drive discovery still prunes it.
                    bool explicitRoot = explicitRoots.Contains(normalized);
                    if (skip.Contains(normalized) || (!includeBroaderLocations && !explicitRoot && DefaultScopeDirectory(normalized)))
                    { stats.ExcludedDirectories++; continue; }
                    stats.Directories++;
                    if (stats.Directories > maxFiles) { stats.BudgetReason = "directory_budget"; break; }
                    try
                    {
                        var current = new DirectoryInfo(directory);
                        if (((int)current.Attributes & CloudMask) != 0) { stats.CloudSkipped++; continue; }
                        if ((current.Attributes & FileAttributes.ReparsePoint) != 0) { stats.LinksSkipped++; continue; }
                        foreach (FileSystemInfo entry in current.EnumerateFileSystemInfos())
                        {
                            if (stats.BudgetReason.Length != 0) break;
                            if (watch.Elapsed.TotalSeconds >= maxSeconds) { stats.BudgetReason = "enumeration_budget"; break; }
                            if ((entry.Attributes & FileAttributes.Directory) != 0)
                            {
                                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) stats.LinksSkipped++;
                                else if (((int)entry.Attributes & CloudMask) != 0) stats.CloudSkipped++;
                                else if (stack.Count >= maxFiles) { stats.BudgetReason = "directory_budget"; break; }
                                else stack.Push(entry.FullName);
                            }
                            else if (customMode == 1) stats.CustomExcludedFiles++;
                            else consider((FileInfo)entry);
                        }
                    }
                    catch (IOException error) { RecordError(stats, "list", directory, error); }
                    catch (UnauthorizedAccessException error) { RecordError(stats, "list", directory, error); }
                    catch (System.Security.SecurityException error) { RecordError(stats, "list", directory, error); }
                }
            }
        }
        stats.Seconds = watch.Elapsed.TotalSeconds;
        return stats;
    }
}
