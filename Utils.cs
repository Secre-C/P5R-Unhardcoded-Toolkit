using Reloaded.Hooks.Definitions;
using Reloaded.Memory.SigScan.ReloadedII.Interfaces;
using Reloaded.Mod.Interfaces;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using Unhardcoded_P5R.Configuration;

namespace Unhardcoded_P5R
{
    public unsafe class Utils
    {
        public delegate bool FileExists(string filepath);
        public delegate PtrToFileHandle* d_OpenFile(string a1);
        public delegate int FsSync(fileHandleStruct* a1);
        public delegate long LoadDDS(string a1);
        public delegate long FlowscriptGetIntArg(int a1);

        public d_OpenFile openFile;
        public FsSync fsSync;
        public LoadDDS loadDDS { get; set; }
        public FlowscriptGetIntArg flowscriptGetIntArg { get; set; }
        internal FileExists fileExists { get; set; }

        public IStartupScanner IScanner { get; set; }
        public ILogger iLogger;
        public Config iConfig;
        public long baseAddress { get; set; }

        public static readonly string PushCallerRegisters = "push rcx\npush rdx\npush r8\npush r9";
        public static readonly string PopCallerRegisters = "pop r9\npop r8\npop rdx\npop rcx";

        public Utils(IReloadedHooks hooks, ILogger logger, IModLoader modLoader, Config modConfig)
        {
            iConfig = modConfig;
            iLogger = logger;

            modLoader.GetController<IStartupScanner>().TryGetTarget(out var startupScanner);
            IScanner = startupScanner;

            using var thisProcess = Process.GetCurrentProcess();
            baseAddress = thisProcess.MainModule.BaseAddress.ToInt64();

            SigScan("48 89 5C 24 ?? 57 48 83 EC 30 BA 10 00 00 00 48 8B F9 8D 4A ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0", "Open_File", (openFileAdr) =>
                openFile = hooks.CreateWrapper<d_OpenFile>(openFileAdr, out _));

            SigScan("83 79 ?? 0C 75 ?? 80 B9 ?? ?? ?? ?? 00", "FsSync", (fsSyncAdr) =>
                fsSync = hooks.CreateWrapper<FsSync>(fsSyncAdr, out _));

            SigScan("48 89 5C 24 ?? 57 48 83 EC 60 48 89 CB 45 31 C0", "LoadDDS", (loadDDSAdr) =>
                loadDDS = hooks.CreateWrapper<LoadDDS>(loadDDSAdr, out _));

            SigScan("4C 8B 05 ?? ?? ?? ?? 41 8B 50 ?? 29 CA", "FlowscriptGetIntArg", (flowscriptGetIntArgAdr) =>
                flowscriptGetIntArg = hooks.CreateWrapper<FlowscriptGetIntArg>(flowscriptGetIntArgAdr, out _));

            SigScan("48 89 5C 24 ?? 57 48 81 EC 20 02 00 00 33 FF", "FileExists", (optionalOpenFileAdr) =>
                fileExists = hooks.CreateWrapper<FileExists>(optionalOpenFileAdr, out _));
        }

        public void SigScan(string pattern, Action<nint> action) => SigScan(pattern, string.Empty, action);

        public void SigScan(string pattern, string name, Action<nint> action)
        {
            IScanner.AddMainModuleScan(pattern, (result) =>
            {
                if (!result.Found)
                {
                    if (name == string.Empty)
                        name = pattern;

                    throw new Exception($"Could not find address for {name}");
                }

                DebugLog($"Found {name} at 0x{baseAddress + result.Offset:X}");
                action.Invoke((nint)(baseAddress + result.Offset));
            });
        }

        public fileHandleStruct* OpenFile(string fileName, int openMode)
        {
            var newFile = openFile(fileName)->ptrtoStruct;
            var status = fsSync(newFile);

            while (status != 1)
            {
                status = fsSync(newFile);
            }

            DebugLog($"Loaded {Encoding.ASCII.GetString(newFile->filename, 128).TrimEnd('\0')} To 0x{newFile->pointerToFile:X8}", Color.LightSkyBlue);
            return newFile;
        }

        public void Log(object logString)
        {
            iLogger.WriteLineAsync($"[Unhardcoded P5R] {logString}", Color.DimGray);
        }

        public void Log(object logString, Color color)
        {
            iLogger.WriteLineAsync($"[Unhardcoded P5R] {logString}", color);
        }

        public void DebugLog(object logString)
        {
            if (iConfig.DebugBool)
                iLogger.WriteLine($"[Unhardcoded P5R DEBUG] {logString}", Color.DimGray);
        }

        public void DebugLog(object logString, Color color)
        {
            if (iConfig.DebugBool)
                iLogger.WriteLine($"[Unhardcoded P5R DEBUG] {logString}", color);
        }

        public nint GetAddressFromGlobalRef(nint instructionAdr, byte length, string name = "")
        {
            int opd = *(int*)(instructionAdr + length - 4);
            nint result = instructionAdr + opd + length;

            if (name == string.Empty)
                DebugLog($"Found Global ref at 0x{result:X} from 0x{instructionAdr:X}");
            else
                DebugLog($"Found Global ref {name} at 0x{result:X} from 0x{instructionAdr:X}");

            return result;
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct fileHandleStruct
        {
            [FieldOffset(0)] public ulong fileStatus;
            [FieldOffset(8)] public fixed byte filename[128];
            [FieldOffset(136)] public uint bufferSize;
            [FieldOffset(152)] public nint pointerToFile;
        };

        public unsafe struct PtrToFileHandle
        {
            public fileHandleStruct* ptrtoStruct;
        };

        public struct AsmHookWrapper
        {
            public IAsmHook asmHook;
            public IReverseWrapper reverseWrapper;
        }
    }
}
