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
        internal delegate bool FileExists(string filepath);
        internal delegate nint LoadDDS(string a1);

        internal LoadDDS loadDDS { get; set; }
        internal FileExists fileExists { get; set; }

        internal IReloadedHooks _hooks;
        internal IStartupScanner IScanner { get; set; }
        internal ILogger iLogger;
        internal Config iConfig;
        internal long baseAddress { get; set; }

        internal static readonly string PushCallerRegisters = "push rcx\npush rdx\npush r8\npush r9";
        internal static readonly string PopCallerRegisters = "pop r9\npop r8\npop rdx\npop rcx";

        internal Utils(IReloadedHooks hooks, ILogger logger, IModLoader modLoader, Config modConfig)
        {
            iConfig = modConfig;
            iLogger = logger;
            _hooks = hooks;

            modLoader.GetController<IStartupScanner>().TryGetTarget(out var startupScanner);
            IScanner = startupScanner;

            using var thisProcess = Process.GetCurrentProcess();
            baseAddress = thisProcess.MainModule.BaseAddress.ToInt64();

            SigScan("48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 60 48 89 CD 89 D6", "LoadDDS", (loadDDSAdr) =>
                loadDDS = hooks.CreateWrapper<LoadDDS>(loadDDSAdr, out _));

            SigScan("48 89 5C 24 ?? 57 48 81 EC 20 02 00 00 33 FF", "FileExists", (optionalOpenFileAdr) =>
                fileExists = hooks.CreateWrapper<FileExists>(optionalOpenFileAdr, out _));
        }

        internal void SigScan(string pattern, Action<nint> action) => SigScan(pattern, pattern, action);

        internal void SigScan(string pattern, string name, Action<nint> action)
        {
            IScanner.AddMainModuleScan(pattern, (result) =>
            {
                if (!result.Found)
                    throw new Exception($"Could not find address for {name}");

                DebugLog($"Found {name} at 0x{baseAddress + result.Offset:X}");
                action.Invoke((nint)(baseAddress + result.Offset));
            });
        }

        internal void Log(object logString)
        {
            iLogger.WriteLineAsync($"[Unhardcoded P5R] {logString}", Color.DimGray);
        }

        internal void Log(object logString, Color color)
        {
            iLogger.WriteLineAsync($"[Unhardcoded P5R] {logString}", color);
        }

        internal void DebugLog(object logString)
        {
            if (iConfig.DebugBool)
                iLogger.WriteLine($"[Unhardcoded P5R DEBUG] {logString}", Color.DimGray);
        }

        internal void DebugLog(object logString, Color color)
        {
            if (iConfig.DebugBool)
                iLogger.WriteLine($"[Unhardcoded P5R DEBUG] {logString}", color);
        }

        internal nint GetAddressFromGlobalRef(nint instructionAdr, byte length, string name = "")
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
        internal unsafe struct fileHandleStruct
        {
            [FieldOffset(0)] public ulong fileStatus;
            [FieldOffset(8)] public fixed byte filename[128];
            [FieldOffset(136)] public uint bufferSize;
            [FieldOffset(152)] public nint pointerToFile;
        };

        internal unsafe struct PtrToFileHandle
        {
            public fileHandleStruct* ptrtoStruct;
        };

        internal struct AsmHookWrapper
        {
            public IAsmHook asmHook;
            public IReverseWrapper reverseWrapper;
        }
    }
}
