using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sigscan.Definitions;
using Reloaded.Memory.Sigscan.Definitions.Structs;
using Reloaded.Memory.SigScan.ReloadedII.Interfaces;
using Reloaded.Memory.Sources;
using Reloaded.Mod.Interfaces;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Encodings;
using Unhardcoded_P5R.Configuration;

namespace Unhardcoded_P5R
{
    public unsafe class Utils
    {
        public delegate PtrToFileHandle* Open_File(string a1);
        public delegate int FsSync(long a1);
        public delegate long LoadDDS(string a1);
        public delegate long FlowscriptGetIntArg(int a1);

        public Open_File openFile;
        public FsSync fsSync;
        public LoadDDS loadDDS { get; set; }
        public FlowscriptGetIntArg flowscriptGetIntArg { get; set; }

        public IStartupScanner IScanner { get; set; }
        public ILogger iLogger;
        public Config iConfig;
        public long baseAddress { get; set; }
        public Utils(IReloadedHooks hooks, ILogger logger, IModLoader modLoader, Config modConfig)
        {
            iConfig = modConfig;
            iLogger = logger;
            long open_file_adr = 0;
            long fsSync_adr = 0;
            long loadDDSAdr = 0;
            long flowscriptGetIntArgAdr = 0;

            modLoader.GetController<IStartupScanner>().TryGetTarget(out var startupScanner);
            IScanner = startupScanner;

            using var thisProcess = Process.GetCurrentProcess();
            baseAddress = thisProcess.MainModule.BaseAddress.ToInt64();

            IScanner.AddMainModuleScan("48 89 5C 24 ?? 57 48 83 EC 30 BA 10 00 00 00 48 8B F9 8D 4A ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0", (result) =>
            {
                if (!result.Found)
                {
                    throw new Exception("Could not find Util \"Open_File\"");
                }

                open_file_adr = result.Offset + baseAddress;
                DebugLog($"Found Open_File at 0x{open_file_adr:X}");

                openFile = hooks.CreateWrapper<Open_File>(open_file_adr, out IntPtr _openFileWrapper);
            });

            IScanner.AddMainModuleScan("83 79 ?? 0C 75 ?? 80 B9 ?? ?? ?? ?? 00", (result) =>
            {
                if (!result.Found)
                {
                    throw new Exception("Could not find Util \"FsSync\"");
                }

                fsSync_adr = result.Offset + baseAddress;
                DebugLog($"Found FsSync at 0x{fsSync_adr:X}");

                fsSync = hooks.CreateWrapper<FsSync>(fsSync_adr, out IntPtr _fsSyncWrapper);
            });

            IScanner.AddMainModuleScan("48 89 5C 24 ?? 57 48 83 EC 60 48 89 CB 45 31 C0", (result) =>
            {
                if (!result.Found)
                {
                    throw new Exception("Could not find Util \"LoadDDS\"");
                }

                loadDDSAdr = baseAddress + result.Offset;
                DebugLog($"Found LoadDDS at 0x{loadDDSAdr:X}");

                loadDDS = hooks.CreateWrapper<LoadDDS>(loadDDSAdr, out IntPtr wrapperAdress);
            });

            IScanner.AddMainModuleScan("4C 8B 05 ?? ?? ?? ?? 41 8B 50 ?? 29 CA", (result) =>
            {
                if (!result.Found)
                {
                    throw new Exception("Could not find Util \"FlowscriptGetIntArg\"");
                }

                flowscriptGetIntArgAdr = baseAddress + result.Offset;
                DebugLog($"Found FlowscriptGetIntArg at 0x{flowscriptGetIntArgAdr:X}");

                flowscriptGetIntArg = hooks.CreateWrapper<FlowscriptGetIntArg>(flowscriptGetIntArgAdr, out IntPtr wrapperAdress);
            });
        }
        public byte* Sprintf(string input)
        {
            byte[] stringByteArray = Encoding.ASCII.GetBytes(input);

            fixed (byte* stringPtr = stringByteArray)
            {
                return stringPtr;
            }
        }

        public fileHandleStruct * OpenFile(string fileName, int openMode)
        {
            var newFile = openFile(fileName)->ptrtoStruct;

            var status = fsSync((long)newFile);

            while (status != 1)
            {
                status = fsSync((long)newFile);
            }

            DebugLog($"Loaded {Encoding.ASCII.GetString(newFile->filename, 128).TrimEnd('\0')} To 0x{newFile->pointerToFile:X8}", Color.LightSkyBlue);

            return newFile;
        }
        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct fileHandleStruct
        {
            [FieldOffset(0)]public ulong fileStatus;
            [FieldOffset(8)] public fixed byte filename[128];
            [FieldOffset(136)] public uint bufferSize;
            [FieldOffset(152)] public long pointerToFile;
        }
        public unsafe struct PtrToFileHandle
        {
            public fileHandleStruct* ptrtoStruct;
        };

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

        public long GetAddressFromGlobalRef(long instructionAdr, byte length)
        {
            int opd = *(int*)(instructionAdr + length - 4);
            return instructionAdr + opd + length;
        }
    }
}
