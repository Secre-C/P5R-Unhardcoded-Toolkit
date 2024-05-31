using Reloaded.Hooks.Definitions;
using Reloaded.Memory.Sources;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;

namespace Unhardcoded_P5R
{
    internal unsafe class LmapHooks
    {
        private delegate void LoadLmapImage(long a1, int a2);
        private delegate ulong LoadLmapFtds(long a1);
        private delegate char FUN_1412f1d70(long a1, int a2);
        private delegate void FUN_1401f9f10(long a1, long a2);

        private delegate long LmapIdtoFieldListPointerIndex(int a1);

        private delegate int GetMapImage(ulong a1);
        private delegate int* FUN_14eec6d60();
        private IHook<GetMapImage> _getMapImage;

        private IHook<LoadLmapImage> _loadLmapImage;
        private IHook<LoadLmapFtds> _loadLmapFtds;
        private IHook<LmapIdtoFieldListPointerIndex> _lmapIdtoFieldListPointerIndex;

        private IAsmHook _cmmLmapTablePtr;
        private IAsmHook _cmmLmapFieldPtr;
        private IAsmHook _cmmLmapFieldEnd;
        private IAsmHook _cmmLmapTableEnd;
        private IAsmHook _mapImageStringPtr;

        internal LmapHooks(IReloadedHooks hooks, Utils utils)
        {
            utils.DebugLog("Loading Lmap Module", Color.PaleGreen);

            nint lmapImageLoadAdr = 0;
            nint loadLmapFtdsAdr = 0;

            nint FUN_1412f1d70adr = 0;
            nint FUN_1401f9f10adr = 0;
            nint getMapImageAdr = 0;
            nint FUN_14eec6d60adr = 0;

            nint lmapParamTable = 0;
            nint lmapImagePtr = 0;
            nint lmapImageGrayPtr = 0;

            nint mapImagePtr = 0;

            nint DAT_142a0b858 = 0;

            List<nint> lmapCmmIdPtrInstructions = new();

            string[] lmapCmmIdPtrPatterns = {
                "4C 8D 15 ?? ?? ?? ?? 48 69 D1 90 02 00 00",
                "4C 8D 25 ?? ?? ?? ?? 41 8B 4C ?? ??",
                "48 8D 3D ?? ?? ?? ?? 48 8D 1C C5 00 00 00 00",
                "48 8D 1D ?? ?? ?? ?? 33 FF 48 8D 2D ?? ?? ?? ??"
            };

            List<nint> lmapCmmLimitInstructions = new();

            string[] lmapCmmLimitPatterns = {
                "41 83 FB 19 73 ?? 45 8B 4A ??",
                "83 FE 19 73 ??",
                "83 F9 19 73 ?? 48 63 C1",
                "83 FF 19 73 ?? 8B 4B ??"
            };

            List<nint> lmapCmmListEndPtrInstructions = new();

            string[] lmapCmmListEndPtrPatterns = {
                "48 8D 05 ?? ?? ?? ?? 49 83 C2 08",
                "48 8D 2D ?? ?? ?? ?? 85 FF",
            };

            List<nint> lmapFieldPtrInstructions = new();

            string[] lmapFieldPtrPatterns = {
                "4C 8D 0D ?? ?? ?? ?? 44 8B 44 24 ?? 44 8B D6",
                "4C 8D 0D ?? ?? ?? ?? 44 8B 44 24 ?? 44 8B D7",
                "4C 8D 2D ?? ?? ?? ?? 33 DB 4C 8D 25 ?? ?? ?? ?? 41 8B F1",
                "4C 8D 2D ?? ?? ?? ?? 4C 8D 25 ?? ?? ?? ?? 0F 1F 40 00 0F 1F 84 ?? 00 00 00 00 48 8D 44 24 ??",
                "4C 8D 25 ?? ?? ?? ?? 41 8B F0",
                "4C 8D 25 ?? ?? ?? ?? 4C 8D 3D ?? ?? ?? ?? 0F 1F 40 00 66 66 66 0F 1F 84 ?? 00 00 00 00",
            };

            List<nint> lmapFieldPtrEndInstructions = new();

            string[] lmapFieldPtrEndPatterns = {
                "48 8D 05 ?? ?? ?? ?? 49 83 C1 08 4C 3B C8 7C ?? 44 8B D7",
                "48 8D 05 ?? ?? ?? ?? 49 83 C1 08 4C 3B C8 7C ?? 44 8B D6",
                "4C 8D 3D ?? ?? ?? ?? 0F 1F 40 00 66 66 66 0F 1F 84 ?? 00 00 00 00 48 8D 44 24 ??",
                "4C 8D 3D ?? ?? ?? ?? 8B EA 44 8B F1",
                "4C 8D 25 ?? ?? ?? ?? 0F 1F 40 00 0F 1F 84 ?? 00 00 00 00 48 8D 44 24 ??",
                "4C 8D 25 ?? ?? ?? ?? 41 8B F1 41 8B E8",
            };

            utils.SigScan("00 00 c0 c1 00 80 14 43 00 00 76 c2 00 00 01 c3 00 00 58 42 00 80 11 43 00 00 d8 41 22 00 09 03", "lmapParamTable", (result) => //Lmap SPD Parameters (data scan)
            {
                lmapParamTable = result;
            });

            utils.SigScan("4A 8B 8C ?? ?? ?? ?? ?? A8 01", "lmapImagePtr", (result) => //Lmap Image String Pointer
            {
                lmapImagePtr = result;
            });

            utils.SigScan("4A 8B 8C ?? ?? ?? ?? ?? 83 A3 ?? ?? ?? ?? FC", "lmapImageGrayPtr", (result) => //Lmap Gray Image String Pointer
            {
                lmapImageGrayPtr = result;
            });

            utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 48 8B D9 48 63 FA B9 F0 03 00 00", "FUN_1412f1d70adr", (result) =>
            {
                FUN_1412f1d70adr = result;
            });

            utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 48 8B D9 8B FA 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? B8 FF FF FF FF F0 0F C1 43 ?? 83 F8 01 75 ?? F7 03 80 00 00 80", "FUN_1401f9f10adr", (result) =>
            {
                FUN_1401f9f10adr = result;
            });

            for (int i = 0; i < lmapCmmIdPtrPatterns.Length; i++)
            {
                utils.SigScan(lmapCmmIdPtrPatterns[i], $"FUN_1401f9f10adr[{i}]", (result) =>
                {
                    lmapCmmIdPtrInstructions.Add(result);
                });
            }

            for (int i = 0; i < lmapCmmLimitPatterns.Length; i++)
            {
                utils.SigScan(lmapCmmLimitPatterns[i], $"lmapCmmLimitInstructions[{i}]", (result) =>
                {
                    lmapCmmLimitInstructions.Add(result);
                });
            }

            for (int i = 0; i < lmapCmmListEndPtrPatterns.Length; i++)
            {
                utils.SigScan(lmapCmmListEndPtrPatterns[i], $"lmapCmmListEndPtrInstructions[{i}]", (result) =>
                {
                    lmapCmmListEndPtrInstructions.Add(result);
                });
            }


            for (int i = 0; i < lmapFieldPtrPatterns.Length; i++)
            {
                utils.SigScan(lmapFieldPtrPatterns[i], $"lmapFieldPtrInstructions[{i}]", (result) =>
                {
                    lmapFieldPtrInstructions.Add(result);
                });
            }

            for (int i = 0; i < lmapFieldPtrEndPatterns.Length; i++)
            {
                utils.SigScan(lmapFieldPtrEndPatterns[i], $"lmapFieldPtrEndInstructions[{i}]", (result) =>
                {
                    lmapFieldPtrEndInstructions.Add(result);
                });
            }

            utils.SigScan("FF C9 BA FF FF FF FF 83 F9 0D", "lmapIdtoPointerIndexAdr", (lmapIdtoPointerIndexAdr) =>
            {
                _lmapIdtoFieldListPointerIndex = hooks.CreateHook<LmapIdtoFieldListPointerIndex>((a1) =>
                {
                    //utils.DebugLog($"Called Function: LmapIdtoFieldListPointerIndex at {lmapIdtoPointerIndexAdr:X8}", Color.LightSlateGray);
                    return a1;
                }, lmapIdtoPointerIndexAdr).Activate();
            });

            utils.SigScan("48 8B 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 83 ?? ?? ?? ??", "mapImagePtr", (result) =>
            {
                mapImagePtr = result;
            });

            utils.SigScan("48 83 EC 28 4C 8B 05 ?? ?? ?? ?? 4D 85 C0 0F 84 ?? ?? ?? ??", "FUN_14eec6d60adr", (result) =>
            {
                FUN_14eec6d60adr = result;
            });

            utils.SigScan("40 53 55 56 57 41 54 41 55 41 56 48 83 EC 30", "loadLmapFtdsAdr", (result) => //Hooks Lmap ftd load function to load new files
            {
                loadLmapFtdsAdr = result;

                bool hooksDone = false;

                _loadLmapFtds = hooks.CreateHook<LoadLmapFtds>((a1) =>
                {
                    utils.DebugLog($"Called Function: LoadLmapFtds at {loadLmapFtdsAdr:X8}", Color.LightSlateGray);
                    if (!hooksDone)
                    {
                        LmapParamHooks(hooks, utils, lmapParamTable);
                        LmapCmmHooks(hooks, utils, lmapCmmIdPtrInstructions, lmapCmmLimitInstructions, lmapCmmListEndPtrInstructions);
                        LmapCmmFieldHooks(hooks, utils, lmapFieldPtrInstructions, lmapFieldPtrEndInstructions);
                    }
                    hooksDone = true;
                    return _loadLmapFtds.OriginalFunction(a1);
                }, loadLmapFtdsAdr).Activate();
            });

            utils.SigScan("48 83 EC 28 8B 81 ?? ?? ?? ?? 41 BB FF FF FF FF", "getMapImageAdr", (result) =>
            {
                long[] mapImageNameStringPtrArray = Array.Empty<long>();
                getMapImageAdr = result;
                utils.DebugLog($"Found getMapImageAdr -> {getMapImageAdr:X8}");

                var _FUN_14eec6d60 = hooks.CreateWrapper<FUN_14eec6d60>(FUN_14eec6d60adr, out IntPtr wrapperAddress);

                _getMapImage = hooks.CreateHook<GetMapImage>((a1) =>
                {
                    utils.DebugLog($"Called Function: GetMapImage at {FUN_14eec6d60adr:X8}", Color.LightSlateGray);

                    int iVar1;
                    long lVar2;
                    uint CurrentFieldMinor;
                    uint CurrentFieldMajor;

                    iVar1 = *(int*)(a1 + 0x16c);
                    CurrentFieldMajor = 0xffffffff;
                    CurrentFieldMinor = 0xffffffff;

                    if (iVar1 >= 1)
                    {
                        return iVar1;
                    }

                    lVar2 = (long)_FUN_14eec6d60();

                    if (lVar2 == 0)
                    {
                        return -1;
                    }

                    lVar2 = (long)_FUN_14eec6d60();
                    CurrentFieldMajor = *(ushort*)(*(long*)(lVar2 + 0x48) + 0x1f0);
                    CurrentFieldMinor = *(ushort*)(*(long*)(lVar2 + 0x48) + 0x1f2);

                    var newFile = utils.OpenFile("field/panel/lmap/map_l_table.dat", 0);

                    long fileAddress = newFile->pointerToFile;
                    long* mapImageNameStringPtrArrayAdr;

                    int CurrentImageId = 0;

                    ushort FieldMajor = 0;
                    ushort FieldMinor = 0;

                    for (int i = 0; i < newFile->bufferSize / 4; i++)
                    {
                        FieldMajor = *(ushort*)(fileAddress + (i * 4));
                        FieldMinor = *(ushort*)(fileAddress + (i * 4) + 2);

                        if (FieldMajor == CurrentFieldMajor || FieldMajor == 0xffff)
                        {
                            if (FieldMinor == CurrentFieldMinor || FieldMinor == 0xffff)
                            {
                                if (FieldMajor != 0xffff || FieldMinor != 0xffff)
                                {
                                    if (mapImageNameStringPtrArray.Length == 0)
                                    {
                                        var mapImageNameFile = utils.OpenFile(@"field/panel/lmap/map_l_names.dat", 0);

                                        mapImageNameStringPtrArray = new long[mapImageNameFile->bufferSize / 0x20];

                                        for (i = 0; i < mapImageNameFile->bufferSize / 0x20; i++)
                                        {
                                            byte* mapImageName = (byte*)(mapImageNameFile->pointerToFile + (i * 0x20));

                                            Memory.Instance.SafeRead((nuint)(long)mapImageName, out byte[] mapImageNameBytes, 0x20, false);

                                            string mapImageNameString = Encoding.ASCII.GetString(mapImageNameBytes).TrimEnd('\0');

                                            mapImageNameStringPtrArray[i] = Marshal.StringToHGlobalAnsi($"field/panel/lmap/map_l_{mapImageNameString}.dds");
                                        }

                                        fixed (long* fixedMapImageNameStringPtrArrayAdr = mapImageNameStringPtrArray)
                                        {
                                            utils.DebugLog($"fixedMapImageNameStringPtrArrayAdr: {(long)fixedMapImageNameStringPtrArrayAdr:X8}", Color.PaleGreen);
                                            mapImageNameStringPtrArrayAdr = fixedMapImageNameStringPtrArrayAdr;

                                            string[] mapImageStringPtrAsm = { $"use64", $"mov RCX, [RDI + RCX*0x8 + 0x{(long)mapImageNameStringPtrArrayAdr - utils.baseAddress:X}]" };

                                            _mapImageStringPtr = hooks.CreateAsmHook(mapImageStringPtrAsm, mapImagePtr, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
                                        }

                                    }

                                    return CurrentImageId;
                                }

                                CurrentImageId++;
                            }
                        }
                    }

                    return -1;
                }, getMapImageAdr).Activate();
            });

            utils.SigScan("8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 B3 ?? ?? ?? ?? 8B D7", "ref_DAT_142a0b858", (result) =>
            {
                DAT_142a0b858 = utils.GetAddressFromGlobalRef(result, 6, "DAT_142a0b858");
            });

            utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 48 63 FA 48 8B D9 39 B9 ?? ?? ?? ??", "lmapImageLoadAdr", (result) => //Lmap Image Function
            {
                lmapImageLoadAdr = result;

                var _FUN_1412f1d70 = hooks.CreateWrapper<FUN_1412f1d70>(FUN_1412f1d70adr, out IntPtr wrapperAddress);
                var _FUN_1401f9f10 = hooks.CreateWrapper<FUN_1401f9f10>(FUN_1401f9f10adr, out wrapperAddress);

                _loadLmapImage = hooks.CreateHook<LoadLmapImage>((a1, a2) =>
                {
                    utils.DebugLog($"Called Function: LoadLmapImage at {lmapImageLoadAdr:X8}", Color.LightSlateGray);

                    bool bVar1;
                    bool bVar2;
                    char cVar3;
                    ulong uVar4;
                    ushort* puVar5;
                    long lVar6;
                    string imageString = $"image/pict{a2 + 40:D2}.dds";

                    if (*(uint*)(a1 + 0x18a4) != a2)
                    {
                        lVar6 = 0;
                        if (*(long*)(a1 + 0x1770) != 0)
                        {
                            _FUN_1401f9f10(*(long*)(a1 + 0x1770), DAT_142a0b858); //1.02
                            *(ulong*)(a1 + 0x1770) = 0;
                        }
                        bVar2 = true;
                        cVar3 = _FUN_1412f1d70(a1, a2);
                        if (cVar3 != '\0')
                        {
                            bool gotofalse = false;
                        LAB_1412ee816:
                            if ((*(uint*)(a1 + 0x1c) >> 0xc & 1) == 0 && gotofalse == false)
                            {
                                puVar5 = (ushort*)(a1 + 0x30);
                                do
                                {

                                    if (*puVar5 == a2)
                                    {
                                        gotofalse = true;
                                        goto LAB_1412ee816;
                                    }
                                    lVar6 = lVar6 + 1;
                                    puVar5 = puVar5 + 1;
                                } while (lVar6 < 0xc);
                            }
                            else
                            {
                                bVar2 = false;
                            }
                        }
                        bVar1 = false;
                        lVar6 = a2;
                        if ((*(uint*)(a1 + 0x1c) >> 0xc & 1) == 0)
                        {
                            bVar1 = bVar2;
                        }
                        if (bVar1)
                        {
                            imageString = $"image/pict{a2 + 40:D2}_gray.dds";
                        }
                        *(uint*)(a1 + 0x1910) = *(uint*)(a1 + 0x1910) & 0xfffffffc;
                        if (lVar6 != 0)
                        {
                            uVar4 = (ulong)utils.loadDDS(imageString);
                            *(ulong*)(a1 + 0x1770) = uVar4;
                            *(uint*)(a1 + 0x1910) = *(uint*)(a1 + 0x1910) | 1;
                        }
                        *(uint*)(a1 + 0x18a4) = (uint)a2;
                    }
                    return;
                }, lmapImageLoadAdr).Activate();
            });
        }

        private void LmapParamHooks(IReloadedHooks hooks, Utils utils, long lmapParamTable)
        {
            string newLmapFile = @"field/panel/lmap/lmapParams.dat";
            var newFile = utils.OpenFile(newLmapFile, 0);

            var fileBuffer = newFile->bufferSize;

            var fileAddress = newFile->pointerToFile;

            var memory = Memory.Instance;

            memory.SafeReadRaw((nuint)fileAddress, out byte[] paramBytes, (int)fileBuffer);

            memory.SafeWriteRaw((nuint)lmapParamTable - 328, paramBytes);
        }

        private void LmapCmmHooks(IReloadedHooks hooks, Utils utils, List<nint> lmapCmmPtrInstructions, List<nint> lmapCmmLimitInstructions, List<nint> lmapCmmListEndPtrInstructions)
        {
            var memory = Memory.Instance;

            string newCmmFile = @"field/panel/lmap/lmapCmmIds.dat";

            string[] cmmIdListRegisters = { "r10", "r12", "rdi", "rbx" };
            string[] cmmIdEndListRegisters = { "rax", "rbp" };

            var newFile = utils.OpenFile(newCmmFile, 0);

            var fileBuffer = newFile->bufferSize;

            var fileAddress = newFile->pointerToFile;

            for (int i = 0; i < lmapCmmPtrInstructions.Count; i++)
            {
                string[] CmmListPointerAsm = { $"use64", $"mov {cmmIdListRegisters[i]}, 0x{fileAddress:X8}" };
                _cmmLmapTablePtr = hooks.CreateAsmHook(CmmListPointerAsm, lmapCmmPtrInstructions[i], Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
            }

            for (int i = 0; i < lmapCmmLimitInstructions.Count; i++) //update corptbl id limit
            {
                if (i == 0)
                    memory.SafeWrite(lmapCmmLimitInstructions[i] + 3, (byte)(fileBuffer / 8));
                else
                    memory.SafeWrite(lmapCmmLimitInstructions[i] + 2, (byte)(fileBuffer / 8));
            }

            for (int i = 0; i < lmapCmmListEndPtrInstructions.Count; i++)
            {
                string[] CmmListEndAsm = { $"use64", $"mov {cmmIdEndListRegisters[i]}, 0x{fileAddress + fileBuffer:X8}" };
                _cmmLmapTableEnd = hooks.CreateAsmHook(CmmListEndAsm, lmapCmmListEndPtrInstructions[i], Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
            }
        }

        private void LmapCmmFieldHooks(IReloadedHooks hooks, Utils utils, List<nint> lmapFieldPtrInstructions, List<nint> lmapFieldEndPtrInstructions)
        {
            string[] fieldListPtrRegisters = { "r9", "r9", "r13", "r13", "r12", "r12" };
            string[] fieldListEndAdrRegisters = { "rax", "rax", "r15", "r15", "r12", "r12" };

            string newLmapFile = @"field/panel/lmap/lmapCmmFields.dat";
            var newFile = utils.OpenFile(newLmapFile, 0);

            var fileBuffer = newFile->bufferSize;

            var fileAddress = newFile->pointerToFile;

            ulong[] fieldIdListOffsets = new ulong[36];
            int fileOffset = 0;

            for (int i = 0; i < fieldIdListOffsets.Length; i++)
            {
                if (i == 0)
                    fieldIdListOffsets[i] = 0;
                else
                    fieldIdListOffsets[i] = (ulong)(fileAddress + (fileOffset * 4));

                while (true)
                {
                    int* fieldId = (int*)(fileAddress + (fileOffset * 4));
                    fileOffset++;
                    if (*fieldId == -1)
                        break;
                }
            }

            fixed (ulong* fieldIdListOffsetsPtr = fieldIdListOffsets)
            {
                utils.DebugLog($"fieldIdListOffsetsPtr: {(long)fieldIdListOffsetsPtr:X8}", Color.PaleGreen);
                for (int i = 0; i < lmapFieldPtrInstructions.Count; i++)
                {
                    string[] lmapFieldPointerListAsm = { $"use64", $"mov {fieldListPtrRegisters[i]}, 0x{(long)fieldIdListOffsetsPtr:X8}" };
                    string[] lmapFieldEndListAsm = { $"use64", $"mov {fieldListEndAdrRegisters[i]}, 0x{(long)(fieldIdListOffsetsPtr + 36):X8}" };
                    _cmmLmapFieldPtr = hooks.CreateAsmHook(lmapFieldPointerListAsm, lmapFieldPtrInstructions[i], Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
                    _cmmLmapFieldEnd = hooks.CreateAsmHook(lmapFieldEndListAsm, lmapFieldEndPtrInstructions[i], Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
                };
            }
        }
    }
}
