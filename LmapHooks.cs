using Reloaded.Hooks.Definitions;
using Reloaded.Memory.Sources;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using static Unhardcoded_P5R.Utils;
using static Reloaded.Hooks.Definitions.X64.FunctionAttribute;
using Reloaded.Hooks.Definitions.X64;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics;

namespace Unhardcoded_P5R
{
    internal unsafe class LmapHooks
    {
        [Function(new[] { Register.rdi }, Register.rcx, true, new[] {Register.rdi, Register.rdx, Register.r8})]
        private delegate nint d_CreateImagePath(int index);
        private d_CreateImagePath _createImagePath;

        [Function(new[] { Register.rdi }, Register.rcx, true, new[] { Register.rdi, Register.rdx, Register.r8})]
        private delegate nint d_CreateGrayImagePath(int index);
        private d_CreateGrayImagePath _createGrayImagePath;

        [Function(new[] { Register.r8, Register.rdx, Register.r9 }, Register.r10, true)]
        private delegate int d_FindCmmField1(int fldMajor, int fldMinor, P5RField** cmmTable);
        private d_FindCmmField1 _findCmmField1;

        [Function(new[] { Register.r9, Register.rdx, Register.r8 }, Register.r10, true)]
        private delegate int d_FindCmmField2(int fldMajor, int fldMinor, P5RField** cmmTable);
        private d_FindCmmField2 _findCmmField2;

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

        private IReloadedHooks _hooks;
        private Utils _utils;
        private byte[] file;

        private readonly List<AsmHookWrapper> asmHookWrappers = new();
        private readonly Dictionary<int, LmapDestination> _lmapDestinationDict = new();

        nint lmapParamTable;
        internal LmapHooks(IReloadedHooks hooks, Utils utils)
        {
            utils.DebugLog("Loading Lmap Module", Color.PaleGreen);

            _hooks = hooks;
            _utils = utils;

            _createImagePath = CreateImagePath;
            _createGrayImagePath = CreateGrayImagePath;

            _findCmmField1 = FindCmmField;
            _findCmmField2 = FindCmmField;

            nint getMapImageAdr = 0;
            nint FUN_14eec6d60adr = 0;

            nint mapImagePtr = 0;

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

            utils.SigScan("4C 8D 15 ?? ?? ?? ?? F3 43 0F 10 5C", "lmapParamTable", (result) => //Lmap SPD Parameters (data scan)
            {
                lmapParamTable = _utils.GetAddressFromGlobalRef(result, 7);
            });

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

            utils.SigScan("FF C9 BA FF FF FF FF 83 F9 0D", "lmapIdtoPointerIndexAdr", (lmapIdtoPointerIndexAdr) => // 0x141342c50
            {
                _lmapIdtoFieldListPointerIndex = hooks.CreateHook<LmapIdtoFieldListPointerIndex>((a1) =>
                {
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

            utils.SigScan("4A 8B 8C ?? ?? ?? ?? ?? A8 01", "lmapImageLoad", (result) => // Lmap Image Function 0x14134137e
            {
                string[] asm =
                {
                    "use64",
                    hooks.Utilities.GetAbsoluteCallMnemonics(_createImagePath, out var wrapper),
                };

                asmHookWrappers.Add(new AsmHookWrapper
                {
                    asmHook = hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate(),
                    reverseWrapper = wrapper
                });
            });

            utils.SigScan("4A 8B 8C ?? ?? ?? ?? ?? 83 A3 ?? ?? ?? ?? FC", "lmapGrayImageLoad", (result) => // Lmap Gray Image Function 0x14134137e
            {
                string[] asm =
                {
                    "use64",
                    hooks.Utilities.GetAbsoluteCallMnemonics(_createGrayImagePath, out var wrapper),
                };

                asmHookWrappers.Add(new AsmHookWrapper
                {
                    asmHook = hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate(),
                    reverseWrapper = wrapper
                });
            });

            utils.SigScan("49 8B 01 48 85 C0 74 ?? 0F 1F 80 00 00 00 00 0F B7 08 66 83 F9 FF 74 ?? 66 41 3B C8 75 ?? 66 39 50 ?? 74 ?? 48 83 C0 04 75 ?? 41 FF C2 48 8D 05 ?? ?? ?? ?? 49 83 C1 08 4C 3B C8 7C ?? 44 8B D7", "FindCmmField1", (result) => // Get Lmap Cmm Ids 0x1411e5681
            {
                string[] asm =
                {
                    "use64",
                    hooks.Utilities.GetAbsoluteCallMnemonics(_findCmmField1, out var wrapper),
                    hooks.Utilities.GetAbsoluteJumpMnemonics((nint)0x1411e56c1, true)
                };

                asmHookWrappers.Add(new AsmHookWrapper
                {
                    asmHook = hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate(),
                    reverseWrapper = wrapper
                });
            });

            utils.SigScan("49 8B 00 48 85 C0 74 ?? 0F 1F 84 ?? 00 00 00 00 0F B7 08 66 83 F9 FF 74 ?? 66 41 3B C9 75 ?? 66 39 50 ?? 74 ?? 48 83 C0 04 75 ?? 41 FF C2 49 83 C0 08 4D 3B C4 7C ?? 45 33 D2 45 3B FA", "FindCmmField2", (result) => // Get Lmap Cmm Ids 0x1411e59b0
            {
                string[] asm =
                {
                    "use64",
                    hooks.Utilities.GetAbsoluteCallMnemonics(_findCmmField2, out var wrapper),
                    hooks.Utilities.GetAbsoluteJumpMnemonics((nint)0x1411e59ea, true)
                };

                asmHookWrappers.Add(new AsmHookWrapper
                {
                    asmHook = hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate(),
                    reverseWrapper = wrapper
                });
            });
        }
        nint CreateImagePath(int index)
        {
            return Marshal.StringToHGlobalAnsi($"image/pict{index + 40:D2}.dds");
        }

        nint CreateGrayImagePath(int index)
        {
            return Marshal.StringToHGlobalAnsi($"image/pict{index + 40:D2}_gray.dds");
        }

        internal void ReadLmapSpriteParamFile(string filePath)
        {
            if (!File.Exists(filePath))
                return;

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                IncludeFields = true,
                AllowTrailingCommas = true,
            };

            var lmapParams = (List<LmapDestination>)JsonSerializer.Deserialize(File.ReadAllText(filePath), typeof(List<LmapDestination>), options);

            foreach (var param in lmapParams)
            {
                if (param.Id > 35 || param.Id < 0)
                    throw new ArgumentOutOfRangeException(nameof(param.Id));

                if (param.SpriteParams != null)
                    _utils.Log($"Registering Lmap params for Id {param.Id}");
                if (param.LmapConfidantFields != null)
                    _utils.Log($"Registering Lmap confidant fields for Id {param.Id}");

                _lmapDestinationDict[param.Id] = param;
            }
        }
        internal void WriteNewLmapParamTable()
        {
            var memory = Memory.Instance;

            foreach (var (key, value) in _lmapDestinationDict)
            {
                if (value.SpriteParams != null)
                {
                    var structSize = Marshal.SizeOf(typeof(LmapSpriteParams));
                    var tblEntryAddress = (nuint)(lmapParamTable + (structSize * key));
                    memory.ChangePermission(tblEntryAddress, structSize, Reloaded.Memory.Kernel32.Kernel32.MEM_PROTECTION.PAGE_READWRITE);
                    Marshal.StructureToPtr(value.SpriteParams, (nint)tblEntryAddress, false);
                }
            }
        }

        internal int FindCmmField(int fldMajor, int fldMinor, P5RField** cmmTable)
        {
            for (int i = 0; i < 36; i++)
            {
                if (_lmapDestinationDict.TryGetValue(i, out var value) && value.LmapConfidantFields != null)
                {
                    var fields = value.LmapConfidantFields;

                    foreach (var field in fields)
                    {
                        if (fldMajor == field.FieldMajorId && fldMinor == field.FieldMinorId)
                        {
                            return i;
                        }
                    }
                }
                else if (i < 27)
                {
                    var index = GetLmapDestinationTableIndex(i);
                    int j = 0;
                    while (true)
                    {
                        if (cmmTable[index] == null)
                        {
                            j++;
                            break;
                        }

                        var field = cmmTable[index][j];
                
                        if (field.FieldMajorId == -1)
                            break;
                        else if (field.FieldMajorId == fldMajor && fldMinor == field.FieldMinorId)
                            return i;
                
                        j++;
                    }
                }
            }

            return 0;
        }

        int GetLmapDestinationTableIndex(int param_1)
        {
            switch (param_1)
            {
                case 1:
                    return 1;
                case 2:
                    return 3;
                case 3:
                    return 2;
                case 4:
                    return 4;
                case 5:
                    return 5;
                case 6:
                    return 6;
                case 7:
                    return 0xc;
                case 0xe:
                    return 0x18;
                default:
                    return param_1;
            }
        }
    }

    public class LmapDestination
    {
        /// <summary>
        /// Index of the param entry
        /// </summary>
        public int Id;

        /// <summary>
        /// Sprite parameters for sprites that show up on the railmap
        /// </summary>
        public LmapSpriteParams SpriteParams;

        /// <summary>
        /// Fields that will show a card if a confidant is available there.
        /// </summary>
        public P5RField[]? LmapConfidantFields;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0xb4, Pack = 1)]
    public unsafe class LmapSpriteParams
    {
        [FieldOffset(0)]
        public Vector2 PlayerIconPos;
        [FieldOffset(8)]
        public float[] unk1;
        [FieldOffset(0x28)]
        public Vector2 MainIconPoint1;
        [FieldOffset(0x30)]
        public Vector2 MainIconPoint2;
        [FieldOffset(0x38)]
        public float[] unk2;
        [FieldOffset(0x48)]
        public Vector2 Kanji1;
        [FieldOffset(0x50)]
        public Vector2 KanjiPoint2;
        [FieldOffset(0x58)]
        public Vector2 LabelPoint1;
        [FieldOffset(0x60)]
        public Vector2 LabelPoint2;
        [FieldOffset(0x68)]
        public Vector2 OuterTopLeftLabelBox;
        [FieldOffset(0x70)]
        public Vector2 OuterTopRightLabelBox;
        [FieldOffset(0x78)]
        public Vector2 OuterBottomLeftLabelBox;
        [FieldOffset(0x80)]
        public Vector2 OuterBottomRightLabelBox;
        [FieldOffset(0x88)]
        public Vector2 InnerTopLeftLabelBox;
        [FieldOffset(0x90)]
        public Vector2 InnerTopRightLabelBox;
        [FieldOffset(0x98)]
        public Vector2 InnerBottomLeftLabelBox;
        [FieldOffset(0xa0)]
        public Vector2 InnerBottomRightLabelBox;
        [FieldOffset(0xa8)]
        public byte MainSpdId;
        [FieldOffset(0xa9)]
        public byte MainSpd2Unused;
        [FieldOffset(0xaa)]
        public byte KanjiSpdId;
        [FieldOffset(0xab)]
        public byte LableSpdId;
    }

    [StructLayout(LayoutKind.Sequential, Size = 4)]
    public struct P5RField
    {
        public short FieldMajorId;
        public short FieldMinorId;

        public override string ToString()
        {
            return $"f{FieldMajorId:D3}_{FieldMinorId:D3}";
        }
    }

    public class LmapSilhouetteArtFields
    {
        string LmapSilhouetteArtPath;
        P5RField[] Fields;
    }
}
