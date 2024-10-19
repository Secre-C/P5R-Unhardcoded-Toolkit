using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Memory.Sources;
using System.Drawing;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text.Json;
using static Reloaded.Hooks.Definitions.X64.FunctionAttribute;
using static Unhardcoded_P5R.Utils;

namespace Unhardcoded_P5R
{
    internal unsafe class LmapHooks
    {
        [Function(new[] { Register.rdi }, Register.rcx, true, new[] { Register.rdi, Register.rdx, Register.r8 })]
        private delegate nint d_CreateImagePath(int index);
        private d_CreateImagePath _createImagePath;

        [Function(new[] { Register.rdi }, Register.rcx, true, new[] { Register.rdi, Register.rdx, Register.r8 })]
        private delegate nint d_CreateGrayImagePath(int index);
        private d_CreateGrayImagePath _createGrayImagePath;

        [Function(new[] { Register.r8, Register.rdx, Register.r9 }, Register.r10, true)]
        private delegate int d_FindCmmField1(int fldMajor, int fldMinor, P5RField** cmmTable);
        private d_FindCmmField1 _findCmmField1;

        [Function(new[] { Register.r9, Register.rdx, Register.r8 }, Register.r10, true)]
        private delegate int d_FindCmmField2(int fldMajor, int fldMinor, P5RField** cmmTable);
        private d_FindCmmField2 _findCmmField2;

        [Function(new[] { Register.rax, Register.rbx }, Register.rax, true)]
        private delegate int d_GetLmapSilhouetteImage(int fileNameIndex, LmapImageInfo* lmapImageInfo);
        private d_GetLmapSilhouetteImage _getLmapSilhouetteImage;

        private delegate FieldWork* GetFieldWork();
        private GetFieldWork _getFieldWork;

        private delegate long LmapIdtoFieldListPointerIndex(int a1);
        private IHook<LmapIdtoFieldListPointerIndex> _lmapIdtoFieldListPointerIndex;

        private IReloadedHooks _hooks;
        private Utils _utils;

        private readonly List<AsmHookWrapper> asmHookWrappers = new();

        private readonly Dictionary<int, LmapDestination> _lmapDestinationDict = new();
        private List<LmapSilhouetteImageFields> _lmapSilhouetteImageFields;

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

            _getLmapSilhouetteImage = GetLmapSilhouetteImage;

            utils.SigScan("4C 8D 15 ?? ?? ?? ?? F3 42 0F 10 5C", "lmapParamTable", (result) => //Lmap SPD Parameters (data scan)
            {
                lmapParamTable = _utils.GetAddressFromGlobalRef(result, 7);
            });

            utils.SigScan("FF C9 BA FF FF FF FF 83 F9 0D", "lmapIdtoPointerIndexAdr", (lmapIdtoPointerIndexAdr) => // 0x141342c50
            {
                _lmapIdtoFieldListPointerIndex = hooks.CreateHook<LmapIdtoFieldListPointerIndex>((a1) =>
                {
                    return a1;
                }, lmapIdtoPointerIndexAdr).Activate();
            });

            utils.SigScan("40 53 48 83 EC 20 48 8B 1D ?? ?? ?? ?? 48 85 DB 0F 84 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ??", "getFieldWork", (result) =>
            {
                _getFieldWork = hooks.CreateWrapper<GetFieldWork>(result, out var wrapper);
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
                    hooks.Utilities.GetAbsoluteJumpMnemonics(result + 0x40, true)
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
                    hooks.Utilities.GetAbsoluteJumpMnemonics(result + 0x3a, true)
                };

                asmHookWrappers.Add(new AsmHookWrapper
                {
                    asmHook = hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate(),
                    reverseWrapper = wrapper
                });
            });

            utils.SigScan("83 F8 FF 74 ?? 48 63 C8 45 33 C0 89 83 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 49 8B 8C", "LoadMap_l_Image", (result) => // Load Map L silhouette image 0x14135c9b6
            {
                string[] asm =
                {
                    "use64",
                    hooks.Utilities.GetAbsoluteCallMnemonics(_getLmapSilhouetteImage, out var wrapper),
                };

                asmHookWrappers.Add(new AsmHookWrapper
                {
                    asmHook = hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate(),
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

        internal void ReadLmapSilhouetteFieldFile(string filePath)
        {
            if (!File.Exists(filePath)) return;

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                IncludeFields = true,
                AllowTrailingCommas = true,
            };

            _lmapSilhouetteImageFields = (List<LmapSilhouetteImageFields>)JsonSerializer.Deserialize(File.ReadAllText(filePath), typeof(List<LmapSilhouetteImageFields>), options);
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

        internal int GetLmapSilhouetteImage(int fileNameIndex, LmapImageInfo* lmapImageInfo)
        {
            var field = _getFieldWork()->FieldInfo->Field;

            foreach (var image in _lmapSilhouetteImageFields)
            {
                foreach (var fieldId in image.Fields)
                {
                    if (fieldId.FieldMajorId == field.FieldMajorId && (fieldId.FieldMinorId == field.FieldMinorId || fieldId.FieldMinorId == -1))
                    {
                        lmapImageInfo->fileNameTableIndex1 = -1;
                        lmapImageInfo->fileNameTableIndex2 = -1;
                        lmapImageInfo->lmapImageData = _utils.loadDDS("field/panel/lmap/" + image.ImageFileName);
                        lmapImageInfo->lmapImageBitflag = lmapImageInfo->lmapImageBitflag & 0xfffffffe | 0x20000;
                        return -1;
                    }
                }
            }

            return fileNameIndex;
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
        public LmapSpriteParams? SpriteParams;

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
        public Vector2 CmmCardIconPos;
        [FieldOffset(0x10)]
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

    public class LmapSilhouetteImageFields
    {
        public string ImageFileName;
        public P5RField[] Fields;
    }

    [StructLayout(LayoutKind.Explicit)]
    unsafe internal struct FieldWork
    {
        [FieldOffset(0x48)]
        internal FieldInfo* FieldInfo;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FieldInfo
    {
        [FieldOffset(0x1f0)]
        internal P5RField Field;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct LmapImageInfo
    {
        [FieldOffset(0x10)]
        internal uint lmapImageBitflag;

        [FieldOffset(0x160)]
        internal nint lmapImageData;

        [FieldOffset(0x168)]
        internal int fileNameTableIndex1;

        [FieldOffset(0x16c)]
        internal int fileNameTableIndex2;
    }
}
