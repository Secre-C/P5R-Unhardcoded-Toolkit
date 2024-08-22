using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Memory.Sources;
using Reloaded.Mod.Interfaces;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using static Reloaded.Hooks.Definitions.X64.FunctionAttribute;
using static Unhardcoded_P5R.Utils;

namespace Unhardcoded_P5R
{
    internal unsafe class ChatHooks
    {
        [Function(new[] { Register.rdx, Register.rax }, Register.rdx, true, new[] {Register.r8})]
        private delegate uint d_GetIconBgColor(nint colorTable, short index);
        private d_GetIconBgColor _getIconBgColor;

        [Function(CallingConventions.Microsoft)]
        private delegate nint d_GetIconParams(nint colorTable, nint ogOffset);
        private d_GetIconParams _getIconParams;

        [Function(Register.rdi, Register.rdi, true)]
        private delegate int d_CreateExpandedChatNameList(int numOfOriginalEntries);
        private d_CreateExpandedChatNameList _createExpandedChatNameList;

        private delegate short GetChatNameId(int a1);
        private delegate nint GetChatName(int a1);

        private IHook<GetChatNameId> _getChatNameId;
        private IHook<GetChatName> _getChatName;

        private List<AsmHookWrapper> _asmHookWrappers;

        private readonly Utils _utils;
        private readonly IReloadedHooks _hooks;
        private readonly IModLoader _modLoader;

        private Dictionary<int, ChatIconParams> _chatIconParamIdDict;
        private Dictionary<int, ChatIconParams> _expandedChatIconParamDict;
        internal ChatHooks(IModLoader modLoader, IReloadedHooks hooks, Utils utils)
        {
            //Debugger.Launch();
            _hooks = hooks;
            _utils = utils;
            _modLoader = modLoader;

            _getIconBgColor = GetChatIconBgColor;
            _getIconParams = GetChatIconParams;
            _createExpandedChatNameList = CreateExpandedChatNameList;

            _chatIconParamIdDict = new();
            _expandedChatIconParamDict = new();

            var chatJsonPath = Path.Join(_modLoader.GetDirectoryForModId("p5rpc.unhardcodedp5r"), "UnhardcodedP5R", "ChatIconParams.json");
            ReadChatIconParamFile(chatJsonPath);

            utils.DebugLog("Loading Chat Module", Color.PaleGreen);

            _asmHookWrappers = new();

            /* Color */

            utils.SigScan("8B 14 ?? 8B CA 8B C2 C1 E9 08 88 4C 24", "chatIconPreviewBgColor", (chatIconPreviewBgColor) => // Chat Preview Icon Color Pointer 0x1417d7a03
            {
                string[] asm =
                {
                    $"use64",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_getIconBgColor, out var reverseWrapper),
                    "mov ecx, edx",
                    "mov eax, edx",
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, chatIconPreviewBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate()
                });
            });

            utils.SigScan("66 85 C9 78 ?? F3 0F 10 0D", "chatIconBgColor", (chatIconBgColor) => // Chat Icon Background Color Pointer 0x1417d7dd3
            {
                string[] asm =
                {
                    $"use64",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_getIconBgColor, out var reverseWrapper),
                    "mov rbx, rdx",
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, chatIconBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate()
                });
            });

            utils.SigScan("41 8B 94 ?? ?? ?? ?? ?? 8B CA 8B C2 C1 E9 08 88 4C 24", "chatPhotoSenderIconBgColor", (chatIconBgColor) => // Chat Icon Background Color Pointer 0x1417c81ef
            {
                nint hookInstruction = chatIconBgColor + 8;
                nint colorTableAddress = (nint)(*(int*)(chatIconBgColor + 4) + 0x140000000);
                
                string[] asm =
                {
                    $"use64",
                    $"mov rdx, {colorTableAddress}",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_getIconBgColor, out var reverseWrapper),
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, hookInstruction, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate()
                });
            });

            /* Params */

            utils.SigScan("F3 44 0F 10 AC 24 ?? ?? ?? ?? 41 0F 28 CD F3 0F 59 0D ?? ?? ?? ?? 0F 28 C1 E8 ?? ?? ?? ?? 66 44 39 27", "GroupIconParam", (chatIconBgColor) => // Chat Icon Spd Parameter Pointer 0x1417c72e8
            {
                string[] asm =
                {
                    $"use64",
                    "mov RCX, RAX",
                    "mov RDX, RDI",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_getIconParams, out var reverseWrapper),
                    "mov rdi, rax",
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, chatIconBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate()
                });
            });

            utils.SigScan("66 83 3B ?? 0F BF 53", "ImageSenderIconParam", (chatIconBgColor) => // Chat Icon Spd Parameter Pointer 0x1417c7a71
            {
                string[] asm =
                {
                    $"use64",
                    "mov RCX, RAX",
                    "mov RDX, RBX",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_getIconParams, out var reverseWrapper),
                    "mov rbx, rax",
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, chatIconBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate()
                });
            });

            utils.SigScan("66 39 1F 4C 8B 3D", "ChatIconParam", (chatIconBgColor) => // Chat Icon Spd Parameter Pointer 0x1417c72e8
            {
                string[] asm =
                {
                    $"use64",
                    "mov RCX, RAX",
                    "mov RDX, RDI",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_getIconParams, out var reverseWrapper),
                    "mov rdi, rax",
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, chatIconBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate()
                });
            });

            /* Name */

            // nop id bounds checks
            _utils.SigScan("73 ?? 66 41 3B DE", (result) =>
            {
                Memory.Instance.SafeWrite(result, (ushort)0x9090);
            });

            _utils.SigScan("0F 83 ?? ?? ?? ?? 66 83 F8 01", (result) =>
            {
                Memory.Instance.SafeWrite(result, (ushort)0x9090);
                Memory.Instance.SafeWrite(result + 2, (uint)0x90909090);
            });

            // 0x1417d75ca patch in jmp instruction
            _utils.SigScan("72 ?? 44 8B F3 F3 44 0F 10 84 24", (chatIconLimit) =>
            {
                Memory.Instance.SafeWrite(chatIconLimit, (byte)0xeb);
            });

            utils.SigScan("8D 04 ?? BA 10 00 00 00 C1 E0 04 8B C8", "chatParamAlloc", (result) =>
            {
                string[] asm =
                {
                    $"use64",
                    _hooks.Utilities.GetAbsoluteCallMnemonics(_createExpandedChatNameList, out var reverseWrapper),
                    "mov rdi, rax"
                };

                _asmHookWrappers.Add(new AsmHookWrapper
                {
                    reverseWrapper = reverseWrapper,
                    asmHook = _hooks.CreateAsmHook(asm, result, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate()
                });
            });

            utils.SigScan("48 63 05 ?? ?? ?? ?? 83 F8 0A 0F 87 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 41 8B 94 ?? ?? ?? ?? ?? 49 03 D0 FF E2 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04",
                    "getChatName", (getChatName) =>
            {
                _getChatName = hooks.CreateHook<GetChatName>((a1) =>
                {            
                    if (_expandedChatIconParamDict.TryGetValue(a1, out var chatIconParams) && chatIconParams.Name != null)
                    {
                        return Marshal.StringToHGlobalAnsi(chatIconParams.Name);
                    }

                    return _getChatName.OriginalFunction(a1);
                }, getChatName).Activate();
            });

            utils.SigScan("48 63 05 ?? ?? ?? ?? 83 F8 0A 0F 87 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 8B 84 ?? ?? ?? ?? ?? 48 03 C2 FF E0 48 63 C1 48 8D 0C",
                    "getChatId", (getChatId) =>
                    {
                        _getChatNameId = hooks.CreateHook<GetChatNameId>((a1) =>
                        {
                            if (_expandedChatIconParamDict.TryGetValue(a1, out var chatIconParams))
                            {
                                return chatIconParams.Id;
                            }

                            return _getChatNameId.OriginalFunction(a1);
                        }, getChatId).Activate();
                    });
        }

        internal void ReadChatIconParamFile(string filePath)
        {
            if (!File.Exists(filePath))
                return;

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                IncludeFields = true,
                AllowTrailingCommas = true,
                
            };

            var iconParams = (List<ChatIconParams>)JsonSerializer.Deserialize(File.ReadAllText(filePath), typeof(List<ChatIconParams>), options);

            foreach (var param in iconParams)
            {
                _chatIconParamIdDict[param.Id] = param;
            }
        }

        private nint GetChatIconParams(nint paramTable, nint ogOffset)
        {
            short index = (short)((ogOffset - paramTable) / 52);
            if (_chatIconParamIdDict.TryGetValue(index, out var iconParams) && iconParams.ChatIconPRS != null)
            {
                fixed (void* p_iconParams = &iconParams.ChatIconPRS.Unk0)
                {
                    return (nint)p_iconParams;
                }
            }

            return ogOffset;
        }

        private uint GetChatIconBgColor(nint colorTable, short index)
        {
            if (_chatIconParamIdDict.TryGetValue(index, out var iconParams) && iconParams.ChatIconColor != null)
            {
                return iconParams.ChatIconColor.Color;
            }

            return *(uint*)(colorTable + (index * 4));
        }

        private int CreateExpandedChatNameList(int numOfEntries)
        {
            foreach (var entry in _chatIconParamIdDict.Values)
            {
                if (_expandedChatIconParamDict.TryAdd(numOfEntries, entry))
                    _utils.Log($"Adding Chat ID {numOfEntries}");
                numOfEntries++;
            }

            return numOfEntries;
        }
    }

    [StructLayout(LayoutKind.Auto, CharSet = CharSet.Ansi)]
    public class ChatIconParams
    {
        public short Id;
        public string Name;
        public ChatIconPRS ChatIconPRS;
        public ChatIconColor ChatIconColor;
    }

    [StructLayout(LayoutKind.Explicit)]
    public class ChatIconPRS
    {
        [FieldOffset(0)]
        public short Unk0;
        [FieldOffset(2)]
        public short ChatSPD_ID;
        [FieldOffset(4)]
        public float IconXOffset;
        [FieldOffset(8)]
        public float IconYOffset;
        [FieldOffset(12)]
        public float IconScale;
        [FieldOffset(16)]
        public float IconRotation;
        [FieldOffset(20)]
        public float PreviewIconXOffset;
        [FieldOffset(24)]
        public float PreviewIconYOffset;
        [FieldOffset(28)]
        public float PreviewIconScale;
        [FieldOffset(32)]
        public float PreviewIconRotate;
        [FieldOffset(36)]
        public int Unk2;
        [FieldOffset(40)]
        public int Unk3;
        [FieldOffset(44)]
        public int Unk4;
        [FieldOffset(48)]
        public int Unk5;
    }

    public class ChatIconColor
    {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Color;
    }
}
