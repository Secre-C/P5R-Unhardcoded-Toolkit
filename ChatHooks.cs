using Reloaded.Hooks.Definitions;
using Reloaded.Memory.Sources;
using System.Drawing;
using static Unhardcoded_P5R.Utils;

namespace Unhardcoded_P5R
{
    internal unsafe class ChatHooks
    {
        private delegate nint d_LoadColorFile();
        private d_LoadColorFile _loadColorFile;

        private delegate nint d_LoadParamFile();
        private d_LoadParamFile _loadParamFile;

        private delegate short GetChatNameId(int a1);
        private delegate char* GetChatName(int a1);

        private IHook<GetChatNameId> _getChatNameId;
        private IHook<GetChatName> _getChatName;

        private AsmHookWrapper _chatColorBgHook;
        private AsmHookWrapper _chatColorPrvwBgHook;

        private List<AsmHookWrapper> _chatParamHooks;

        private readonly List<nint> _chatIconLimitInstructions;

        private fileHandleStruct* _chatColorTableData;
        private fileHandleStruct* _chatParamTableData;
        private fileHandleStruct* _chatNameTableData;

        private readonly Utils _utils;
        private readonly IReloadedHooks _hooks;
        internal ChatHooks(IReloadedHooks hooks, Utils utils)
        {
            _hooks = hooks;
            _utils = utils;

            utils.DebugLog("Loading Chat Module", Color.PaleGreen);

            byte langIndex = 0;

            _chatParamHooks = new();
            _chatIconLimitInstructions = new();

            string[] newNameFile =
                { @"font/Chat/Names/ChatNameIds_En.dat",
                @"font/chat/Names/ChatNameIds_Fr.dat",
                @"font/chat/Names/ChatNameIds_It.dat",
                @"font/chat/Names/ChatNameIds_De.dat",
                @"font/chat/Names/ChatNameIds_Es.dat" };

            string[] chatIconParamRaxPatterns =
            {
                "48 8D 05 ?? ?? ?? ?? 48 03 F8 F3 44 0F 10 AC 24 ?? ?? ?? ??",
                "48 8D 05 ?? ?? ?? ?? 48 03 D8 66 83 3B ??",
                "48 8D 05 ?? ?? ?? ?? 48 03 C8 48 8B C1",
                "48 8D 05 ?? ?? ?? ?? 48 03 F8 66 39 1F"
            };

            string[] chatIconLimitPatterns =
            {
                "66 83 FB 32 73 ?? 66 41 3B DE",
                "66 83 F8 32 0F 83 ?? ?? ?? ??",
                "66 41 83 F8 32 72 ??",
            };

            utils.SigScan("48 8D 15 ?? ?? ?? ?? F3 44 0F 11 7C 24 ?? 4C 8D 0D ?? ?? ?? ??", "chatIconPreviewBgColor", (chatIconPreviewBgColor) => // Chat Preview Icon Color Pointer
            {
                _chatColorPrvwBgHook = RedirectIconColorTable(chatIconPreviewBgColor);
            });

            utils.SigScan("48 8D 15 ?? ?? ?? ?? 8B 1C ??", "chatIconBgColor", (chatIconBgColor) => // Chat Icon Background Color Pointer
            {
                _chatColorBgHook = RedirectIconColorTable(chatIconBgColor);
            });

            for (int i = 0; i < chatIconParamRaxPatterns.Length; i++)
            {
                utils.SigScan(chatIconParamRaxPatterns[i], $"chatIconParam_RAX_{i}", (result) => //Chat Icon Spd Parameter Pointer
                {
                    _chatParamHooks.Add(RedirectIconParamTable(result, false));
                });
            }

            utils.SigScan("48 8D 0D ?? ?? ?? ?? 48 6B C0 34", "chatIconParam_RCX", (result) => //Chat Icon Spd Parameter Pointer
            {
                _chatParamHooks.Add(RedirectIconParamTable(result, true));
            });

            for (int i = 0; i < chatIconLimitPatterns.Length; i++)
            {
                utils.SigScan(chatIconLimitPatterns[i], $"chatIconLimit[{i}]", (result) =>  //Chat Icon Limit
                {
                    _chatIconLimitInstructions.Add(result);
                });
            }

            utils.SigScan("8B 05 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 48 8B CE", "Global_lang", (result) =>
            {
                langIndex = *(byte*)utils.GetAddressFromGlobalRef(result, 6, "Global_lang");
            });

            utils.SigScan("0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ??",
                "getChatNameId", (getChatNameId) =>
            {
                _getChatNameId = hooks.CreateHook<GetChatNameId>((a1) =>
               {
                   if (_chatNameTableData == null)
                       _chatNameTableData = utils.OpenFile(newNameFile[langIndex], 0);

                   var fileAddress = _chatNameTableData->pointerToFile;
                   short ChatID = *(short*)(fileAddress + (a1 * 8));
                   return ChatID;
               }, getChatNameId).Activate();
            });

            utils.SigScan("48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ??",
                    "getChatName", (getChatName) =>
            {
                _getChatName = hooks.CreateHook<GetChatName>((a1) =>
                {
                    if (_chatNameTableData == null)
                        _chatNameTableData = utils.OpenFile(newNameFile[langIndex], 0);

                    var fileAddress = _chatNameTableData->pointerToFile;
                    char* result = (char*)(fileAddress + 2 + (a1 * 0x30));
                    return result;
                }, getChatName).Activate();
            });
        }

        private AsmHookWrapper RedirectIconColorTable(nint address)
        {
            _loadColorFile = LoadChatIconColorFile;

            string[] asm =
            {
                $"use64",
                PushCallerRegisters,
                "sub rsp, 0x20",
                _hooks.Utilities.GetAbsoluteCallMnemonics(_loadColorFile, out var reverseWrapper),
                "add rsp, 0x20",
                PopCallerRegisters,
                "mov rdx, rax",
                "movsx rax, r14w"
            };

            AsmHookWrapper asmHook;

            asmHook.reverseWrapper = reverseWrapper;
            asmHook.asmHook = _hooks.CreateAsmHook(asm, address, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();

            return asmHook;
        }

        private nint LoadChatIconColorFile()
        {
            if (_chatColorTableData != null)
                return _chatColorTableData->pointerToFile;

            string newColorFile = @"font/chat/ChatBgColors.dat";
            var colorTableFile = _utils.OpenFile(newColorFile, 0);

            if (colorTableFile == null)
                throw new Exception($"Failed to load {newColorFile}");

            _chatColorTableData = colorTableFile;
            return colorTableFile->pointerToFile;
        }

        private AsmHookWrapper RedirectIconParamTable(nint address, bool useRCX, int rspAlignmentOffset = 0)
        {
            _loadParamFile = LoadChatIconParamFile;

            List<string> asm = new List<string>()
            {
                $"use64",
                PushCallerRegisters,
                "sub rsp, 0x20",
                _hooks.Utilities.GetAbsoluteCallMnemonics(_loadParamFile, out var reverseWrapper),
                "add rsp, 0x20",
                PopCallerRegisters,
            };

            if (useRCX)
                asm.Add("mov rcx, rax");

            AsmHookWrapper asmHook;

            asmHook.reverseWrapper = reverseWrapper;
            asmHook.asmHook = _hooks.CreateAsmHook(asm.ToArray(), address, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();

            return asmHook;
        }

        private nint LoadChatIconParamFile()
        {
            if (_chatParamTableData != null)
                return _chatParamTableData->pointerToFile;

            string newParamFilePath = @"font/chat/ChatIconParams.dat";
            var newParamTableFile = _utils.OpenFile(newParamFilePath, 0);

            if (newParamTableFile == null)
                throw new Exception($"Failed to load {newParamFilePath}");

            //Add Variable limit for chat icon slots.
            var memory = Memory.Instance;

            var fileBuffer = newParamTableFile->bufferSize;

            memory.SafeWrite(_chatIconLimitInstructions[0] + 3, (byte)(fileBuffer / 52));
            memory.SafeWrite(_chatIconLimitInstructions[1] + 3, (byte)(fileBuffer / 52));
            memory.SafeWrite(_chatIconLimitInstructions[2] + 4, (byte)(fileBuffer / 52));

            _chatParamTableData = newParamTableFile;
            return _chatParamTableData->pointerToFile;
        }
    }

    class ChatIconParams
    {
        internal string Name;
        internal int Color;
        internal short Unk0;
        internal short ChatSPD_ID;
        internal float IconXOffset;
        internal float IconYOffset;
        internal float IconScale;
        internal float IconRotation;
        internal float PreviewIconXOffset;
        internal float PreviewIconYOffset;
        internal float PreviewIconScale;
        internal float PreviewIconRotate;
        internal int Unk2;
        internal int Unk3;
        internal int Unk4;
        internal int Unk5;
    }
}
