using Reloaded.Hooks;
using Reloaded.Hooks.Definitions;
using Reloaded.Memory.Pointers;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sigscan.Definitions;
using Reloaded.Memory.Sigscan.Definitions.Structs;
using Reloaded.Memory.SigScan.ReloadedII.Interfaces;
using Reloaded.Memory.Sources;
using Reloaded.Mod.Interfaces;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Text;
using static Unhardcoded_P5R.Utils;

namespace Unhardcoded_P5R
{
    internal unsafe class ChatHooks
    {
        private delegate short GetChatNameId(int a1);
        private delegate char * GetChatName(int a1);

        private IHook<GetChatNameId> _getChatNameId;
        private IHook<GetChatName> _getChatName;

        private IAsmHook _chatColorBgHook;
        private IAsmHook _chatColorPrvwBgHook;

        private IAsmHook _chatParamHook_RAX;
        private IAsmHook _chatParamHook_RCX;
        internal ChatHooks(IReloadedHooks hooks, IModLoader modLoader, Utils utils)
        {
            utils.DebugLog("Loading Chat Module", Color.PaleGreen);

            long lang = 0;

            long chatIconPreviewBgColor = 0;
            long chatIconBgColor = 0;
            long chatIconParam_RCX = 0;
            List<long> chatIconParam_RAX = new();
            List<long> chatIconLimit = new();

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

            utils.IScanner.AddMainModuleScan("48 8D 15 ?? ?? ?? ?? F3 44 0F 11 7C 24 ?? 4C 8D 0D ?? ?? ?? ??", (result) => //Chat Preview Icon Color Pointer
            {
                if (!result.Found)
                {
                    utils.Log("Could not find chatIconPreviewBgColor", Color.PaleVioletRed);
                }

                chatIconPreviewBgColor = result.Offset + utils.baseAddress;
                utils.DebugLog($"Found chatIconPreviewBgColor -> {chatIconPreviewBgColor:X8}");
            });

            utils.IScanner.AddMainModuleScan("48 8D 15 ?? ?? ?? ?? 8B 1C ??", (result) => //Chat Icon Background Color Pointer
            {
                if (!result.Found)
                {
                    utils.Log("Could not find chatIconBgColor", Color.PaleVioletRed);
                    return;
                }

                chatIconBgColor = result.Offset + utils.baseAddress;
                utils.DebugLog($"Found chatIconBgColor -> {chatIconBgColor:X8}");
            });

            for (int i = 0; i < chatIconParamRaxPatterns.Length; i++)
            {
                utils.IScanner.AddMainModuleScan(chatIconParamRaxPatterns[i], (result) => //Chat Icon Spd Parameter Pointer
                {
                    if (!result.Found)
                    {
                        utils.Log($"Could not find chatIconParam_RAX[{i}]", Color.PaleVioletRed);
                        return;
                    }

                    chatIconParam_RAX.Add(result.Offset + utils.baseAddress);
                    utils.DebugLog($"Found chatIconParam_RAX[{i}] -> {result.Offset + utils.baseAddress:X8}");
                });
            }

            utils.IScanner.AddMainModuleScan("48 8D 0D ?? ?? ?? ?? 48 6B C0 34", (result) => //Chat Icon Spd Parameter Pointer
            {
                if (!result.Found)
                {
                    utils.Log("Could not find chatIconParam_RCX", Color.PaleVioletRed);
                    return;
                }

                chatIconParam_RCX = result.Offset + utils.baseAddress;
                utils.DebugLog($"Found chatIconParam_RCX -> {chatIconParam_RCX:X8}");
            });

            for (int i = 0; i < chatIconLimitPatterns.Length; i++)
            {
                utils.IScanner.AddMainModuleScan(chatIconLimitPatterns[i], (result) =>  //Chat Icon Limit
                {
                    if (!result.Found)
                    {
                        utils.Log($"Could not find chatIconLimit[{i}]", Color.PaleVioletRed);
                        return;
                    }

                    chatIconLimit.Add(result.Offset + utils.baseAddress);
                    utils.DebugLog($"Found chatIconLimit[{i}] -> {result.Offset + utils.baseAddress:X8}");
                });
            }

            utils.IScanner.AddMainModuleScan("8B 05 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 48 8B CE", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find Global lang", Color.PaleVioletRed);
                    throw new Exception($"Could not find Global lang from signature \"8B 05 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 48 8B CE\"");
                }

                lang = utils.GetAddressFromGlobalRef(result.Offset + utils.baseAddress, 6);
                utils.DebugLog($"Found Global lang -> {lang:X8}");
            });

            utils.IScanner.AddMainModuleScan("0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ?? 48 03 C9 0F B7 84 ?? ?? ?? ?? ?? C3 48 63 C1 48 8D 0C ??", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find getChatNameId", Color.PaleVioletRed);
                    return;
                }

                long getChatNameId = result.Offset + utils.baseAddress;
                utils.DebugLog($"Found getChatNameId -> {getChatNameId:X8}");

                _getChatNameId = hooks.CreateHook<GetChatNameId>((a1) =>
                {
                    var newFile = utils.OpenFile(newNameFile[*(byte*)lang], 0);

                    var fileAddress = newFile->pointerToFile;

                    short ChatID = *(short*)(fileAddress + (a1 * 8));

                    IconColorHooks(hooks, utils, chatIconPreviewBgColor, chatIconBgColor);
                    IconParamHooks(hooks, utils, chatIconParam_RAX, chatIconParam_RCX, chatIconLimit);
                    return ChatID;
                }, getChatNameId).Activate();
            });

            utils.IScanner.AddMainModuleScan("48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ?? 48 C1 E0 04 48 03 C1 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8D 04 ??", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find getChatName", Color.PaleVioletRed);
                    return;
                }

                long getChatName = result.Offset + utils.baseAddress;
                utils.DebugLog($"Found getChatName -> {getChatName:X8}");

                _getChatName = hooks.CreateHook<GetChatName>((a1) =>
                {
                    var newFile = utils.OpenFile(newNameFile[*(byte*)lang], 0);

                    var fileAddress = newFile->pointerToFile;

                    char* result = (char*)(fileAddress + 2 + (a1 * 0x30));
                    return result;
                }, getChatName).Activate();
            });
        }

        private void IconColorHooks(IReloadedHooks hooks, Utils utils, long chatIconPreviewBgColor, long chatIconBgColor)
        {
            string newColorFile = @"font/chat/ChatBgColors.dat";
            var newFile = utils.OpenFile(newColorFile, 0);

            var fileAddress = newFile->pointerToFile;

            string[] newChatBgColorPtr = { $"use64", $"mov rdx, 0x{fileAddress:X8}" };

            _chatColorBgHook = hooks.CreateAsmHook(newChatBgColorPtr, chatIconPreviewBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
            _chatColorPrvwBgHook = hooks.CreateAsmHook(newChatBgColorPtr, chatIconBgColor, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
        }

        private void IconParamHooks(IReloadedHooks hooks, Utils utils, List<long> chatIconParam_RAX, long chatIconParam_RCX, List<long> chatIconLimit)
        {
            string newParamFile = @"font/chat/ChatIconParams.dat";
            var newFile = utils.OpenFile(newParamFile, 0);

            var fileBuffer = newFile->bufferSize;

            var fileAddress = newFile->pointerToFile;

            string[] newParamPointer_RAX = { $"use64", $"mov rax, 0x{fileAddress:X8}" };
            string[] newParamPointer_RCX = { $"use64", $"mov rcx, 0x{fileAddress:X8}" };

            foreach (var param in chatIconParam_RAX)
            {
                _chatParamHook_RAX = hooks.CreateAsmHook(newParamPointer_RAX, param, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
            }

            _chatParamHook_RCX = hooks.CreateAsmHook(newParamPointer_RCX, chatIconParam_RCX, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();

            //Add Variable limit for chat icon slots.

            var memory = Memory.Instance;

            memory.SafeWrite(chatIconLimit[0] + 3, (byte)(fileBuffer / 52));
            memory.SafeWrite(chatIconLimit[1] + 3, (byte)(fileBuffer / 52));
            memory.SafeWrite(chatIconLimit[2] + 4, (byte)(fileBuffer / 52));
        }
    }
}
