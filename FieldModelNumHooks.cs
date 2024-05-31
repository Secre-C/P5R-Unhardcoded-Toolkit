using Reloaded.Hooks.Definitions;
using System.Runtime.InteropServices;

namespace Unhardcoded_P5R;
internal unsafe class FieldModelNumHooks
{
    private IAsmHook _getFieldModelNumHook;
    private IReverseWrapper _reverseWrapper;
    private Utils _utils;
    internal FieldModelNumHooks(IReloadedHooks hooks, Utils utils)
    {
        _utils = utils;
        utils.SigScan("B8 01 00 00 00 E9 ?? ?? ?? ?? 48 8D 0C", "FieldModelNum", (functionAddress) =>
        {
            string[] asm =
            {
                    "use64",
                    "sub rsp, 0x20",
                    Utils.PushCallerRegisters,
                    "MOV RCX, R14",
                    hooks.Utilities.GetAbsoluteCallMnemonics(FindFieldModelFileNum, out var reverseWrapper),
                    Utils.PopCallerRegisters,
                    "add rsp, 0x20"
            };

            _reverseWrapper = reverseWrapper;
            _getFieldModelNumHook = hooks.CreateAsmHook(asm, functionAddress, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.ExecuteFirst).Activate();
        });
    }

    private sbyte FindFieldModelFileNum(FieldInfo* fieldInfo)
    {
        sbyte models = 0;
        uint fldMajor = (fieldInfo->fieldIds >> 20) & 0xffff;
        short fldMinor = *(short*)fieldInfo;

        _utils.DebugLog($"FieldIds 0x{*(long*)fieldInfo:X8}, f{fldMajor:D3}_{fldMinor:D3}");

        while (true)
        {
            var fieldModelPath = @"model/field_tex/" + $"f{fldMajor:D3}_{fldMinor:D3}_{models}.GFS";

            var file = _utils.fileExists(fieldModelPath);
            if (!file)
                break;

            _utils.DebugLog($"Found {fieldModelPath}");
            models++;
        }

        _utils.DebugLog($"Found {models} field models");
        models = (sbyte)(models != 0 ? models : 1);
        fieldInfo->fieldModelCount = (uint)models;
        return models;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FieldInfo
    {
        [FieldOffset(0)]
        public uint fieldIds;

        [FieldOffset(0x370)]
        public uint fieldModelCount;
    }
}
