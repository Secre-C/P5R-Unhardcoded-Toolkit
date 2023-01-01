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
    internal unsafe class ShopHooks
    {
        private delegate long LoadShopBanner(long *a1, long a2);
        private delegate void PlaceShopBanner(long a1, long a2);

        private IHook<LoadShopBanner> _loadShopBanner;
        private IHook<PlaceShopBanner> _placeShopBanner;

        private IAsmHook _shop2BannerStringPtr;

        internal ShopHooks(IReloadedHooks hooks, IModLoader modLoader, Utils utils)
        {
            utils.DebugLog("Loading Shop Module", Color.PaleGreen);

            long loadShopBannerAdr = 0;

            long fclPublicShopDataTablePtr = 0;

            long Shop2BannerStringPtrInstr = 0;
            long Shop2BannerStringPtr = 0;

            long placeShopBannerAdr = 0;

            utils.IScanner.AddMainModuleScan("48 8B 05 ?? ?? ?? ?? 48 8B 74 24 ?? 49 89 BE ?? ?? ?? ??", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find Global fclPublicShopDataTablePtr", Color.PaleVioletRed);
                    throw new Exception($"Could not find Global fclPublicShopDataTablePtr from signature \"48 8B 05 ?? ?? ?? ?? 48 8B 74 24 ?? 49 89 BE ?? ?? ?? ??\"");
                }

                fclPublicShopDataTablePtr = utils.GetAddressFromGlobalRef(result.Offset + utils.baseAddress, 7);
                utils.DebugLog($"Found Global fclPublicShopDataTablePtr -> {fclPublicShopDataTablePtr:X8}");
            });

            utils.IScanner.AddMainModuleScan("48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? 66 83 FA 03", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find Global Shop2BannerStringPtrInstr", Color.PaleVioletRed);
                    throw new Exception($"Could not find Global Shop2BannerStringPtr from signature \"48 8B 05 ?? ?? ?? ?? 48 8B 74 24 ?? 49 89 BE ?? ?? ?? ??\"");
                }

                Shop2BannerStringPtrInstr = result.Offset + utils.baseAddress;
                Shop2BannerStringPtr = utils.GetAddressFromGlobalRef(Shop2BannerStringPtrInstr, 7);
                utils.DebugLog($"Found Global Shop2BannerStringPtrInstr -> {Shop2BannerStringPtrInstr:X8}");
                utils.DebugLog($"Found Global Shop2BannerStringPtr -> {Shop2BannerStringPtr:X8}");
            });

            utils.IScanner.AddMainModuleScan("48 89 5C 24 ?? 48 89 7C 24 ?? 41 56 48 83 EC 60", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find LoadShopBanner Function", Color.PaleVioletRed);
                    return;
                }

                loadShopBannerAdr = utils.baseAddress + result.Offset;
                utils.DebugLog($"Found LoadShopBanner -> {loadShopBannerAdr:X8}");
                _loadShopBanner = hooks.CreateHook<LoadShopBanner>((a1, a2) =>
                {
                    long ddsStringAdr;

                    long lVar3 = fclPublicShopDataTablePtr;

                    short ShopId = *(short*)(a2 + 0xC6);
                    short BannerId = *(short*)(*(long*)lVar3 + 0x30 + (ShopId * 4));
                    utils.DebugLog($"Banner -> {BannerId}");

                    if (BannerId > 41 && BannerId < 99)
                    {
                        ddsStringAdr = (long)utils.Sprintf($"facility/fcl_ps_title/h_name_{BannerId:D2}.dds");
                        string[] newBannerAsmHook = { $"use64", $"mov rcx, {ddsStringAdr}" };
                        _shop2BannerStringPtr = hooks.CreateAsmHook(newBannerAsmHook, Shop2BannerStringPtrInstr, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
                        *(short*)(*(long*)lVar3 + 0x30 + (ShopId * 4)) = 2; //sets the BannerId to 2 to prevent crashes
                    }
                    else if (BannerId == 2)
                    {
                        string[] newBannerAsmHook = { $"use64", $"mov rcx, {Shop2BannerStringPtr}" };
                        _shop2BannerStringPtr = hooks.CreateAsmHook(newBannerAsmHook, Shop2BannerStringPtrInstr, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
                    }

                    long result = _loadShopBanner.OriginalFunction(a1, a2);
                    *(short*)(*(long*)lVar3 + 0x30 + (ShopId * 4)) = BannerId;
                    return result;

                }, loadShopBannerAdr).Activate();
            });

            utils.IScanner.AddMainModuleScan("4C 8B DC 49 89 53 ?? 55 41 54 41 55 48 81 EC E0 00 00 00", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not find PlaceShopBanner Function", Color.PaleVioletRed);
                }

                placeShopBannerAdr = result.Offset + utils.baseAddress;
                utils.DebugLog($"Found PlaceShopBanner -> {placeShopBannerAdr:X8}");

                _placeShopBanner = hooks.CreateHook<PlaceShopBanner>((a1, a2) =>
                {
                    long lVar3 = fclPublicShopDataTablePtr;

                    short ShopId = *(short*)(a2 + 0xC6);
                    short BannerId = *(short*)(*(long*)lVar3 + 0x30 + (ShopId * 4));

                    *(short*)(*(long*)lVar3 + 0x30 + (ShopId * 4)) = 2; //sets the BannerId to 2 temporarily to place the shop Banner correctly

                    _placeShopBanner.OriginalFunction(a1, a2);

                    *(short*)(*(long*)lVar3 + 0x30 + (ShopId * 4)) = BannerId; //sets the BannerId back to what it was before

                }, placeShopBannerAdr).Activate();
            });
        }
    }
}
