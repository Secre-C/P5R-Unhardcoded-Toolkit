using Reloaded.Hooks.Definitions;
using System.Drawing;
using System.Runtime.InteropServices;

namespace Unhardcoded_P5R
{
    internal unsafe class ShopHooks
    {
        private delegate long LoadShopBanner(long* a1, ShopInfo* shopInfo);
        private delegate void PlaceShopBanner(long a1, ShopInfo* shopInfo);

        private delegate long d_GetDDSStringAdr();
        private d_GetDDSStringAdr _getDDSStringAdr;

        private IHook<LoadShopBanner> _loadShopBanner;
        private IHook<PlaceShopBanner> _placeShopBanner;

        private IAsmHook _shop2BannerStringPtr;
        private IReverseWrapper _reverseWrapper;

        int currentDisplayingShopBanner = 0;
        long Shop2BannerStringPtr = 0;
        nint shopTablePointers = 0;

        internal ShopHooks(IReloadedHooks hooks, Utils utils)
        {
            utils.DebugLog("Loading Shop Module", Color.PaleGreen);

            utils.SigScan("48 8B 05 ?? ?? ?? ?? 48 8B 74 24 ?? 49 89 BE ?? ?? ?? ??", "fclPublicShopDataTablePtr", (result) =>
                shopTablePointers = utils.GetAddressFromGlobalRef(result, 7, "shopDataTable"));

            utils.SigScan("48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? 66 83 FA 03", "Shop2BannerStringPtrInstr", (Shop2BannerStringPtrInstr) => // 0x14100a474
            {
                Shop2BannerStringPtr = utils.GetAddressFromGlobalRef(Shop2BannerStringPtrInstr, 7, "Shop2BannerStringPtr");

                _getDDSStringAdr = GetDDSStringAdr;
                string[] asm =
                {
                    "use64",
                    Utils.PushCallerRegisters,
                    hooks.Utilities.GetAbsoluteCallMnemonics(_getDDSStringAdr, out var reverseWrapper),
                    Utils.PopCallerRegisters,
                    "mov rcx, rax"
                };

                _reverseWrapper = reverseWrapper;
                _shop2BannerStringPtr = hooks.CreateAsmHook(asm, Shop2BannerStringPtrInstr, Reloaded.Hooks.Definitions.Enums.AsmHookBehaviour.DoNotExecuteOriginal).Activate();
            });

            utils.SigScan("48 89 5C 24 ?? 41 56 48 83 EC 20 48 89 6C 24 ?? 4C 8B F1", "LoadShopBanner", (loadShopBannerAdr) =>
            {
                _loadShopBanner = hooks.CreateHook<LoadShopBanner>((a1, shopInfo) =>
                {
                    var shopDataTable = GetShopDataTable();
                    short shopId = shopInfo->shopId;
                    short bannerId = shopDataTable[shopId].bannerId;
                    utils.DebugLog($"Banner -> {bannerId}");
                    currentDisplayingShopBanner = bannerId;

                    if (useCustomShopBanner())
                        shopDataTable[shopId].bannerId = 2;

                    long result = _loadShopBanner.OriginalFunction(a1, shopInfo);
                    shopDataTable[shopId].bannerId = bannerId;
                    return result;

                }, loadShopBannerAdr).Activate();
            });

            utils.SigScan("4C 8B DC 41 54 41 55 41 57 48 81 EC 20 01 00 00", "PlaceShopBanner", (placeShopBannerAdr) =>
            {
                _placeShopBanner = hooks.CreateHook<PlaceShopBanner>((a1, shopInfo) =>
                {
                    var shopDataTable = GetShopDataTable();
                    short shopId = shopInfo->shopId;
                    short bannerId = shopDataTable[shopId].bannerId;

                    if (useCustomShopBanner())
                        shopDataTable[shopId].bannerId = 2; // sets the BannerId to 2 temporarily to place the shop Banner correctly

                    _placeShopBanner.OriginalFunction(a1, shopInfo);

                    shopDataTable[shopId].bannerId = bannerId; // revert bannerId

                }, placeShopBannerAdr).Activate();
            });
        }

        private bool useCustomShopBanner()
            => currentDisplayingShopBanner > 41 && currentDisplayingShopBanner < 99;
        private long GetDDSStringAdr()
        {
            if (useCustomShopBanner())
                return Marshal.StringToHGlobalAnsi($"facility/fcl_ps_title/h_name_{currentDisplayingShopBanner:D2}.dds");
            else
                return Shop2BannerStringPtr;
        }

        private ShopDataTable* GetShopDataTable() => (ShopDataTable*)(*(long*)shopTablePointers + 0x30);

        [StructLayout(LayoutKind.Explicit)]
        private struct ShopInfo
        {
            [FieldOffset(0xc6)]
            internal short shopId;
        }

        [StructLayout(LayoutKind.Sequential, Size = 0x4)]
        private struct ShopDataTable
        {
            internal short bannerId;
            internal bool hideNameTag;
            internal byte mode;
        }
    }
}
