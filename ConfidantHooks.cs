using Reloaded.Hooks.Definitions;
using System.Drawing;

namespace Unhardcoded_P5R
{
    internal unsafe class ConfidantHooks
    {
        private delegate long Cmm_Friend();
        private delegate short FUN_140d8e660(short a1);
        private delegate void FUN_140d8e2b0(ulong a1);
        private delegate void FUN_140d8e090(short a1);

        private delegate void CmmCheckFriend(short a1);

        private delegate short CmmGetFriendId(short a1);

        IHook<Cmm_Friend> _cmm_Friend;
        IHook<CmmCheckFriend> _cmmCheckFriend;
        IHook<CmmGetFriendId> _cmmGetFriendId;
        internal ConfidantHooks(IReloadedHooks hooks, Utils utils)
        {
            utils.DebugLog("Loading Confidant Module", Color.PaleGreen);

            long cmm_FriendAdr = 0;
            long FUN_140d8e660Adr = 0;
            long FUN_140d8e2b0Adr = 0;
            long FUN_140d8e090Adr = 0;

            long cmmCheckFriendAdr = 0;

            long DAT_142a63ee0 = 0;
            long ConfidantSavePtr = 0;

            utils.SigScan("48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 56 48 83 EC 20 33 ED 4C 8D 35 ?? ?? ?? ?? 0F B7 DD", "FUN_140d8e660Adr", (result) =>
            {
                FUN_140d8e660Adr = result;
            });

            utils.SigScan("48 89 5C 24 ?? 48 89 7C 24 ?? 0F B7 C1", "FUN_140d8e2b0Adr", (result) =>
            {
                FUN_140d8e2b0Adr = result;
            });

            utils.SigScan("48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B 2D ?? ?? ?? ?? 33 FF", "FUN_140d8e090Adr", (result) =>
            {
                FUN_140d8e090Adr = result;
            });

            utils.SigScan("48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 ?? 48 85 C9 74 ?? 0F B7 01 EB ?? 8B C7 0F B7 C0", "DAT_142a63ee0", (result) =>
            {
                DAT_142a63ee0 = utils.GetAddressFromGlobalRef(result, 7, "DAT_142a63ee0");
            });

            utils.SigScan("48 8B 1D ?? ?? ?? ?? 48 83 C3 02 66 39 53 ??", "ConfidantSavePtr", (result) =>
            {
                ConfidantSavePtr = utils.GetAddressFromGlobalRef(result, 7, "ConfidantSavePtr");
            });

            utils.SigScan("40 57 48 83 EC 20 33 C9 E8 ?? ?? ?? ?? 8B C8", "cmm_FriendAdr", (result) => //Flowscript Function CMM_FRIEND
            {
                cmm_FriendAdr = result;

                long cmmFriendTableAdr = 0;
                long cmmFriendTableBuffer = 0;

                _cmm_Friend = hooks.CreateHook<Cmm_Friend>(() =>
                {
                    short sVar1;
                    short sVar2;
                    ulong uVar3;
                    long lVar4;
                    int iVar5;

                    var _FUN_140d8e660 = hooks.CreateWrapper<FUN_140d8e660>(FUN_140d8e660Adr, out IntPtr wrapperAddress);
                    var _FUN_140d8e2b0 = hooks.CreateWrapper<FUN_140d8e2b0>(FUN_140d8e2b0Adr, out wrapperAddress);
                    var _FUN_140d8e090 = hooks.CreateWrapper<FUN_140d8e090>(FUN_140d8e090Adr, out wrapperAddress);

                    uVar3 = (ulong)utils.flowscriptGetIntArg(0);
                    sVar1 = _FUN_140d8e660((short)uVar3);
                    iVar5 = 0;
                    if (sVar1 == 0)
                    {
                        if ((*(long*)DAT_142a63ee0 == 0) || (*(short**)(DAT_142a63ee0 + 0x48) == (short*)0x0))
                        {
                            sVar1 = 0;
                        }
                        else
                        {
                            sVar1 = **(short**)(DAT_142a63ee0 + 0x48);
                        }
                    }
                    sVar1 = _FUN_140d8e660(sVar1);
                    if (sVar1 != 0)
                    {
                        lVar4 = *(long*)ConfidantSavePtr + 2;
                        while (*(short*)(lVar4 + 4) != sVar1)
                        {
                            lVar4 += 0x10;
                            iVar5++;
                            if (0x17 < iVar5)
                            {
                                return 1;
                            }
                        }

                        string cmmFriendFile = @"init/cmm/cmmFriendTable.dat";

                        var newFile = utils.OpenFile(cmmFriendFile, 0);

                        cmmFriendTableAdr = newFile->pointerToFile;
                        cmmFriendTableBuffer = newFile->bufferSize;

                        sVar2 = 0;

                        for (int i = 0; i < cmmFriendTableBuffer / 4; i++)
                        {
                            short FriendTableOgId = *(short*)(cmmFriendTableAdr + (i * 4));
                            short FriendTableNewId = *(short*)(cmmFriendTableAdr + (i * 4) + 2);
                            if (FriendTableOgId == sVar1)
                            {
                                sVar2 = FriendTableNewId;
                            }
                        }

                        if (sVar2 == 0)
                            return 1;

                        if (sVar2 != sVar1)
                        {
                            *(short*)(lVar4 + 4) = sVar2;
                            _FUN_140d8e2b0((ulong)sVar1);
                            _FUN_140d8e090((short)*(ushort*)(lVar4 + 4));
                        }
                    }
                    return 1;
                }, cmm_FriendAdr).Activate();
            });

            utils.SigScan("0F B7 C1 83 C0 FD 83 F8 1F", "cmmCheckFriendAdr", (result) => // 0x140d8d930
            {
                cmmCheckFriendAdr = result;

                long cmmFriendTableAdr = 0;
                long cmmFriendTableBuffer = 0;

                _cmmCheckFriend = hooks.CreateHook<CmmCheckFriend>((a1) =>
                {
                    var _FUN_140d8e2b0 = hooks.CreateWrapper<FUN_140d8e2b0>(FUN_140d8e2b0Adr, out IntPtr wrapperAddress);

                    int iVar1;
                    long* puVar2;

                    if (cmmFriendTableAdr == 0)
                    {
                        string cmmFriendFile = @"init/cmm/cmmFriendTable.dat";

                        var newFile = utils.OpenFile(cmmFriendFile, 0);

                        cmmFriendTableAdr = newFile->pointerToFile;
                        cmmFriendTableBuffer = newFile->bufferSize;
                    }

                    for (int i = 0; i < cmmFriendTableBuffer / 4; i++)
                    {
                        short FriendTableOgId = *(short*)(cmmFriendTableAdr + (i * 4));
                        short FriendTableNewId = *(short*)(cmmFriendTableAdr + (i * 4) + 2);
                        ulong altId = (ulong)FriendTableNewId;

                        if (FriendTableOgId == a1 || FriendTableNewId == a1)
                        {
                            if (FriendTableNewId == a1)
                                altId = (ulong)FriendTableOgId;

                            puVar2 = *(long**)ConfidantSavePtr;
                            iVar1 = 0;
                            do
                            {
                                if (*(short*)((long)puVar2 + 6) == (short)altId)
                                {
                                    *puVar2 = 0;
                                    puVar2[1] = 0;
                                    _FUN_140d8e2b0(altId);
                                    return;
                                }
                                puVar2 += 2;
                                iVar1++;
                            } while (iVar1 < 0x18);
                            return;
                        }
                    }

                }, cmmCheckFriendAdr).Activate();
            });

            utils.SigScan("0F B7 C1 83 C0 FD 83 F8 22", "cmmGetFriendId", (result) => // 0x140d8de80 breaks kawakami????
            {
                long cmmFriendFileAdr = 0;
                long cmmGetFriendId = result;
                long bufferSize = 0;

                _cmmGetFriendId = hooks.CreateHook<CmmGetFriendId>((a1) =>
                {
                    if (cmmFriendFileAdr == 0)
                    {
                        string cmmFriendFile = @"init/cmm/cmmFriendTable.dat";

                        var newFile = utils.OpenFile(cmmFriendFile, 0);

                        cmmFriendFileAdr = newFile->pointerToFile;
                        bufferSize = newFile->bufferSize;
                    }

                    utils.Log($"a1 -> {a1}");
                    for (int i = 0; i < bufferSize / 4; i++)
                    {
                        short FriendTableOgId = *(short*)(cmmFriendFileAdr + (i * 4));
                        short FriendTableNewId = *(short*)(cmmFriendFileAdr + (i * 4) + 2);

                        short altId = FriendTableNewId;

                        if (FriendTableOgId == a1 || FriendTableNewId == a1)
                        {
                            if (FriendTableNewId == a1)
                                altId = FriendTableOgId;

                            utils.Log($"alt -> {altId}");
                            return altId;
                        }
                    }
                    return a1;
                }, cmmGetFriendId);
            });
        }
    }
}
