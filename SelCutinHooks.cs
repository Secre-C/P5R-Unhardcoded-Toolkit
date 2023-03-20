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
    public class SelCutinHooks
    {
        public SelCutinHooks(IReloadedHooks hooks, IModLoader modLoader, Utils utils)
        {
            utils.IScanner.AddMainModuleScan("80 7B ?? 06 0F B7 03", (result) =>
            {
                if (!result.Found)
                {
                    utils.Log("Could not Find Sel Cutin override check");
                    return;
                }

                long selCutinAddress = utils.baseAddress + result.Offset;
                utils.DebugLog($"Found Sel Cutin override check at 0x{selCutinAddress:X8}");

                var memory = Memory.Instance;

                memory.SafeWrite(selCutinAddress + 3, (byte)0xff);
            });
        }
    }
}
