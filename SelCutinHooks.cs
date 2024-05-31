using Reloaded.Memory.Sources;

namespace Unhardcoded_P5R
{
    public class SelCutinHooks
    {
        public SelCutinHooks(Utils utils)
        {
            utils.SigScan("80 7B ?? 06 0F B7 03", "SelCutin", (selCutinAddress) =>
            {
                var memory = Memory.Instance;
                memory.SafeWrite(selCutinAddress + 3, (byte)0xff);
            });
        }
    }
}
