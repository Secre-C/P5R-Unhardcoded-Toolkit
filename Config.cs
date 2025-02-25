﻿using System.ComponentModel;
using Unhardcoded_P5R.Template.Configuration;

namespace Unhardcoded_P5R.Configuration
{
    public class Config : Configurable<Config>
    {
        /*
            User Properties:
                - Please put all of your configurable properties here.

            By default, configuration saves as "Config.json" in mod user config folder.    
            Need more config files/classes? See Configuration.cs

            Available Attributes:
            - Category
            - DisplayName
            - Description
            - DefaultValue

            // Technically Supported but not Useful
            - Browsable
            - Localizable

            The `DefaultValue` attribute is used as part of the `Reset` button in Reloaded-Launcher.
        */

        [DisplayName("Debug")]
        [Description("print stuff for debug purposes")]
        [DefaultValue(false)]
        public bool DebugBool { get; set; } = false;

        [DisplayName("Chat Module")]
        [Description("Enables unhardcoded chat module. ONLY DISABLE FOR TROUBLESHOOTING")]
        [DefaultValue(true)]
        public bool ChatHooks { get; set; } = true;

        [DisplayName("Lmap Module")]
        [Description("Enables unhardcoded lmap module. ONLY DISABLE FOR TROUBLESHOOTING")]
        [DefaultValue(true)]
        public bool LmapHooks { get; set; } = true;

        [DisplayName("Shop Module")]
        [Description("Enables unhardcoded shop module. ONLY DISABLE FOR TROUBLESHOOTING")]
        [DefaultValue(true)]
        public bool ShopHooks { get; set; } = true;

        [DisplayName("Select Cutin Module")]
        [Description("Remove early return when using ID 6 for the SelCutin override")]
        [DefaultValue(true)]
        public bool SelCutinHooks { get; set; } = true;

        [DisplayName("Item Icon Module")]
        [Description("Item Icon Moduler Placeholder description")]
        [DefaultValue(true)]
        public bool ItemIconHooks { get; set; } = true;

        [DisplayName("Field Model Num Module")]
        [Description("Unhardcodes the table that determines how many field models an overworld field will load in favor of incrementally checking if the models exist.")]
        [DefaultValue(true)]
        public bool FieldModelNumHooks { get; set; } = true;
    }

    /// <summary>
    /// Allows you to override certain aspects of the configuration creation process (e.g. create multiple configurations).
    /// Override elements in <see cref="ConfiguratorMixinBase"/> for finer control.
    /// </summary>
    public class ConfiguratorMixin : ConfiguratorMixinBase
    {
        // 
    }
}