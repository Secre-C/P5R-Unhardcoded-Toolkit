﻿using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;
using Unhardcoded_P5R.Configuration;
using Unhardcoded_P5R.Template;

namespace Unhardcoded_P5R
{
    /// <summary>
    /// Your mod logic goes here.
    /// </summary>
    public class Mod : ModBase // <= Do not Remove.
    {
        /// <summary>
        /// Provides access to the mod loader API.
        /// </summary>
        private readonly IModLoader _modLoader;

        /// <summary>
        /// Provides access to the Reloaded.Hooks API.
        /// </summary>
        /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
        private readonly IReloadedHooks? _hooks;

        /// <summary>
        /// Provides access to the Reloaded logger.
        /// </summary>
        private readonly ILogger _logger;

        /// <summary>
        /// Entry point into the mod, instance that created this class.
        /// </summary>
        private readonly IMod _owner;

        /// <summary>
        /// Provides access to this mod's configuration.
        /// </summary>
        private Config _configuration;

        /// <summary>
        /// The configuration of the currently executing mod.
        /// </summary>
        private readonly IModConfig _modConfig;

        private Utils _utils = null!;
        private ChatHooks _chatHooks = null!;
        private LmapHooks _lmapHooks = null!;
        private ShopHooks _shopHooks = null!;
        private SelCutinHooks _selCutinHooks = null!;
        private FieldModelNumHooks _fieldModelNumHooks = null!;
        public Mod(ModContext context)
        {
            //Debugger.Launch();
            _modLoader = context.ModLoader;
            _hooks = context.Hooks;
            _logger = context.Logger;
            _owner = context.Owner;
            _configuration = context.Configuration;
            _modConfig = context.ModConfig;


            // For more information about this template, please see
            // https://reloaded-project.github.io/Reloaded-II/ModTemplate/

            // If you want to implement e.g. unload support in your mod,
            // and some other neat features, override the methods in ModBase.

            // TODO: Implement some mod logic
            _utils = new Utils(_hooks, _logger, _modLoader, _configuration);

            if (_configuration.ChatHooks)
                _chatHooks = new ChatHooks(_modLoader, _hooks, _utils);

            if (_configuration.LmapHooks)
                _lmapHooks = new LmapHooks(_hooks, _utils);

            if (_configuration.ShopHooks)
                _shopHooks = new ShopHooks(_hooks, _utils);

            if (_configuration.SelCutinHooks)
                _selCutinHooks = new SelCutinHooks(_utils);

            if (_configuration.FieldModelNumHooks)
                _fieldModelNumHooks = new FieldModelNumHooks(_hooks, _utils);

            _modLoader.ModLoading += OnModLoading;
            _modLoader.OnModLoaderInitialized += OnModLoaderInitialized;
        }

        private void OnModLoading(IModV1 mod, IModConfigV1 modConfig)
        {
            if (_configuration.ChatHooks)
            {
                var chatIconParamFilePath = Path.Join(_modLoader.GetDirectoryForModId(modConfig.ModId), "UnhardcodedP5R", "ChatIconParams.json");
                _chatHooks.ReadChatIconParamFile(chatIconParamFilePath);
            }

            if (_configuration.LmapHooks)
            {
                var lmapSpriteParamFilePath = Path.Join(_modLoader.GetDirectoryForModId(modConfig.ModId), "UnhardcodedP5R", "LmapSpriteParams.json");
                _lmapHooks.ReadLmapSpriteParamFile(lmapSpriteParamFilePath);

                var lmapSilhouetteFieldsFilePath = Path.Join(_modLoader.GetDirectoryForModId(modConfig.ModId), "UnhardcodedP5R", "LmapSilhouetteFields.json");
                _lmapHooks.ReadLmapSilhouetteFieldFile(lmapSilhouetteFieldsFilePath);
            }

        }

        private void OnModLoaderInitialized()
        {
            if (_configuration.LmapHooks)
                _lmapHooks.WriteNewLmapParamTable();
        }

        #region Standard Overrides
        public override void ConfigurationUpdated(Config configuration)
        {
            // Apply settings from configuration.
            // ... your code here.
            _configuration = configuration;
            _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
        }
        #endregion

        #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public Mod() { }
#pragma warning restore CS8618
        #endregion
    }
}