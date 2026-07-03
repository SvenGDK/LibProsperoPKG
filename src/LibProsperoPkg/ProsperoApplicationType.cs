// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PS5 application-type model. A PS5 package records its application type through the
// sce_sys/param.json applicationDrmType bucket (and, for some titles, contentBadgeType). This type
// maps a human-facing application type name ("Paid Standalone Full App", "Upgradable App",
// "Demo App" and "Freemium App") onto the param.json fields the builder writes.
//
// Integer codes: 0 = not specified, 1 = paid standalone, 2 = upgradable, 3 = demo, 4 = freemium.

#nullable enable
using System;

namespace LibProsperoPkg;

/// <summary>
/// The PS5 application type. The numeric values are the codes carried by the gp5 <c>app_type</c>
/// attribute and the param.sfo <c>APP_TYPE</c> key.
/// </summary>
public enum ProsperoApplicationType
{
    /// <summary>No specific application type (code <c>0</c>, "Not specified"). Treated as a free app.</summary>
    NotSpecified = 0,

    /// <summary>A full, paid standalone application (code <c>1</c>, "Paid Standalone Full App").</summary>
    PaidStandaloneFullApp = 1,

    /// <summary>An upgradable application (code <c>2</c>, "Upgradable App"), e.g. disc-to-digital / PS3 key disc.</summary>
    UpgradableApp = 2,

    /// <summary>A demo application (code <c>3</c>, "Demo App").</summary>
    DemoApp = 3,

    /// <summary>A free-to-play application with in-app purchases (code <c>4</c>, "Freemium App").</summary>
    FreemiumApp = 4,
}

/// <summary>
/// Maps <see cref="ProsperoApplicationType"/> onto the PS5 <c>sce_sys/param.json</c> fields the
/// builder emits. The monetization/DRM bucket is written as <c>applicationDrmType</c>, and the
/// <c>pfsimage.xml</c> <c>&lt;application-type&gt;</c> mirrors it.
/// </summary>
public static class ProsperoApplicationTypes
{
    /// <summary>The <c>param.json</c> <c>applicationDrmType</c> token for a debug/homebrew "free" package.</summary>
    public const string DrmFree = "free";

    /// <summary>The <c>param.json</c> <c>applicationDrmType</c> token for a paid package (the default).</summary>
    public const string DrmStandard = "standard";

    /// <summary>The <c>param.json</c> <c>applicationDrmType</c> token for a free-to-play package.</summary>
    public const string DrmFreemium = "freemium";

    /// <summary>
    /// The <c>applicationDrmType</c> bucket a given application type maps to. Paid and upgradable
    /// apps are <c>standard</c>; freemium is <c>freemium</c>; demo and unspecified default to
    /// <c>free</c>.
    /// </summary>
    public static string ApplicationDrmType(ProsperoApplicationType type) => type switch
    {
        ProsperoApplicationType.PaidStandaloneFullApp => DrmStandard,
        ProsperoApplicationType.UpgradableApp => DrmStandard,
        ProsperoApplicationType.FreemiumApp => DrmFreemium,
        ProsperoApplicationType.DemoApp => DrmFree,
        _ => DrmFree,
    };

    /// <summary>The display name for an application type.</summary>
    public static string DisplayName(ProsperoApplicationType type) => type switch
    {
        ProsperoApplicationType.PaidStandaloneFullApp => "Paid Standalone Full App",
        ProsperoApplicationType.UpgradableApp => "Upgradable App",
        ProsperoApplicationType.DemoApp => "Demo App",
        ProsperoApplicationType.FreemiumApp => "Freemium App",
        _ => "Not specified",
    };

    /// <summary>
    /// Parses an application-type display name (case-insensitive) into the enum. Unknown or empty
    /// input yields <see cref="ProsperoApplicationType.NotSpecified"/>.
    /// </summary>
    public static ProsperoApplicationType Parse(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return ProsperoApplicationType.NotSpecified;

        return name.Trim() switch
        {
            var s when s.Equals("Paid Standalone Full App", StringComparison.OrdinalIgnoreCase) => ProsperoApplicationType.PaidStandaloneFullApp,
            var s when s.Equals("Upgradable App", StringComparison.OrdinalIgnoreCase) => ProsperoApplicationType.UpgradableApp,
            var s when s.Equals("Demo App", StringComparison.OrdinalIgnoreCase) => ProsperoApplicationType.DemoApp,
            var s when s.Equals("Freemium App", StringComparison.OrdinalIgnoreCase) => ProsperoApplicationType.FreemiumApp,
            _ => ProsperoApplicationType.NotSpecified,
        };
    }
}
