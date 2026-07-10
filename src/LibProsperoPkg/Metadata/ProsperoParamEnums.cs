// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Value sets and key names for the sce_sys/param.json application-metadata document. The keys,
// the applicationDrmType tokens, the gameIntent intent tokens and the recognised language codes
// are the constrained vocabularies the document may use.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace LibProsperoPkg.Metadata;

/// <summary>The <c>applicationDrmType</c> token carried by a <c>param.json</c> document.</summary>
public enum ProsperoDrmType
{
    /// <summary>A paid package (<c>standard</c>).</summary>
    Standard,

    /// <summary>A package with no purchase requirement (<c>free</c>).</summary>
    Free,

    /// <summary>A free-to-play package with in-application purchases (<c>freemium</c>).</summary>
    Freemium,
}

/// <summary>The <c>intentType</c> token of a <c>gameIntent.permittedIntents</c> entry.</summary>
public enum ProsperoIntentType
{
    /// <summary>Launch an activity (<c>launchActivity</c>).</summary>
    LaunchActivity,

    /// <summary>Join a multiplayer session (<c>joinSession</c>).</summary>
    JoinSession,
}

/// <summary>Maps <see cref="ProsperoDrmType"/> onto its <c>param.json</c> token and back.</summary>
public static class ProsperoDrmTypes
{
    /// <summary>Token for <see cref="ProsperoDrmType.Standard"/>.</summary>
    public const string Standard = "standard";

    /// <summary>Token for <see cref="ProsperoDrmType.Free"/>.</summary>
    public const string Free = "free";

    /// <summary>Token for <see cref="ProsperoDrmType.Freemium"/>.</summary>
    public const string Freemium = "freemium";

    /// <summary>Returns the <c>param.json</c> token for <paramref name="type"/>.</summary>
    public static string ToToken(ProsperoDrmType type) => type switch
    {
        ProsperoDrmType.Standard => Standard,
        ProsperoDrmType.Free => Free,
        ProsperoDrmType.Freemium => Freemium,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    /// <summary>Parses a token into a <see cref="ProsperoDrmType"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="token"/> is not a known token.</exception>
    public static ProsperoDrmType Parse(string? token) => token switch
    {
        Standard => ProsperoDrmType.Standard,
        Free => ProsperoDrmType.Free,
        Freemium => ProsperoDrmType.Freemium,
        _ => throw new ArgumentException($"Unknown applicationDrmType token '{token}'.", nameof(token)),
    };

    /// <summary>Tries to parse a token into a <see cref="ProsperoDrmType"/>.</summary>
    public static bool TryParse(string? token, out ProsperoDrmType type)
    {
        switch (token)
        {
            case Standard: type = ProsperoDrmType.Standard; return true;
            case Free: type = ProsperoDrmType.Free; return true;
            case Freemium: type = ProsperoDrmType.Freemium; return true;
            default: type = default; return false;
        }
    }
}

/// <summary>Maps <see cref="ProsperoIntentType"/> onto its <c>param.json</c> token and back.</summary>
public static class ProsperoIntentTypes
{
    /// <summary>Token for <see cref="ProsperoIntentType.LaunchActivity"/>.</summary>
    public const string LaunchActivity = "launchActivity";

    /// <summary>Token for <see cref="ProsperoIntentType.JoinSession"/>.</summary>
    public const string JoinSession = "joinSession";

    /// <summary>Returns the <c>param.json</c> token for <paramref name="type"/>.</summary>
    public static string ToToken(ProsperoIntentType type) => type switch
    {
        ProsperoIntentType.LaunchActivity => LaunchActivity,
        ProsperoIntentType.JoinSession => JoinSession,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    /// <summary>Parses a token into a <see cref="ProsperoIntentType"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="token"/> is not a known token.</exception>
    public static ProsperoIntentType Parse(string? token) => token switch
    {
        LaunchActivity => ProsperoIntentType.LaunchActivity,
        JoinSession => ProsperoIntentType.JoinSession,
        _ => throw new ArgumentException($"Unknown intentType token '{token}'.", nameof(token)),
    };
}

/// <summary>The recognised <c>param.json</c> property names.</summary>
public static class ProsperoParamKeys
{
    /// <summary><c>addcont</c> object (holds <c>serviceIdForSharing</c>).</summary>
    public const string AddCont = "addcont";

    /// <summary><c>serviceIdForSharing</c> array inside <c>addcont</c>.</summary>
    public const string ServiceIdForSharing = "serviceIdForSharing";

    /// <summary><c>ageLevel</c> object (per-country integer levels plus <c>default</c>).</summary>
    public const string AgeLevel = "ageLevel";

    /// <summary><c>default</c> key inside <c>ageLevel</c>.</summary>
    public const string Default = "default";

    /// <summary><c>applicationCategoryType</c> integer.</summary>
    public const string ApplicationCategoryType = "applicationCategoryType";

    /// <summary><c>applicationDrmType</c> token.</summary>
    public const string ApplicationDrmType = "applicationDrmType";

    /// <summary><c>attribute</c> integer.</summary>
    public const string Attribute = "attribute";

    /// <summary><c>attribute2</c> integer.</summary>
    public const string Attribute2 = "attribute2";

    /// <summary><c>attribute3</c> integer.</summary>
    public const string Attribute3 = "attribute3";

    /// <summary><c>conceptId</c> string.</summary>
    public const string ConceptId = "conceptId";

    /// <summary><c>contentBadgeType</c> integer.</summary>
    public const string ContentBadgeType = "contentBadgeType";

    /// <summary><c>contentId</c> string.</summary>
    public const string ContentId = "contentId";

    /// <summary><c>contentVersion</c> string.</summary>
    public const string ContentVersion = "contentVersion";

    /// <summary><c>deeplinkUri</c> string.</summary>
    public const string DeeplinkUri = "deeplinkUri";

    /// <summary><c>downloadDataSize</c> integer.</summary>
    public const string DownloadDataSize = "downloadDataSize";

    /// <summary><c>gameIntent</c> object (holds <c>permittedIntents</c>).</summary>
    public const string GameIntent = "gameIntent";

    /// <summary><c>permittedIntents</c> array inside <c>gameIntent</c>.</summary>
    public const string PermittedIntents = "permittedIntents";

    /// <summary><c>intentType</c> token inside a <c>permittedIntents</c> entry.</summary>
    public const string IntentType = "intentType";

    /// <summary><c>localizedParameters</c> object (holds <c>defaultLanguage</c> and per-language entries).</summary>
    public const string LocalizedParameters = "localizedParameters";

    /// <summary><c>defaultLanguage</c> key inside <c>localizedParameters</c>.</summary>
    public const string DefaultLanguage = "defaultLanguage";

    /// <summary><c>titleName</c> key inside a per-language <c>localizedParameters</c> entry.</summary>
    public const string TitleName = "titleName";

    /// <summary><c>masterVersion</c> string.</summary>
    public const string MasterVersion = "masterVersion";

    /// <summary><c>originContentVersion</c> string.</summary>
    public const string OriginContentVersion = "originContentVersion";

    /// <summary>Creation metadata object.</summary>
    public const string PubTools = "pubtools";

    /// <summary><c>creationDate</c> key inside creation metadata.</summary>
    public const string CreationDate = "creationDate";

    /// <summary><c>submission</c> key inside creation metadata.</summary>
    public const string Submission = "submission";

    /// <summary><c>toolVersion</c> key inside creation metadata.</summary>
    public const string ToolVersion = "toolVersion";

    /// <summary><c>requiredSystemSoftwareVersion</c> string (hex-encoded).</summary>
    public const string RequiredSystemSoftwareVersion = "requiredSystemSoftwareVersion";

    /// <summary><c>sdkVersion</c> string (hex-encoded).</summary>
    public const string SdkVersion = "sdkVersion";

    /// <summary><c>targetContentVersion</c> string.</summary>
    public const string TargetContentVersion = "targetContentVersion";

    /// <summary><c>titleId</c> string.</summary>
    public const string TitleId = "titleId";

    /// <summary><c>userDefinedParam1</c> integer.</summary>
    public const string UserDefinedParam1 = "userDefinedParam1";

    /// <summary><c>userDefinedParam2</c> integer.</summary>
    public const string UserDefinedParam2 = "userDefinedParam2";

    /// <summary><c>userDefinedParam3</c> integer.</summary>
    public const string UserDefinedParam3 = "userDefinedParam3";

    /// <summary><c>userDefinedParam4</c> integer.</summary>
    public const string UserDefinedParam4 = "userDefinedParam4";

    /// <summary><c>versionFileUri</c> string.</summary>
    public const string VersionFileUri = "versionFileUri";
}

/// <summary>The language codes a <c>localizedParameters</c> block may key on.</summary>
public static class ProsperoParamLanguages
{
    private static readonly string[] CodesArray =
    [
        "ja-JP", "en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "nl-NL", "pt-PT", "ru-RU", "ko-KR",
        "zh-Hant", "zh-Hans", "fi-FI", "sv-SE", "da-DK", "no-NO", "pl-PL", "pt-BR", "es-419", "tr-TR",
        "en-GB", "ar-AE", "fr-CA", "cs-CZ", "hu-HU", "el-GR", "ro-RO", "th-TH", "vi-VN", "id-ID",
    ];

    private static readonly HashSet<string> CodeSet = new(CodesArray, StringComparer.Ordinal);

    /// <summary>All recognised language codes.</summary>
    public static ReadOnlyCollection<string> Codes { get; } = new(CodesArray);

    /// <summary>Returns true when <paramref name="code"/> is a recognised language code.</summary>
    public static bool IsKnown(string? code) => code is not null && CodeSet.Contains(code);
}

/// <summary>The country codes an <c>ageLevel</c> block may key on (plus the <c>default</c> level).</summary>
public static class ProsperoParamCountries
{
    private static readonly string[] CodesArray =
    [
        "AE", "AR", "AT", "AU", "BE", "BG", "BH", "BO", "BR", "CA", "CH", "CL", "CN", "CO", "CR",
        "CY", "CZ", "DE", "DK", "EC", "ES", "FI", "FR", "GB", "GR", "GT", "HK", "HN", "HR", "HU",
        "ID", "IE", "IL", "IN", "IS", "IT", "JP", "KR", "KW", "LB", "LU", "MT", "MX", "MY", "NI",
        "NL", "NO", "NZ", "OM", "PA", "PE", "PL", "PT", "PY", "QA", "RO", "RU", "SA", "SE", "SG",
        "SI", "SK", "SV", "TH", "TR", "TW", "UA", "US", "UY", "ZA",
    ];

    private static readonly HashSet<string> CodeSet = new(CodesArray, StringComparer.Ordinal);

    /// <summary>All recognised country codes (the <c>default</c> key is separate).</summary>
    public static ReadOnlyCollection<string> Codes { get; } = new(CodesArray);

    /// <summary>Returns true when <paramref name="code"/> is a recognised country code.</summary>
    public static bool IsKnown(string? code) => code is not null && CodeSet.Contains(code);
}
