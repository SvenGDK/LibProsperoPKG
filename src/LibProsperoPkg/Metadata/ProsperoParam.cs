// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Reader/writer model for the sce_sys/param.json application-metadata document. The document is
// kept as a live JsonObject so every property - recognised or not - round-trips exactly, while
// typed accessors cover the well-known keys, nested metadata blocks, and constrained value sets.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibProsperoPkg.Metadata;

/// <summary>
/// The <c>sce_sys/param.json</c> application-metadata document. Backed by a mutable
/// <see cref="JsonObject"/> (<see cref="Root"/>) so arbitrary keys are preserved on load/save,
/// with typed accessors for the recognised keys and helpers for the nested blocks.
/// </summary>
public sealed class ProsperoParam
{
    /// <summary>The number of <c>serviceIdForSharing</c> slots a default <c>addcont</c> block carries.</summary>
    public const int ServiceIdForSharingSlots = 7;

    /// <summary>The width in characters of an empty <c>serviceIdForSharing</c> slot.</summary>
    public const int ServiceIdForSharingWidth = 19;

    /// <summary>Creates an empty document.</summary>
    public ProsperoParam() => Root = new JsonObject();

    /// <summary>Wraps an existing JSON object as a document. The object is used directly, not copied.</summary>
    public ProsperoParam(JsonObject root) => Root = root ?? throw new ArgumentNullException(nameof(root));

    /// <summary>The live document object. Mutations are reflected by <see cref="ToJson"/> / <see cref="Save"/>.</summary>
    public JsonObject Root { get; }

    // ---- Generic access ----

    /// <summary>Gets or sets a raw node by key. Setting <see langword="null"/> removes the key.</summary>
    public JsonNode? this[string key]
    {
        get
        {
            ArgumentException.ThrowIfNullOrEmpty(key);
            return Root.TryGetPropertyValue(key, out JsonNode? node) ? node : null;
        }
        set
        {
            ArgumentException.ThrowIfNullOrEmpty(key);
            if (value is null) Root.Remove(key);
            else Root[key] = value;
        }
    }

    /// <summary>Returns true when the document has a property named <paramref name="key"/>.</summary>
    public bool ContainsKey(string key) => Root.ContainsKey(key);

    /// <summary>Removes the property named <paramref name="key"/>; returns true when it existed.</summary>
    public bool Remove(string key) => Root.Remove(key);

    // ---- Scalar keys ----

    /// <summary><c>applicationCategoryType</c> integer.</summary>
    public int? ApplicationCategoryType
    {
        get => GetInt(ProsperoParamKeys.ApplicationCategoryType);
        set => SetInt(ProsperoParamKeys.ApplicationCategoryType, value);
    }

    /// <summary>The raw <c>applicationDrmType</c> token.</summary>
    public string? ApplicationDrmType
    {
        get => GetString(ProsperoParamKeys.ApplicationDrmType);
        set => SetString(ProsperoParamKeys.ApplicationDrmType, value);
    }

    /// <summary>The <c>applicationDrmType</c> as a typed value, or <see langword="null"/> when absent/unrecognised.</summary>
    public ProsperoDrmType? DrmType
    {
        get => ProsperoDrmTypes.TryParse(ApplicationDrmType, out ProsperoDrmType t) ? t : null;
        set => ApplicationDrmType = value is null ? null : ProsperoDrmTypes.ToToken(value.Value);
    }

    /// <summary><c>attribute</c> integer.</summary>
    public int? Attribute
    {
        get => GetInt(ProsperoParamKeys.Attribute);
        set => SetInt(ProsperoParamKeys.Attribute, value);
    }

    /// <summary><c>attribute2</c> integer.</summary>
    public int? Attribute2
    {
        get => GetInt(ProsperoParamKeys.Attribute2);
        set => SetInt(ProsperoParamKeys.Attribute2, value);
    }

    /// <summary><c>attribute3</c> integer.</summary>
    public int? Attribute3
    {
        get => GetInt(ProsperoParamKeys.Attribute3);
        set => SetInt(ProsperoParamKeys.Attribute3, value);
    }

    /// <summary><c>conceptId</c> string.</summary>
    public string? ConceptId
    {
        get => GetString(ProsperoParamKeys.ConceptId);
        set => SetString(ProsperoParamKeys.ConceptId, value);
    }

    /// <summary><c>contentBadgeType</c> integer.</summary>
    public int? ContentBadgeType
    {
        get => GetInt(ProsperoParamKeys.ContentBadgeType);
        set => SetInt(ProsperoParamKeys.ContentBadgeType, value);
    }

    /// <summary><c>contentId</c> string.</summary>
    public string? ContentId
    {
        get => GetString(ProsperoParamKeys.ContentId);
        set => SetString(ProsperoParamKeys.ContentId, value);
    }

    /// <summary><c>contentVersion</c> string.</summary>
    public string? ContentVersion
    {
        get => GetString(ProsperoParamKeys.ContentVersion);
        set => SetString(ProsperoParamKeys.ContentVersion, value);
    }

    /// <summary><c>deeplinkUri</c> string.</summary>
    public string? DeeplinkUri
    {
        get => GetString(ProsperoParamKeys.DeeplinkUri);
        set => SetString(ProsperoParamKeys.DeeplinkUri, value);
    }

    /// <summary><c>downloadDataSize</c> integer (in bytes).</summary>
    public long? DownloadDataSize
    {
        get => GetLong(ProsperoParamKeys.DownloadDataSize);
        set => SetLong(ProsperoParamKeys.DownloadDataSize, value);
    }

    /// <summary><c>masterVersion</c> string.</summary>
    public string? MasterVersion
    {
        get => GetString(ProsperoParamKeys.MasterVersion);
        set => SetString(ProsperoParamKeys.MasterVersion, value);
    }

    /// <summary><c>originContentVersion</c> string.</summary>
    public string? OriginContentVersion
    {
        get => GetString(ProsperoParamKeys.OriginContentVersion);
        set => SetString(ProsperoParamKeys.OriginContentVersion, value);
    }

    /// <summary><c>requiredSystemSoftwareVersion</c> string (hex-encoded firmware value).</summary>
    public string? RequiredSystemSoftwareVersion
    {
        get => GetString(ProsperoParamKeys.RequiredSystemSoftwareVersion);
        set => SetString(ProsperoParamKeys.RequiredSystemSoftwareVersion, value);
    }

    /// <summary><c>sdkVersion</c> string (hex-encoded).</summary>
    public string? SdkVersion
    {
        get => GetString(ProsperoParamKeys.SdkVersion);
        set => SetString(ProsperoParamKeys.SdkVersion, value);
    }

    /// <summary><c>targetContentVersion</c> string.</summary>
    public string? TargetContentVersion
    {
        get => GetString(ProsperoParamKeys.TargetContentVersion);
        set => SetString(ProsperoParamKeys.TargetContentVersion, value);
    }

    /// <summary><c>titleId</c> string.</summary>
    public string? TitleId
    {
        get => GetString(ProsperoParamKeys.TitleId);
        set => SetString(ProsperoParamKeys.TitleId, value);
    }

    /// <summary><c>versionFileUri</c> string.</summary>
    public string? VersionFileUri
    {
        get => GetString(ProsperoParamKeys.VersionFileUri);
        set => SetString(ProsperoParamKeys.VersionFileUri, value);
    }

    /// <summary>Gets or sets one of the four <c>userDefinedParamN</c> integers (<paramref name="index"/> 1..4).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not 1..4.</exception>
    public int? GetUserDefinedParam(int index) => GetInt(UserDefinedKey(index));

    /// <summary>Sets one of the four <c>userDefinedParamN</c> integers (<paramref name="index"/> 1..4).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is not 1..4.</exception>
    public void SetUserDefinedParam(int index, int? value) => SetInt(UserDefinedKey(index), value);

    private static string UserDefinedKey(int index) => index switch
    {
        1 => ProsperoParamKeys.UserDefinedParam1,
        2 => ProsperoParamKeys.UserDefinedParam2,
        3 => ProsperoParamKeys.UserDefinedParam3,
        4 => ProsperoParamKeys.UserDefinedParam4,
        _ => throw new ArgumentOutOfRangeException(nameof(index), index, "userDefinedParam index must be 1..4."),
    };

    // ---- localizedParameters ----

    /// <summary>The <c>localizedParameters.defaultLanguage</c> value.</summary>
    public string? DefaultLanguage
    {
        get => (Root[ProsperoParamKeys.LocalizedParameters] as JsonObject) is { } lp
            ? AsString(lp[ProsperoParamKeys.DefaultLanguage])
            : null;
        set
        {
            JsonObject lp = GetOrCreateObject(ProsperoParamKeys.LocalizedParameters);
            if (value is null) lp.Remove(ProsperoParamKeys.DefaultLanguage);
            else lp[ProsperoParamKeys.DefaultLanguage] = value;
        }
    }

    /// <summary>The language codes that carry a localized entry (excludes <c>defaultLanguage</c>).</summary>
    public IReadOnlyList<string> Languages
    {
        get
        {
            if (Root[ProsperoParamKeys.LocalizedParameters] is not JsonObject lp)
                return Array.Empty<string>();
            return lp
                .Where(kvp => kvp.Key != ProsperoParamKeys.DefaultLanguage && kvp.Value is JsonObject)
                .Select(kvp => kvp.Key)
                .ToArray();
        }
    }

    /// <summary>Returns the <c>titleName</c> for a language, or <see langword="null"/> when absent.</summary>
    public string? GetTitleName(string language)
    {
        ArgumentException.ThrowIfNullOrEmpty(language);
        return (Root[ProsperoParamKeys.LocalizedParameters] as JsonObject)?[language] is JsonObject entry
            ? AsString(entry[ProsperoParamKeys.TitleName])
            : null;
    }

    /// <summary>Sets the <c>titleName</c> for a language, creating the language entry when needed.</summary>
    public void SetTitleName(string language, string titleName)
    {
        ArgumentException.ThrowIfNullOrEmpty(language);
        ArgumentNullException.ThrowIfNull(titleName);
        JsonObject lp = GetOrCreateObject(ProsperoParamKeys.LocalizedParameters);
        if (lp[language] is not JsonObject entry)
        {
            entry = new JsonObject();
            lp[language] = entry;
        }
        entry[ProsperoParamKeys.TitleName] = titleName;
    }

    /// <summary>Removes a language entry; returns true when it existed.</summary>
    public bool RemoveLanguage(string language)
    {
        ArgumentException.ThrowIfNullOrEmpty(language);
        return (Root[ProsperoParamKeys.LocalizedParameters] as JsonObject)?.Remove(language) ?? false;
    }

    // ---- ageLevel ----

    /// <summary>Returns the age level for a country code (or the <c>default</c> key), or <see langword="null"/>.</summary>
    public int? GetAgeLevel(string country)
    {
        ArgumentException.ThrowIfNullOrEmpty(country);
        return (Root[ProsperoParamKeys.AgeLevel] as JsonObject) is { } al ? AsInt(al[country]) : null;
    }

    /// <summary>Sets the age level for a country code (or the <c>default</c> key).</summary>
    public void SetAgeLevel(string country, int level)
    {
        ArgumentException.ThrowIfNullOrEmpty(country);
        GetOrCreateObject(ProsperoParamKeys.AgeLevel)[country] = level;
    }

    /// <summary>The <c>ageLevel.default</c> value.</summary>
    public int? DefaultAgeLevel
    {
        get => GetAgeLevel(ProsperoParamKeys.Default);
        set
        {
            if (value is null) (Root[ProsperoParamKeys.AgeLevel] as JsonObject)?.Remove(ProsperoParamKeys.Default);
            else SetAgeLevel(ProsperoParamKeys.Default, value.Value);
        }
    }

    /// <summary>
    /// Writes <paramref name="level"/> for every recognised country code and the <c>default</c> key,
    /// replacing any existing <c>ageLevel</c> block.
    /// </summary>
    public void SetAllAgeLevels(int level)
    {
        var al = new JsonObject();
        foreach (string country in ProsperoParamCountries.Codes)
            al[country] = level;
        al[ProsperoParamKeys.Default] = level;
        Root[ProsperoParamKeys.AgeLevel] = al;
    }

    // ---- gameIntent.permittedIntents ----

    /// <summary>The <c>gameIntent.permittedIntents</c> tokens, in order.</summary>
    public IReadOnlyList<string> PermittedIntentTokens
    {
        get
        {
            if ((Root[ProsperoParamKeys.GameIntent] as JsonObject)?[ProsperoParamKeys.PermittedIntents] is not JsonArray arr)
                return Array.Empty<string>();
            var list = new List<string>(arr.Count);
            foreach (JsonNode? item in arr)
            {
                string? token = (item as JsonObject) is { } o ? AsString(o[ProsperoParamKeys.IntentType]) : null;
                if (token is not null) list.Add(token);
            }
            return list;
        }
    }

    /// <summary>Appends a permitted intent, creating the <c>gameIntent.permittedIntents</c> block when needed.</summary>
    public void AddPermittedIntent(ProsperoIntentType intent)
    {
        JsonObject gi = GetOrCreateObject(ProsperoParamKeys.GameIntent);
        if (gi[ProsperoParamKeys.PermittedIntents] is not JsonArray arr)
        {
            arr = new JsonArray();
            gi[ProsperoParamKeys.PermittedIntents] = arr;
        }
        arr.Add(new JsonObject { [ProsperoParamKeys.IntentType] = ProsperoIntentTypes.ToToken(intent) });
    }

    /// <summary>Replaces the <c>gameIntent.permittedIntents</c> block with the given intents (in order).</summary>
    public void SetPermittedIntents(params ProsperoIntentType[] intents)
    {
        ArgumentNullException.ThrowIfNull(intents);
        var arr = new JsonArray();
        foreach (ProsperoIntentType intent in intents)
            arr.Add(new JsonObject { [ProsperoParamKeys.IntentType] = ProsperoIntentTypes.ToToken(intent) });
        GetOrCreateObject(ProsperoParamKeys.GameIntent)[ProsperoParamKeys.PermittedIntents] = arr;
    }

    // ---- addcont.serviceIdForSharing ----

    /// <summary>The <c>addcont.serviceIdForSharing</c> entries, in order.</summary>
    public IReadOnlyList<string> ServiceIdForSharing
    {
        get
        {
            if ((Root[ProsperoParamKeys.AddCont] as JsonObject)?[ProsperoParamKeys.ServiceIdForSharing] is not JsonArray arr)
                return Array.Empty<string>();
            return arr.Select(n => AsString(n) ?? "").ToArray();
        }
    }

    /// <summary>Replaces the <c>addcont.serviceIdForSharing</c> array with the given entries.</summary>
    public void SetServiceIdForSharing(IEnumerable<string> serviceIds)
    {
        ArgumentNullException.ThrowIfNull(serviceIds);
        var arr = new JsonArray();
        foreach (string id in serviceIds)
            arr.Add(id);
        GetOrCreateObject(ProsperoParamKeys.AddCont)[ProsperoParamKeys.ServiceIdForSharing] = arr;
    }

    /// <summary>Writes a default <c>addcont</c> block of blank sharing slots.</summary>
    public void SetDefaultServiceIdForSharing() =>
        SetServiceIdForSharing(Enumerable.Repeat(new string(' ', ServiceIdForSharingWidth), ServiceIdForSharingSlots));

    // ---- Creation metadata ----

    /// <summary>The creation-date metadata value.</summary>
    public string? PubToolsCreationDate
    {
        get => (Root[ProsperoParamKeys.PubTools] as JsonObject) is { } p ? AsString(p[ProsperoParamKeys.CreationDate]) : null;
        set => SetPubToolsField(ProsperoParamKeys.CreationDate, value is null ? null : JsonValue.Create(value));
    }

    /// <summary>The tool-version metadata value.</summary>
    public string? PubToolsToolVersion
    {
        get => (Root[ProsperoParamKeys.PubTools] as JsonObject) is { } p ? AsString(p[ProsperoParamKeys.ToolVersion]) : null;
        set => SetPubToolsField(ProsperoParamKeys.ToolVersion, value is null ? null : JsonValue.Create(value));
    }

    /// <summary>The submission metadata flag.</summary>
    public bool? PubToolsSubmission
    {
        get => (Root[ProsperoParamKeys.PubTools] as JsonObject) is { } p ? AsBool(p[ProsperoParamKeys.Submission]) : null;
        set => SetPubToolsField(ProsperoParamKeys.Submission, value is null ? null : JsonValue.Create(value.Value));
    }

    private void SetPubToolsField(string key, JsonNode? value)
    {
        if (value is null)
        {
            (Root[ProsperoParamKeys.PubTools] as JsonObject)?.Remove(key);
            return;
        }
        GetOrCreateObject(ProsperoParamKeys.PubTools)[key] = value;
    }

    // ---- Serialization ----

    /// <summary>
    /// Serializes the document. When <paramref name="sorted"/> is <see langword="true"/> the keys of
    /// every object are written in ordinal order (the canonical layout); non-ASCII characters are
    /// written literally.
    /// </summary>
    public string ToJson(bool sorted = true, bool indented = true)
    {
        JsonNode node = sorted ? SortedClone(Root)! : Root;
        var options = new JsonSerializerOptions
        {
            WriteIndented = indented,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return node.ToJsonString(options);
    }

    /// <summary>Writes the document to <paramref name="path"/> as UTF-8 without a byte-order mark.</summary>
    public void Save(string path, bool sorted = true, bool indented = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        File.WriteAllText(path, ToJson(sorted, indented), new UTF8Encoding(false));
    }

    /// <summary>Returns a deep, independent copy of the document.</summary>
    public ProsperoParam Clone() => new((JsonObject)Root.DeepClone());

    /// <summary>Parses a document from JSON text.</summary>
    /// <exception cref="InvalidDataException">The root is not a JSON object.</exception>
    public static ProsperoParam Parse(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        JsonNode? node = JsonNode.Parse(json);
        return node is JsonObject obj
            ? new ProsperoParam(obj)
            : throw new InvalidDataException("param.json root is not a JSON object.");
    }

    /// <summary>Reads and parses a <c>param.json</c> file.</summary>
    public static ProsperoParam Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return Parse(File.ReadAllText(path));
    }

    /// <summary>
    /// Builds a minimal but valid document: the content id, title id, category type, DRM token, a
    /// default-language title name, the zeroed attribute/user-defined integers and a zero
    /// <c>downloadDataSize</c>.
    /// </summary>
    public static ProsperoParam CreateDefault(
        string contentId,
        string titleId,
        string titleName,
        ProsperoDrmType drmType = ProsperoDrmType.Standard,
        int applicationCategoryType = 0,
        string defaultLanguage = "en-US")
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ArgumentNullException.ThrowIfNull(titleName);
        ArgumentException.ThrowIfNullOrEmpty(defaultLanguage);

        var param = new ProsperoParam
        {
            ApplicationCategoryType = applicationCategoryType,
            ApplicationDrmType = ProsperoDrmTypes.ToToken(drmType),
            ContentId = contentId,
            TitleId = titleId,
            MasterVersion = "01.00",
            ContentVersion = "01.000.000",
            Attribute = 0,
            Attribute2 = 0,
            Attribute3 = 0,
            DownloadDataSize = 0,
        };
        param.DefaultLanguage = defaultLanguage;
        param.SetTitleName(defaultLanguage, titleName);
        for (int i = 1; i <= 4; i++)
            param.SetUserDefinedParam(i, 0);
        return param;
    }

    // ---- Internals ----

    private JsonObject GetOrCreateObject(string key)
    {
        if (Root[key] is JsonObject existing)
            return existing;
        var created = new JsonObject();
        Root[key] = created;
        return created;
    }

    private int? GetInt(string key) => AsInt(Root[key]);

    private long? GetLong(string key) => AsLong(Root[key]);

    private string? GetString(string key) => AsString(Root[key]);

    private void SetInt(string key, int? value)
    {
        if (value is null) Root.Remove(key);
        else Root[key] = value.Value;
    }

    private void SetLong(string key, long? value)
    {
        if (value is null) Root.Remove(key);
        else Root[key] = value.Value;
    }

    private void SetString(string key, string? value)
    {
        if (value is null) Root.Remove(key);
        else Root[key] = value;
    }

    private static int? AsInt(JsonNode? node)
    {
        long? l = AsLong(node);
        return l is >= int.MinValue and <= int.MaxValue ? (int)l.Value : null;
    }

    private static long? AsLong(JsonNode? node)
    {
        if (node is not JsonValue value) return null;
        if (value.TryGetValue(out long l)) return l;
        if (value.TryGetValue(out int i)) return i;
        if (value.TryGetValue(out double d) && d == Math.Floor(d) && !double.IsInfinity(d)) return (long)d;
        return null;
    }

    private static string? AsString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out string? s) ? s : null;

    private static bool? AsBool(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out bool b) ? b : null;

    private static JsonNode? SortedClone(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                var sorted = new JsonObject();
                foreach (KeyValuePair<string, JsonNode?> kvp in obj.OrderBy(k => k.Key, StringComparer.Ordinal))
                    sorted[kvp.Key] = SortedClone(kvp.Value);
                return sorted;
            case JsonArray arr:
                var array = new JsonArray();
                foreach (JsonNode? item in arr)
                    array.Add(SortedClone(item));
                return array;
            case JsonValue value:
                return value.DeepClone();
            default:
                return null;
        }
    }
}
