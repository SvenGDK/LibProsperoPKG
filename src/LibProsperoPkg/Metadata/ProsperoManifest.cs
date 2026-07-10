// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Reader/writer model for the manifest.json document that ships alongside framework-based system
// applications. The document is kept as a live JsonObject so every property round-trips exactly,
// with typed accessors for the recognised keys and the nested applicationData block.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibProsperoPkg.Metadata;

/// <summary>The recognised <c>manifest.json</c> property names.</summary>
public static class ProsperoManifestKeys
{
    /// <summary><c>applicationName</c> string.</summary>
    public const string ApplicationName = "applicationName";

    /// <summary><c>applicationVersion</c> string.</summary>
    public const string ApplicationVersion = "applicationVersion";

    /// <summary><c>commitHash</c> string.</summary>
    public const string CommitHash = "commitHash";

    /// <summary><c>bootAnimation</c> string.</summary>
    public const string BootAnimation = "bootAnimation";

    /// <summary><c>titleId</c> string.</summary>
    public const string TitleId = "titleId";

    /// <summary><c>repositoryUrl</c> string.</summary>
    public const string RepositoryUrl = "repositoryUrl";

    /// <summary><c>reactNativePlaystationVersion</c> string.</summary>
    public const string ReactNativePlaystationVersion = "reactNativePlaystationVersion";

    /// <summary><c>applicationData</c> object.</summary>
    public const string ApplicationData = "applicationData";

    /// <summary><c>branchType</c> key inside <c>applicationData</c>.</summary>
    public const string BranchType = "branchType";

    /// <summary><c>twinTurbo</c> flag.</summary>
    public const string TwinTurbo = "twinTurbo";

    /// <summary><c>enableAccessibility</c> string array.</summary>
    public const string EnableAccessibility = "enableAccessibility";

    /// <summary><c>enableHttpCache</c> flag.</summary>
    public const string EnableHttpCache = "enableHttpCache";
}

/// <summary>
/// The <c>manifest.json</c> document. Backed by a mutable <see cref="JsonObject"/>
/// (<see cref="Root"/>) so arbitrary keys are preserved on load/save, with typed accessors for the
/// recognised keys and the nested <c>applicationData</c> block. Property order is preserved on
/// round-trip; created documents use the canonical field order.
/// </summary>
public sealed class ProsperoManifest
{
    /// <summary>The field order used by <see cref="Create"/> and the canonical writer.</summary>
    private static readonly string[] CanonicalOrder =
    [
        ProsperoManifestKeys.ApplicationName,
        ProsperoManifestKeys.ApplicationVersion,
        ProsperoManifestKeys.CommitHash,
        ProsperoManifestKeys.BootAnimation,
        ProsperoManifestKeys.TitleId,
        ProsperoManifestKeys.RepositoryUrl,
        ProsperoManifestKeys.ReactNativePlaystationVersion,
        ProsperoManifestKeys.EnableAccessibility,
        ProsperoManifestKeys.EnableHttpCache,
        ProsperoManifestKeys.ApplicationData,
        ProsperoManifestKeys.TwinTurbo,
    ];

    /// <summary>Creates an empty document.</summary>
    public ProsperoManifest() => Root = new JsonObject();

    /// <summary>Wraps an existing JSON object as a document. The object is used directly, not copied.</summary>
    public ProsperoManifest(JsonObject root) => Root = root ?? throw new ArgumentNullException(nameof(root));

    /// <summary>The live document object. Mutations are reflected by <see cref="ToJson"/> / <see cref="Save"/>.</summary>
    public JsonObject Root { get; }

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

    /// <summary><c>applicationName</c> string.</summary>
    public string? ApplicationName
    {
        get => GetString(ProsperoManifestKeys.ApplicationName);
        set => SetString(ProsperoManifestKeys.ApplicationName, value);
    }

    /// <summary><c>applicationVersion</c> string.</summary>
    public string? ApplicationVersion
    {
        get => GetString(ProsperoManifestKeys.ApplicationVersion);
        set => SetString(ProsperoManifestKeys.ApplicationVersion, value);
    }

    /// <summary><c>commitHash</c> string.</summary>
    public string? CommitHash
    {
        get => GetString(ProsperoManifestKeys.CommitHash);
        set => SetString(ProsperoManifestKeys.CommitHash, value);
    }

    /// <summary><c>bootAnimation</c> string.</summary>
    public string? BootAnimation
    {
        get => GetString(ProsperoManifestKeys.BootAnimation);
        set => SetString(ProsperoManifestKeys.BootAnimation, value);
    }

    /// <summary><c>titleId</c> string.</summary>
    public string? TitleId
    {
        get => GetString(ProsperoManifestKeys.TitleId);
        set => SetString(ProsperoManifestKeys.TitleId, value);
    }

    /// <summary><c>repositoryUrl</c> string.</summary>
    public string? RepositoryUrl
    {
        get => GetString(ProsperoManifestKeys.RepositoryUrl);
        set => SetString(ProsperoManifestKeys.RepositoryUrl, value);
    }

    /// <summary><c>reactNativePlaystationVersion</c> string.</summary>
    public string? ReactNativePlaystationVersion
    {
        get => GetString(ProsperoManifestKeys.ReactNativePlaystationVersion);
        set => SetString(ProsperoManifestKeys.ReactNativePlaystationVersion, value);
    }

    /// <summary><c>twinTurbo</c> flag.</summary>
    public bool? TwinTurbo
    {
        get => AsBool(Root[ProsperoManifestKeys.TwinTurbo]);
        set
        {
            if (value is null) Root.Remove(ProsperoManifestKeys.TwinTurbo);
            else Root[ProsperoManifestKeys.TwinTurbo] = value.Value;
        }
    }

    /// <summary><c>enableHttpCache</c> flag.</summary>
    public bool? EnableHttpCache
    {
        get => AsBool(Root[ProsperoManifestKeys.EnableHttpCache]);
        set
        {
            if (value is null) Root.Remove(ProsperoManifestKeys.EnableHttpCache);
            else Root[ProsperoManifestKeys.EnableHttpCache] = value.Value;
        }
    }

    /// <summary>The <c>enableAccessibility</c> entries, in order.</summary>
    public IReadOnlyList<string> EnableAccessibility
    {
        get => Root[ProsperoManifestKeys.EnableAccessibility] is JsonArray arr
            ? arr.Select(n => AsString(n) ?? "").ToArray()
            : Array.Empty<string>();
    }

    /// <summary>Replaces the <c>enableAccessibility</c> array with the given entries.</summary>
    public void SetEnableAccessibility(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var arr = new JsonArray();
        foreach (string value in values)
            arr.Add(value);
        Root[ProsperoManifestKeys.EnableAccessibility] = arr;
    }

    /// <summary>The <c>applicationData.branchType</c> value.</summary>
    public string? BranchType
    {
        get => (Root[ProsperoManifestKeys.ApplicationData] as JsonObject) is { } data
            ? AsString(data[ProsperoManifestKeys.BranchType])
            : null;
        set
        {
            if (value is null)
            {
                (Root[ProsperoManifestKeys.ApplicationData] as JsonObject)?.Remove(ProsperoManifestKeys.BranchType);
                return;
            }
            GetOrCreateObject(ProsperoManifestKeys.ApplicationData)[ProsperoManifestKeys.BranchType] = value;
        }
    }

    /// <summary>
    /// Serializes the document. When <paramref name="canonical"/> is <see langword="true"/> the
    /// recognised keys are written in the canonical field order (unrecognised keys follow, in their
    /// current order); non-ASCII characters are written literally.
    /// </summary>
    public string ToJson(bool canonical = false, bool indented = true, int indentSize = 4)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(indentSize);
        JsonNode node = canonical ? OrderedClone(Root) : Root;
        var options = new JsonSerializerOptions
        {
            WriteIndented = indented,
            IndentSize = indentSize,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return node.ToJsonString(options);
    }

    /// <summary>Writes the document to <paramref name="path"/> as UTF-8 without a byte-order mark.</summary>
    public void Save(string path, bool canonical = false, bool indented = true, int indentSize = 4)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        File.WriteAllText(path, ToJson(canonical, indented, indentSize), new UTF8Encoding(false));
    }

    /// <summary>Returns a deep, independent copy of the document.</summary>
    public ProsperoManifest Clone() => new((JsonObject)Root.DeepClone());

    /// <summary>Parses a document from JSON text.</summary>
    /// <exception cref="InvalidDataException">The root is not a JSON object.</exception>
    public static ProsperoManifest Parse(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        JsonNode? node = JsonNode.Parse(json);
        return node is JsonObject obj
            ? new ProsperoManifest(obj)
            : throw new InvalidDataException("manifest.json root is not a JSON object.");
    }

    /// <summary>Reads and parses a <c>manifest.json</c> file.</summary>
    public static ProsperoManifest Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return Parse(File.ReadAllText(path));
    }

    /// <summary>
    /// Builds a document with the required fields in canonical order: the application name and
    /// version, the title id, the framework version, an <c>applicationData.branchType</c> and the
    /// <c>twinTurbo</c> flag.
    /// </summary>
    public static ProsperoManifest Create(
        string applicationName,
        string applicationVersion,
        string titleId,
        string reactNativePlaystationVersion,
        string branchType = "release",
        bool twinTurbo = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(applicationName);
        ArgumentException.ThrowIfNullOrEmpty(applicationVersion);
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ArgumentException.ThrowIfNullOrEmpty(reactNativePlaystationVersion);
        ArgumentException.ThrowIfNullOrEmpty(branchType);

        return new ProsperoManifest
        {
            ApplicationName = applicationName,
            ApplicationVersion = applicationVersion,
            TitleId = titleId,
            ReactNativePlaystationVersion = reactNativePlaystationVersion,
            BranchType = branchType,
            TwinTurbo = twinTurbo,
        };
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

    private string? GetString(string key) => AsString(Root[key]);

    private void SetString(string key, string? value)
    {
        if (value is null) Root.Remove(key);
        else Root[key] = value;
    }

    private static string? AsString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out string? s) ? s : null;

    private static bool? AsBool(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out bool b) ? b : null;

    private JsonObject OrderedClone(JsonObject source)
    {
        var ordered = new JsonObject();
        foreach (string key in CanonicalOrder)
        {
            if (source.TryGetPropertyValue(key, out JsonNode? value))
                ordered[key] = value?.DeepClone();
        }
        foreach (KeyValuePair<string, JsonNode?> kvp in source)
        {
            if (!ordered.ContainsKey(kvp.Key))
                ordered[kvp.Key] = kvp.Value?.DeepClone();
        }
        return ordered;
    }
}
