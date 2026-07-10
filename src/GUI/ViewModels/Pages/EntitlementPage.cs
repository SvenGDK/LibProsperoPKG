using LibProsperoPkg.Gui.Services;
using LibProsperoPkg.Gui.ViewModels.Fields;
using LibProsperoPkg.License;
using System;
using System.IO;

namespace LibProsperoPkg.Gui.ViewModels.Pages;

public sealed class EntitlementPage : ToolPageViewModel
{
    private readonly TextFieldViewModel _keyHex;
    private readonly TextFieldViewModel _passcode;

    private readonly TextFieldViewModel _debugContentId;
    private readonly TextFieldViewModel _debugPasscode;
    private readonly TextFieldViewModel _debugSeed;
    private readonly TextFieldViewModel _debugRecordOutput;

    public EntitlementPage(IAppHost host)
        : base(host, "Entitlement and debug license", "Validate an entitlement key, resolve the key mode, and derive debug-license material.")
    {
        _keyHex = Text("Entitlement key (hex)", watermark: "32 hex characters");
        _passcode = Text("Passcode", watermark: "Optional; used for mode resolution");
        Run("Validate key", ValidateKey, primary: true);
        Run("Resolve mode", ResolveMode);

        _debugContentId = Text("Content id");
        _debugPasscode = Text("Passcode (debug)", watermark: "32 characters (blank uses the all-zero default)");
        _debugSeed = Text("Key-set seed (hex)", watermark: "Optional; derives a full key set when set");
        _debugRecordOutput = Text("Structural record output", pick: PickKind.SaveFile, suggestedName: "license.rif");
        Run("Derive image key", DeriveImageKey);
        Run("Derive key set", DeriveKeySet);
        Run("Write structural record", WriteStructuralRecord);
    }

    private void ValidateKey(Action<string> log)
    {
        var key = ProsperoEntitlementKey.ParseHex(_keyHex.Value.Trim());
        bool ok = key.Validate(out string? error);
        log("Valid: " + (ok ? "yes" : "no"));
        if (!ok && error is not null)
            log("Reason: " + error);
    }

    private void ResolveMode(Action<string> log)
    {
        string passcode = _passcode.Value.Trim();
        string keyHex = _keyHex.Value.Trim();
        ProsperoEntitlementKey? key = keyHex.Length > 0 ? ProsperoEntitlementKey.ParseHex(keyHex) : null;
        bool ok = ProsperoEntitlementKey.ResolveMode(passcode.Length > 0 ? passcode : null, key, out ProsperoKeyMode mode, out string? error);
        log(ok ? "Mode: " + mode : "Cannot resolve: " + error);
    }

    private ProsperoDebugLicense BuildDebug()
        => ProsperoDebugLicense.Create(_debugContentId.Value.Trim(), ParseHelpers.Passcode(_debugPasscode.Value));

    private void DeriveImageKey(Action<string> log)
        => log("Image key: " + Convert.ToHexString(BuildDebug().DeriveEkpfs()).ToLowerInvariant());

    private void DeriveKeySet(Action<string> log)
    {
        string seedHex = _debugSeed.Value.Trim();
        if (seedHex.Length == 0)
        {
            log("Provide a key-set seed to derive a full key set.");
            return;
        }

        ProsperoDebugKeySet set = BuildDebug().DeriveKeySet(Convert.FromHexString(seedHex));
        log("Image key: " + Convert.ToHexString(set.Ekpfs).ToLowerInvariant());
        log("Tweak key: " + Convert.ToHexString(set.TweakKey).ToLowerInvariant());
        log("Data key: " + Convert.ToHexString(set.DataKey).ToLowerInvariant());
        log("Sign key: " + Convert.ToHexString(set.SignKey).ToLowerInvariant());
    }

    private void WriteStructuralRecord(Action<string> log)
    {
        ProsperoDebugLicense license = BuildDebug();
        if (!license.Validate(out string? error))
        {
            log("Invalid: " + error);
            return;
        }

        byte[] bytes = license.ToStructuralRif().ToBytes();
        File.WriteAllBytes(_debugRecordOutput.Value.Trim(), bytes);
        log($"Output: {_debugRecordOutput.Value.Trim()} ({bytes.Length} bytes)");
    }
}
