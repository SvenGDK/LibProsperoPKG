// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// Model for a multi-content license file: one or more 0x400-byte RIF records concatenated in a
// single "license/rif". A single-title disc carries one record; a multi-application disc carries
// one record per sub-title (e.g. a three-title compilation is a 0xC00-byte file of three records).
//
// The set mirrors the fields the verify path reports over a license file: the record count
// ("Number of Contents in RIF file" / n_rif), the per-record service label (ServiceID), the
// expected vs actual file size (rif_size exp/act), whether an application record is present
// (has_app) and how many of the remaining records are additional content (n_ac).

#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace LibProsperoPkg.License;

/// <summary>
/// A summary of a <see cref="ProsperoRifSet"/> relative to a known application title, mirroring the
/// verify-path report: the record count, the resolved application record, the additional-content
/// count and the expected/actual file size.
/// </summary>
public sealed class ProsperoRifSetSummary
{
    /// <summary>The number of records in the file (<c>n_rif</c>).</summary>
    public required int RecordCount { get; init; }

    /// <summary>True when a record for the supplied application title-id was found (<c>has_app</c>).</summary>
    public required bool HasApp { get; init; }

    /// <summary>The content-id of the application record, or <see langword="null"/> when absent.</summary>
    public string? AppContentId { get; init; }

    /// <summary>The service label (<c>ServiceID</c>) of the application record, or <see langword="null"/>.</summary>
    public string? ServiceId { get; init; }

    /// <summary>The count of records that are not the application record (<c>n_ac</c>).</summary>
    public required int AdditionalContentCount { get; init; }

    /// <summary>The expected file size for <see cref="RecordCount"/> records (<c>rif_size</c> exp).</summary>
    public required long ExpectedSize { get; init; }

    /// <summary>The actual file size measured (<c>rif_size</c> act), or the expected size when built in-memory.</summary>
    public required long ActualSize { get; init; }

    /// <summary>True when <see cref="ExpectedSize"/> equals <see cref="ActualSize"/>.</summary>
    public bool SizeMatches => ExpectedSize == ActualSize;

    /// <summary>Renders the one-line verify-style summary.</summary>
    public override string ToString() =>
        $"ServiceID={ServiceId ?? "-"}, rif_size(exp/act)={ExpectedSize:D8}/{ActualSize:D8}, " +
        $"has_app={(HasApp ? "true" : "false")}, n_ac={AdditionalContentCount}, n_rif={RecordCount}";
}

/// <summary>
/// A parsed multi-content license file: an ordered collection of <see cref="ProsperoRif"/> records.
/// Provides the record count, per-record identifiers and the structural checks the verify path runs,
/// including the whole-file-size rule (a positive multiple of <see cref="ProsperoRif.RecordSize"/>).
/// </summary>
public sealed class ProsperoRifSet
{
    /// <summary>The records in file order. Always at least one when parsed from a valid file.</summary>
    public required IReadOnlyList<ProsperoRif> Records { get; init; }

    /// <summary>The measured file size in bytes, or the computed size for an in-memory set.</summary>
    public required long FileSize { get; init; }

    /// <summary>The number of records (<c>n_rif</c>, "Number of Contents in RIF file").</summary>
    public int Count => Records.Count;

    /// <summary>The expected file size: <see cref="Count"/> × <see cref="ProsperoRif.RecordSize"/>.</summary>
    public long ExpectedSize => (long)Count * ProsperoRif.RecordSize;

    /// <summary>The distinct content-ids across the records, in first-seen order.</summary>
    public IReadOnlyList<string> ContentIds =>
        Records.Select(r => r.ContentId).Distinct(StringComparer.Ordinal).ToArray();

    /// <summary>The distinct title-ids across the records (nulls dropped), in first-seen order.</summary>
    public IReadOnlyList<string> TitleIds =>
        Records.Select(r => r.TitleId).Where(t => t is not null).Select(t => t!).Distinct(StringComparer.Ordinal).ToArray();

    /// <summary>The distinct service labels (<c>ServiceID</c>s) across the records, in first-seen order.</summary>
    public IReadOnlyList<string> ServiceLabels =>
        Records.Select(r => r.ServiceLabel).Where(s => s is not null).Select(s => s!).Distinct(StringComparer.Ordinal).ToArray();

    /// <summary>Reads every record from a (single- or multi-content) license file on disk.</summary>
    public static ProsperoRifSet ReadFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        long size = new FileInfo(path).Length;
        IReadOnlyList<ProsperoRif> records = ProsperoRif.ReadAll(path);
        return new ProsperoRifSet { Records = records, FileSize = size };
    }

    /// <summary>Reads every record from a (single- or multi-content) license stream.</summary>
    public static ProsperoRifSet Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        long size = stream.Length;
        IReadOnlyList<ProsperoRif> records = ProsperoRif.ReadAll(stream);
        return new ProsperoRifSet { Records = records, FileSize = size };
    }

    /// <summary>Builds a set from already-parsed records (for building or re-checking in memory).</summary>
    /// <exception cref="ArgumentException"><paramref name="records"/> is empty.</exception>
    public static ProsperoRifSet FromRecords(IEnumerable<ProsperoRif> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        var list = records.ToArray();
        if (list.Length == 0)
            throw new ArgumentException("A license set needs at least one record.", nameof(records));
        return new ProsperoRifSet { Records = list, FileSize = (long)list.Length * ProsperoRif.RecordSize };
    }

    /// <summary>
    /// Validates the set: a non-zero record count, the whole-file-size rule, and each record's own
    /// structural checks. Returns <see langword="true"/> when consistent; otherwise
    /// <paramref name="error"/> describes the first problem.
    /// </summary>
    public bool Validate(out string? error)
    {
        if (Count == 0)
        {
            error = "A license file must contain at least one record.";
            return false;
        }
        if (FileSize != ExpectedSize)
        {
            error = $"Unexpected rif file size {FileSize} (expected {ExpectedSize} for {Count} record(s)).";
            return false;
        }
        for (int i = 0; i < Records.Count; i++)
        {
            if (!Records[i].Validate(out string? recordError))
            {
                error = $"Record {i}: {recordError}";
                return false;
            }
        }
        error = null;
        return true;
    }

    /// <summary>
    /// Summarises the set relative to a known application title-id (typically taken from the disc
    /// backup's <c>app.json</c> / <c>bd/param.json</c>). The record whose title-id matches is treated
    /// as the application; the rest are counted as additional content (<c>n_ac</c>).
    /// </summary>
    /// <param name="appTitleId">The application title-id (e.g. <c>PPSA00000</c>), or <see langword="null"/>.</param>
    public ProsperoRifSetSummary Summarize(string? appTitleId = null)
    {
        ProsperoRif? app = appTitleId is null
            ? null
            : Records.FirstOrDefault(r => string.Equals(r.TitleId, appTitleId, StringComparison.OrdinalIgnoreCase));

        bool hasApp = app is not null;
        return new ProsperoRifSetSummary
        {
            RecordCount = Count,
            HasApp = hasApp,
            AppContentId = app?.ContentId,
            ServiceId = app?.ServiceLabel ?? (Records.Count > 0 ? Records[0].ServiceLabel : null),
            AdditionalContentCount = hasApp ? Count - 1 : Count,
            ExpectedSize = ExpectedSize,
            ActualSize = FileSize,
        };
    }

    /// <summary>Renders a multi-line description of every record for diagnostics.</summary>
    public string Describe()
    {
        var sb = new StringBuilder();
        sb.Append("License set: ").Append(Count).Append(" record(s), ").Append(FileSize).AppendLine(" bytes");
        for (int i = 0; i < Records.Count; i++)
        {
            ProsperoRif r = Records[i];
            sb.Append("  [").Append(i).Append("] ContentId=").Append(r.ContentId)
              .Append(", ServiceID=").Append(r.ServiceLabel ?? "-")
              .Append(", TitleId=").Append(r.TitleId ?? "-")
              .Append(", keyBlob=").AppendLine(r.HasKeyBlob ? "present" : "empty");
        }
        return sb.ToString();
    }
}
