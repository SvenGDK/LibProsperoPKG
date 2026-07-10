// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// ---------------------------------------------------------------------------------------------------
// PS5 nwonly INNER pfs_image.dat assembler (generalised from a file tree). Computes the inode table,
// afid assignment, dirents, both flat-path tables, the afid_to_ino_table, per-file logical offsets and
// the data-first on-disk layout, then emits the metadata plaintext (via ProsperoPs5InnerMetadata) and
// the assembled inner image (via ProsperoPs5InnerImageBuilder).
//
// The file-tree model fixes inode order, afid order, dirent offsets, FLT entries, packed data offsets,
// store rules, data-first layout, and inner mount geometry (Ndblock / metadata-region base).
// ---------------------------------------------------------------------------------------------------
#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace LibProsperoPkg.PFS;

/// <summary>One regular file to place in the PS5 nwonly inner image.</summary>
public sealed class ProsperoPs5InnerFile
{
    /// <summary>Absolute path from the user root, e.g. <c>/sce_sys/keystone</c> or <c>/application.ps.bundle</c>.</summary>
    public required string Path { get; init; }

    /// <summary>The uncompressed file bytes.</summary>
    public required byte[] Data { get; init; }
}

/// <summary>The assembled inner image plus the intermediate model (for verification/diagnostics).</summary>
public sealed class ProsperoPs5InnerImageResult
{
    /// <summary>The on-disk inner <c>pfs_image.dat</c> bytes (data-first, per-file compressed).</summary>
    public required byte[] Image { get; init; }

    /// <summary>The uncompressed metadata-region plaintext (the block that is Kraken-compressed into the image tail).</summary>
    public required byte[] MetadataPlaintext { get; init; }

    /// <summary>The computed metadata nodes (inode order), for inspection.</summary>
    public required IReadOnlyList<ProsperoPs5MetaNode> Nodes { get; init; }

    /// <summary>The inner mount logical block count (superblock <c>Ndblock</c>).</summary>
    public required long Ndblock { get; init; }

    /// <summary>The per-file uncompressed logical start offsets, in afid order (the naps fidx values).</summary>
    public required IReadOnlyList<long> AfidLogicalOffsets { get; init; }

    /// <summary>Per-file on-disk/logical placement (afid order), for naps generation.</summary>
    public IReadOnlyList<ProsperoPs5InnerPlacement> Placements { get; init; } = Array.Empty<ProsperoPs5InnerPlacement>();

    /// <summary>On-disk byte offset of the block-info table (block 75).</summary>
    public long BlockInfoOnDiskOffset { get; init; }

    /// <summary>On-disk byte offset of the Kraken-compressed metadata region.</summary>
    public long MetadataOnDiskOffset { get; init; }

    /// <summary>The Kraken-compressed metadata bytes (concatenated 256K blocks).</summary>
    public byte[] CompressedMetadata { get; init; } = Array.Empty<byte>();

    /// <summary>Logical end of the packed data files (first fidx boundary after the last file).</summary>
    public long DataEndLogical { get; init; }

    /// <summary>Logical base of the metadata region in the mount (= Ndblock*64K - MetadataPlaintext.Length).</summary>
    public long MetaBaseLogical { get; init; }
}

/// <summary>One file's on-disk + logical placement in the assembled inner image (afid order).</summary>
public readonly struct ProsperoPs5InnerPlacement
{
    /// <summary>On-disk (compressed-image) byte offset.</summary>
    public long OnDiskOffset { get; init; }
    /// <summary>Uncompressed logical byte offset in the mount.</summary>
    public long LogicalOffset { get; init; }
    /// <summary>On-disk byte size (raw size when stored raw, else the Kraken payload size).</summary>
    public long OnDiskSize { get; init; }
    /// <summary>Uncompressed byte size.</summary>
    public long UncompressedSize { get; init; }
    /// <summary>True when stored raw (block-split), false when Kraken-compressed.</summary>
    public bool StoreRaw { get; init; }
}

/// <summary>
/// Builds a PS5 nwonly inner <c>pfs_image.dat</c> from a flat list of files. Handles the two flat-path
/// tables, the afid table, the data-first layout, and per-file Kraken compression.
/// </summary>
public sealed class ProsperoPs5InnerImageAssembler
{
    /// <summary>Inner-image block size (64 KiB).</summary>
    public const int BlockSize = 0x10000;

    private const string SceSysDir = "sce_sys";

    private readonly long _timeSec;
    private readonly uint _timeNsec;

    /// <param name="buildTimeSec">Build timestamp seconds (package c_date/c_time — a deterministic build input).</param>
    /// <param name="buildTimeNsec">Build timestamp nanoseconds fraction.</param>
    public ProsperoPs5InnerImageAssembler(long buildTimeSec, uint buildTimeNsec)
    {
        _timeSec = buildTimeSec;
        _timeNsec = buildTimeNsec;
    }

    // ---- Internal tree model -----------------------------------------------------------------------

    private sealed class Dir
    {
        public string Name = "";
        public string FullPath = "";      // "" for uroot
        public Dir? Parent;
        public readonly List<Dir> SubDirs = new();
        public readonly List<FileNode> Files = new();
        public uint Inode;
        public int DirentOffsetInParent = -1;
        public readonly List<ProsperoPfsDirent> Dirents = new();
    }

    private sealed class FileNode
    {
        public string Name = "";
        public string FullPath = "";
        public byte[] Data = Array.Empty<byte>();
        public Dir Parent = null!;
        public uint Inode;
        public uint Afid;
        public bool StoreRaw;
        public long LogicalOffset;
        public int DirentOffsetInParent = -1;

        /// <summary>The file's on-disk (data-region) byte offset in the built image (set during assembly).</summary>
        public long OnDiskOffset;

        /// <summary>The file's on-disk bytes (raw when StoreRaw, else the Kraken-compressed payload). Cached to
        /// avoid recompressing: it drives both the data-region geometry and the final image assembly.</summary>
        public byte[]? OnDiskData;

        /// <summary>True for files in the sce_sys subtree. Drives the inode mode (base +0x20000) and the
        /// block-info Σ exclusion (sce_sys payload is not part of the uroot app-payload sum).</summary>
        public bool SceSys;

        /// <summary>True only for the DRM keystone, which is stored raw and occupies whole 64 KiB blocks
        /// (block-aligned start and end) so the packed data region begins on a fresh block after it. Other
        /// sce_sys payload files are Kraken-compressed and packed like app payload.</summary>
        public bool WholeBlockRaw;
    }

    /// <summary>
    /// Bridges the package builder's <see cref="ProsperoFsDir"/> tree to the assembler: renders every file's
    /// bytes and its full path, then builds the data-first inner image. Convenience entry point for wiring the
    /// assembler into <c>ProsperoPkgBuilder</c> for the nwonly Kraken format.
    /// </summary>
    public ProsperoPs5InnerImageResult BuildFromFsTree(ProsperoFsDir uroot)
    {
        ArgumentNullException.ThrowIfNull(uroot);
        var files = new List<ProsperoPs5InnerFile>();
        foreach (var f in uroot.GetAllChildrenFiles())
        {
            if (IsExcludedFromInner(f.FullPath())) continue;
            using var ms = new System.IO.MemoryStream();
            f.Write(ms);
            files.Add(new ProsperoPs5InnerFile { Path = f.FullPath(), Data = ms.ToArray() });
        }
        return Build(files);
    }

    // A sce_sys file whose sce_sys-relative name is a known outer-CNT entry is carried in the OUTER
    // container, not the inner image. The rule extends the standard inner-PFS builder
    // (ProsperoPfsBuilder) with param.json (CNT id 0x2000, emitted as its own outer entry and therefore
    // absent from NameToId). Files without CNT ids stay in the inner uroot alongside the app payload.
    private static bool IsExcludedFromInner(string fullPath)
    {
        const string prefix = "/sce_sys/";
        if (!fullPath.StartsWith(prefix, StringComparison.Ordinal)) return false;
        string rel = fullPath.Substring(prefix.Length);
        return rel == "param.json" || PKG.ProsperoCntEntryNames.NameToId.ContainsKey(rel);
    }

    /// <summary>Assembles the inner image from the supplied files.</summary>
    public ProsperoPs5InnerImageResult Build(IReadOnlyList<ProsperoPs5InnerFile> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        if (files.Count == 0)
            throw new ArgumentException("At least one inner file is required.", nameof(files));

        Dir uroot = BuildTree(files);

        // ---- 1. Assign inodes. ---------------------------------------------------------------------
        // 0 = super-root, 1..3 = the three internal metadata files, 4 = uroot, then sub-directories in
        // pre-order DFS, then regular files grouped by directory in *reverse* directory-inode order
        // (deepest-assigned directory's files first), ordinal within a directory.
        var dirsPreOrder = new List<Dir>();
        CollectDirsPreOrder(uroot, dirsPreOrder); // uroot first, then descendants pre-order

        uint next = 0;
        var superRootInode = next++;      // 0
        var inodeFltInode = next++;       // 1
        var aprFltInode = next++;         // 2
        var afidTableInode = next++;      // 3
        foreach (var d in dirsPreOrder)   // uroot=4, subdirs...
            d.Inode = next++;

        // Files: directories in POST-ORDER DFS (deepest-first, siblings ordinal), files ordinal within each.
        // (For a linear chain — e.g. nwonly's uroot/sce_sys/about — post-order == reverse pre-order, but for a
        // branching tree they differ; post-order is the general rule.)
        var dirsPostOrder = new List<Dir>();
        CollectDirsPostOrder(uroot, dirsPostOrder);
        var fileNodes = new List<FileNode>();
        foreach (var d in dirsPostOrder)
            foreach (var f in d.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            {
                f.Inode = next++;
                fileNodes.Add(f);
            }

        // ---- 2. Assign afids. ----------------------------------------------------------------------
        // sce_sys subtree files first (pre-order DFS), then the remaining uroot files (ordinal by name).
        var afidOrder = new List<FileNode>();
        Dir? sceSys = uroot.SubDirs.FirstOrDefault(d => d.Name == SceSysDir);
        if (sceSys != null) CollectFilesPreOrder(sceSys, afidOrder);
        foreach (var d in dirsPreOrder)
            if (d != sceSys && !IsUnder(d, sceSys))
                foreach (var f in d.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
                    afidOrder.Add(f);
        // Any files directly in uroot come after the sce_sys subtree, ordinal (already covered by the
        // loop above because uroot is in dirsPreOrder and is not under sce_sys).
        for (uint a = 0; a < afidOrder.Count; a++)
            afidOrder[(int)a].Afid = a;

        // ---- 3. Logical offsets (packed, in afid order) + store rule. -----------------------------
        long cursor = 0;
        var afidOffsets = new long[afidOrder.Count];
        foreach (var f in afidOrder)
        {
            f.LogicalOffset = cursor;
            afidOffsets[f.Afid] = cursor;
            cursor += f.Data.Length;
            f.StoreRaw = ShouldStoreRaw(f);
            f.SceSys = f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal);
            f.WholeBlockRaw = IsKeystone(f.FullPath);
            // Cache the on-disk bytes now (raw, or the Kraken payload) so the data-region geometry and the
            // final image share one compression pass.
            f.OnDiskData = f.StoreRaw ? f.Data : ProsperoPs5InnerImageBuilder.CompressPayload(f.Data, storeRaw: false);
        }

        // Data-region block count = the on-disk block index of the block-info table (the block-aligned end of
        // the packed data files). Raw files are block-aligned, compressed files are packed; this mirrors
        // ProsperoPs5InnerImageBuilder.Build exactly.
        long dataBlocks = ComputeDataRegionBlocks(afidOrder);

        // ---- 4. Dirents (with byte offsets). -------------------------------------------------------
        BuildDirents(uroot);

        // ---- 5. Build the metadata nodes in inode order. ------------------------------------------
        var nodes = BuildNodes(uroot, dirsPreOrder, fileNodes, dataBlocks,
            superRootInode, inodeFltInode, aprFltInode, afidTableInode, out long ndblock);

        // ---- 6. Build metadata plaintext. ----------------------------------------------------------
        byte[] metaPlain = BuildMetadataPlaintext(nodes, dirsPreOrder, fileNodes, afidOrder, ndblock,
            inodeFltInode, aprFltInode, afidTableInode, uroot);

        // ---- 7. Assemble the data-first image. ----------------------------------------------------
        byte[] image = BuildImage(afidOrder, metaPlain, out long blockInfoOnDisk, out long metadataOnDisk,
            out byte[] compressedMeta);

        long metaBaseLogical = ndblock * ProsperoPs5InnerImageBuilder.BlockSize - metaPlain.Length;
        long dataEndLogical = afidOrder.Count == 0 ? 0
            : afidOrder[^1].LogicalOffset + afidOrder[^1].Data.Length;
        var placements = afidOrder.Select(f => new ProsperoPs5InnerPlacement
        {
            OnDiskOffset = f.OnDiskOffset,
            LogicalOffset = f.LogicalOffset,
            OnDiskSize = f.OnDiskData!.Length,
            UncompressedSize = f.Data.Length,
            StoreRaw = f.StoreRaw,
        }).ToList();

        return new ProsperoPs5InnerImageResult
        {
            Image = image,
            MetadataPlaintext = metaPlain,
            Nodes = nodes,
            Ndblock = ndblock,
            AfidLogicalOffsets = afidOffsets,
            Placements = placements,
            BlockInfoOnDiskOffset = blockInfoOnDisk,
            MetadataOnDiskOffset = metadataOnDisk,
            CompressedMetadata = compressedMeta,
            DataEndLogical = dataEndLogical,
            MetaBaseLogical = metaBaseLogical,
        };
    }

    // ---- Tree construction -------------------------------------------------------------------------

    private static Dir BuildTree(IReadOnlyList<ProsperoPs5InnerFile> files)
    {
        var uroot = new Dir { Name = "uroot", FullPath = "" };
        var dirLookup = new Dictionary<string, Dir>(StringComparer.Ordinal) { [""] = uroot };

        Dir GetDir(string fullPath)
        {
            if (dirLookup.TryGetValue(fullPath, out var d)) return d;
            int slash = fullPath.LastIndexOf('/');
            string parentPath = slash <= 0 ? "" : fullPath[..slash];
            string name = fullPath[(slash + 1)..];
            Dir parent = GetDir(parentPath);
            var dir = new Dir { Name = name, FullPath = fullPath, Parent = parent };
            parent.SubDirs.Add(dir);
            dirLookup[fullPath] = dir;
            return dir;
        }

        foreach (var f in files.OrderBy(f => f.Path, StringComparer.Ordinal))
        {
            string path = f.Path.StartsWith('/') ? f.Path[1..] : f.Path;
            int slash = path.LastIndexOf('/');
            string dirPath = slash < 0 ? "" : path[..slash];
            string name = slash < 0 ? path : path[(slash + 1)..];
            Dir parent = GetDir(dirPath);
            parent.Files.Add(new FileNode
            {
                Name = name,
                FullPath = "/" + path,
                Data = f.Data,
                Parent = parent,
            });
        }
        return uroot;
    }

    private static void CollectDirsPreOrder(Dir dir, List<Dir> outList)
    {
        outList.Add(dir);
        foreach (var d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectDirsPreOrder(d, outList);
    }

    private static void CollectDirsPostOrder(Dir dir, List<Dir> outList)
    {
        foreach (var d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectDirsPostOrder(d, outList);
        outList.Add(dir);
    }

    private static void CollectFilesPreOrder(Dir dir, List<FileNode> outList)
    {
        foreach (var f in dir.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            outList.Add(f);
        foreach (var d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectFilesPreOrder(d, outList);
    }

    private static bool IsUnder(Dir dir, Dir? ancestor)
    {
        if (ancestor == null) return false;
        for (Dir? d = dir; d != null; d = d.Parent)
            if (d == ancestor) return true;
        return false;
    }

    private static bool IsKeystone(string fullPath) =>
        string.Equals(fullPath, "/sce_sys/keystone", StringComparison.Ordinal);

    // Executable modules are stored raw (uncompressed) in the nwonly inner. The console memory-maps
    // modules directly, so compression is skipped. Detected by container magic: plaintext SELF
    // (0x1D3D154F), module container (0xEEF51454), or raw executable image (0x464C457F).
    private static bool IsExecutableModule(byte[] data)
    {
        if (data.Length < 4) return false;
        uint magic = (uint)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
        return magic is 0x1D3D154F or 0xEEF51454 or 0x464C457F;
    }

    private static bool ShouldStoreRaw(FileNode f)
    {
        // The DRM keystone and every executable module are stored raw. Other files (app data assets) are
        // Kraken-compressed and packed, unless the Kraken result does not save at least the format store
        // threshold, in which case they are stored raw too.
        if (IsKeystone(f.FullPath) || IsExecutableModule(f.Data)) return true;
        byte[] comp = ProsperoPs5InnerImageBuilder.CompressPayload(f.Data, storeRaw: false);
        return comp.Length >= f.Data.Length; // CompressPayload already returns raw when it doesn't help
    }

    // ---- Dirents -----------------------------------------------------------------------------------

    private static void BuildDirents(Dir uroot)
    {
        // super-root's children (the three tables + uroot) get no dirent-offset (ParentInode == -1).
        // Every ordinary directory's dirent block is: ".", "..", sub-directories (ordinal), files (ordinal).
        BuildDirentsRecursive(uroot, isUroot: true);
    }

    private static void BuildDirentsRecursive(Dir dir, bool isUroot)
    {
        dir.Dirents.Clear();
        // "." -> self, ".." -> parent (uroot's parent is itself).
        dir.Dirents.Add(new ProsperoPfsDirent { Name = ".", InodeNumber = dir.Inode, Type = ProsperoDirentType.Dot });
        uint parentIno = dir.Parent?.Inode ?? dir.Inode;
        dir.Dirents.Add(new ProsperoPfsDirent { Name = "..", InodeNumber = parentIno, Type = ProsperoDirentType.DotDot });

        foreach (var d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            dir.Dirents.Add(new ProsperoPfsDirent { Name = d.Name, InodeNumber = d.Inode, Type = ProsperoDirentType.Directory });
        foreach (var f in dir.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            dir.Dirents.Add(new ProsperoPfsDirent { Name = f.Name, InodeNumber = f.Inode, Type = ProsperoDirentType.File });

        // Resolve each child's byte offset within this dirent block.
        int off = 0;
        var byName = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var e in dir.Dirents)
        {
            byName[e.Name] = off;
            off += e.EntSize;
        }
        foreach (var d in dir.SubDirs)
            d.DirentOffsetInParent = byName[d.Name];
        foreach (var f in dir.Files)
            f.DirentOffsetInParent = byName[f.Name];

        foreach (var d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            BuildDirentsRecursive(d, isUroot: false);
    }

    // ---- Node model + geometry ---------------------------------------------------------------------

    private List<ProsperoPs5MetaNode> BuildNodes(
        Dir uroot, List<Dir> dirsPreOrder, List<FileNode> fileNodes, long dataBlocks,
        uint superRootInode, uint inodeFltInode, uint aprFltInode, uint afidTableInode, out long ndblock)
    {
        // Metadata-region layout (in the logical mount, after the data region): one block each for the
        // super-root dirents, the inode/apr flat-path tables, the afid table, then every directory's
        // dirent block (uroot, sub-directories in pre-order). Their logical offsets are consecutive
        // 64 KiB blocks starting at the metadata-region base.
        int metadataContentBlocks = 1 /*super-root dirents*/ + 3 /*flt/apr/afid*/ + dirsPreOrder.Count /*dir dirents*/ + 1 /*trailing*/;
        // PFSv3 mount geometry: after the on-disk data region (dataBlocks = the block-aligned end of
        // the packed data files, i.e. the block-info table's block index) the mount leaves a fixed 61-block
        // reserve, then the metadata plaintext (superblock + inode table + content blocks). The super-root
        // dirents block (metaBase) is the third metadata block, so metaBase = dataBlocks + 61 + 2. Ndblock is
        // the end of the metadata region = metaBase + metadataContentBlocks.
        const long MetadataReserveBlocks = 61;
        long metaBaseBlock = dataBlocks + MetadataReserveBlocks + 2;
        long metaBase = metaBaseBlock * BlockSize;
        ndblock = metaBaseBlock + metadataContentBlocks;

        long b = metaBase;
        var nodes = new List<ProsperoPs5MetaNode>();

        // inode 0: super-root directory.
        nodes.Add(new ProsperoPs5MetaNode
        {
            Name = "",
            Inode = superRootInode,
            IsDirectory = true,
            Mode = 0x416d,
            Nlink = 1,
            Flags = 0x00020010,
            Size = BlockSize,
            LogicalOffset = (ulong)b,
            ParentInode = -1,
            DirentOffset = -1,
        });
        b += BlockSize;

        // inodes 1..3: the internal metadata files (flat-path tables + afid table). Sizes are filled in
        // by BuildMetadataPlaintext; here we only need the logical offsets + inode fields. The names are the
        // fixed PFS-internal identifiers (used for the pfsimage.xml introspection; not written as dirents).
        nodes.Add(MetaFileNode(inodeFltInode, (ulong)b, 0x00020010, "inode_flat_path_table")); b += BlockSize;
        nodes.Add(MetaFileNode(aprFltInode, (ulong)b, 0x00020010, "apr_flat_path_table")); b += BlockSize;
        nodes.Add(MetaFileNode(afidTableInode, (ulong)b, 0x00020010, "afid_to_ino_table")); b += BlockSize;

        // inode 4: uroot; then sub-directories pre-order.
        foreach (var d in dirsPreOrder)
        {
            bool isUroot = d == uroot;
            nodes.Add(new ProsperoPs5MetaNode
            {
                Name = d.Name,
                Inode = d.Inode,
                IsDirectory = true,
                Mode = (ushort)(isUroot ? 0x416d : 0x4168),
                Nlink = (ushort)(2 + d.SubDirs.Count + (isUroot ? 1 : 0)),
                Flags = (uint)(isUroot ? 0x00000010 : 0x00020010),
                Size = BlockSize,
                LogicalOffset = (ulong)b,
                ParentInode = isUroot ? -1 : (int)d.Parent!.Inode,
                DirentOffset = isUroot ? -1 : d.DirentOffsetInParent,
            });
            b += BlockSize;
        }

        // Regular files (inode order = fileNodes order).
        foreach (var f in fileNodes)
        {
            bool sceSys = f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal);
            bool exec = IsExecutableModule(f.Data);
            nodes.Add(new ProsperoPs5MetaNode
            {
                Name = f.Name,
                Inode = f.Inode,
                IsDirectory = false,
                Mode = (ushort)(sceSys ? 0x8168 : 0x816d),
                Nlink = 1,
                // base 0x10, +0x40 for an executable module else +0x20
                // for a data blob (e.g. the DRM keystone), +0x20000 for the sce_sys subtree.
                Flags = 0x10u | (exec ? 0x40u : 0x20u) | (sceSys ? 0x20000u : 0u),
                Afid = f.Afid,
                Size = f.Data.Length,
                LogicalOffset = (ulong)f.LogicalOffset,
                ParentInode = (int)f.Parent.Inode,
                DirentOffset = f.DirentOffsetInParent,
            });
        }

        return nodes.OrderBy(n => n.Inode).ToList();
    }

    private ProsperoPs5MetaNode MetaFileNode(uint inode, ulong logOff, uint flags, string name = "") => new()
    {
        Name = name,
        Inode = inode,
        IsDirectory = false,
        Mode = 0x816d,
        Nlink = 1,
        Flags = flags,
        LogicalOffset = logOff,
        ParentInode = -1,
        DirentOffset = -1,
    };

    /// <summary>Rounds <paramref name="value"/> up to a multiple of <paramref name="granularity"/>.</summary>
    private static long RoundUp(long value, long granularity) => (value + granularity - 1) / granularity * granularity;

    // ---- Metadata plaintext + FLT + afid table -----------------------------------------------------

    private byte[] BuildMetadataPlaintext(
        List<ProsperoPs5MetaNode> nodes, List<Dir> dirsPreOrder, List<FileNode> fileNodes,
        List<FileNode> afidOrder, long ndblock,
        uint inodeFltInode, uint aprFltInode, uint afidTableInode, Dir uroot)
    {
        // Flat-path tables. inode_flat_path_table = every path (files + dirs) -> {inode, dir flag, subtree
        // flag, afid}. apr_flat_path_table = only the non-sce_sys ("apr") files -> {uncompressed size, afid}.
        var inodeFlt = new List<ProsperoPs5FlatPathTable.Entry>();
        void FI(string path, uint inode, bool dir, bool subtreeApr, uint afid) =>
            inodeFlt.Add(new(ProsperoPs5FlatPathTable.HashPath(path),
                ProsperoPs5FlatPathTable.PackInodeEntry(inode, dir, !subtreeApr, afid)));

        var aprFlt = new List<ProsperoPs5FlatPathTable.Entry>();
        void FA(string path, long size, uint afid) =>
            aprFlt.Add(new(ProsperoPs5FlatPathTable.HashPath(path),
                ProsperoPs5FlatPathTable.PackAprEntry(size, afid)));

        foreach (var d in dirsPreOrder)
            if (d != uroot)
                FI(d.FullPath, d.Inode, dir: true, subtreeApr: false, afid: 0);
        foreach (var f in fileNodes)
        {
            bool apr = !f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal);
            FI(f.FullPath, f.Inode, dir: false, subtreeApr: apr, afid: f.Afid);
            if (apr) FA(f.FullPath, f.Data.Length, f.Afid);
        }

        byte[] inodeFltBytes = ProsperoPs5FlatPathTable.ToBytes(inodeFlt);
        byte[] aprFltBytes = ProsperoPs5FlatPathTable.ToBytes(aprFlt);

        // afid_to_ino_table: [firstFileInode, inode per afid (afid 0..N), -1, -1]. The leading value is the
        // number of non-file inodes (super-root + 3 tables + all directories) = the first regular-file inode.
        var afidTable = new List<int> { (int)fileNodes.Min(f => f.Inode) };
        foreach (var f in afidOrder) afidTable.Add((int)f.Inode);
        afidTable.Add(-1); afidTable.Add(-1);
        byte[] afidBytes = new byte[afidTable.Count * 4];
        for (int i = 0; i < afidTable.Count; i++)
            BitConverter.GetBytes(afidTable[i]).CopyTo(afidBytes, i * 4);

        // Fill in the internal-file sizes on their nodes.
        foreach (var n in nodes)
        {
            if (n.Inode == inodeFltInode) n.Size = inodeFltBytes.Length;
            else if (n.Inode == aprFltInode) n.Size = aprFltBytes.Length;
            else if (n.Inode == afidTableInode) n.Size = afidBytes.Length;
        }

        // Ordered metadata blocks after the superblock (block 0) + inode table (block 1):
        //   [super-root dirents][inode_flt][apr_flt][afid][uroot dirents][sub-dir dirents...][empty]
        var blocks = new List<byte[]>
        {
            DirentBytes(SuperRootDirents(inodeFltInode, aprFltInode, afidTableInode, uroot.Inode)),
            inodeFltBytes, aprFltBytes, afidBytes,
        };
        foreach (var d in dirsPreOrder)
            blocks.Add(DirentBytes(d.Dirents));
        blocks.Add(Array.Empty<byte>());

        var meta = new ProsperoPs5InnerMetadata(_timeSec, _timeNsec);
        return meta.Build(nodes, ndblock, blocks);
    }

    private static IEnumerable<ProsperoPfsDirent> SuperRootDirents(uint inodeFlt, uint aprFlt, uint afid, uint uroot) => new[]
    {
        new ProsperoPfsDirent { InodeNumber = inodeFlt, Name = "inode_flat_path_table", Type = ProsperoDirentType.File },
        new ProsperoPfsDirent { InodeNumber = aprFlt, Name = "apr_flat_path_table", Type = ProsperoDirentType.File },
        new ProsperoPfsDirent { InodeNumber = afid, Name = "afid_to_ino_table", Type = ProsperoDirentType.File },
        new ProsperoPfsDirent { InodeNumber = uroot, Name = "uroot", Type = ProsperoDirentType.Directory },
    };

    private static byte[] DirentBytes(IEnumerable<ProsperoPfsDirent> dirents)
    {
        using var ms = new System.IO.MemoryStream();
        foreach (var d in dirents) d.WriteToStream(ms);
        return ms.ToArray();
    }

    // ---- Data-first image --------------------------------------------------------------------------

    /// <summary>
    /// Computes the on-disk block index of the block-info table = the block-aligned end of the packed data
    /// files (raw files block-aligned, compressed files packed), matching ProsperoPs5InnerImageBuilder.Build.
    /// </summary>
    private static long ComputeDataRegionBlocks(List<FileNode> afidOrder)
    {
        long pos = 0;
        foreach (var f in afidOrder)
        {
            byte[] data = f.OnDiskData!;
            // Raw files (keystone + executable modules) start block-aligned; the keystone additionally
            // occupies whole blocks so the data region begins on a fresh block after it. Compressed app
            // data packs contiguously.
            if (f.StoreRaw)
                pos = RoundUp(pos, BlockSize);
            pos += data.Length;
            if (f.WholeBlockRaw)
                pos = RoundUp(pos, BlockSize);
        }
        return RoundUp(pos, BlockSize) / BlockSize;
    }

    private byte[] BuildImage(List<FileNode> afidOrder, byte[] metaPlain,
        out long blockInfoOnDisk, out long metadataOnDisk, out byte[] compressedMeta)
    {
        const int BLK = ProsperoPs5InnerImageBuilder.BlockSize; // 0x10000
        static long AlignUp(long v, long a) => (v + a - 1) & ~(a - 1);

        // Build payloads with the on-disk packing rule and compute each file's on-disk offset by
        // replaying the same layout the builder performs.
        //   - keystone (WholeBlockRaw): anchors its own whole block (block-aligned before + after).
        //   - other raw modules: pack contiguously into the current block, but a module that does not fit
        //     in the current block's remainder starts a fresh block. A module already sitting on a block
        //     boundary never needs realignment. The metadata/mount geometry stays derived from the
        //     block-aligned data-region count (ComputeDataRegionBlocks), so packing only shrinks the
        //     on-disk image; metaBase/ndblock (mount size) are unchanged.
        //   - compressed app data: packs contiguously.
        var payloads = new List<ProsperoPs5InnerPayload>();
        long pos = 0;
        foreach (var f in afidOrder)
        {
            bool alignAfter = f.WholeBlockRaw;
            bool alignBefore =
                f.WholeBlockRaw ||
                (f.StoreRaw && pos % BLK != 0 && f.OnDiskData!.Length > BLK - pos % BLK);

            var p = new ProsperoPs5InnerPayload
            {
                // Pre-compressed: pass the cached on-disk bytes through as raw so the builder never recompresses.
                Data = f.OnDiskData!,
                StoreRaw = true,
                BlockAligned = alignBefore,
                BlockAlignedAfter = alignAfter,
            };
            payloads.Add(p);

            if (alignBefore) pos = AlignUp(pos, BLK);
            f.OnDiskOffset = pos;
            pos += p.Data.Length;
            if (alignAfter) pos = AlignUp(pos, BLK);
        }

        // The block-info table sits between the data files and the metadata block, block-aligned.
        // Its variable entry encodes the sub-256KiB remainder of the uroot payload size; see BuildBlockInfoTable.
        long urootSize = 0;
        foreach (var f in afidOrder)
            if (!f.SceSys) urootSize += f.Data.Length;
        byte[] blockInfo = BuildBlockInfoTable(urootSize);
        pos = AlignUp(pos, BLK);
        blockInfoOnDisk = pos;
        pos += blockInfo.Length;
        payloads.Add(new ProsperoPs5InnerPayload { Data = blockInfo, StoreRaw = true, BlockAligned = true });

        compressedMeta = ProsperoPs5InnerImageBuilder.CompressPayload(metaPlain, storeRaw: false);
        pos = AlignUp(pos, BLK);
        metadataOnDisk = pos;
        payloads.Add(new ProsperoPs5InnerPayload
        {
            Data = compressedMeta,
            StoreRaw = true,
            BlockAligned = true,
        });
        return new ProsperoPs5InnerImageBuilder().Build(payloads);
    }

    /// <summary>
    /// PFSv3 build/SDK version stamped into every block-75 entry (little-endian u32). The low nibble
    /// encodes system/firmware 4.03.
    /// </summary>
    private const uint BlockInfoVersion = 0x00400003;

    /// <summary>The constant value emitted for the three template slots of the block-75 table; independent
    /// of package content.</summary>
    private const uint BlockInfoTemplate = 0x00FCFF27;

    /// <summary>
    /// Global base constant (read big-endian) of the block-75 variable entry. See <see cref="BuildBlockInfoTable"/>.
    /// </summary>
    private const uint BlockInfoBase = 0x0027373C;

    /// <summary>
    /// Builds the 32-byte inner block-75 table (the PFSv3 inner block-info table that precedes the compressed
    /// metadata block). Each 8-byte entry is <c>{ u32 value, u32 version }</c> (little-endian): three template
    /// entries carry <see cref="BlockInfoTemplate"/>; the fourth carries a value derived structurally from the
    /// uroot content.
    /// <para>The variable entry, read big-endian (<c>b0·2^16 + b1·2^8 + b2</c>), equals
    /// <c>0x27373C − 4·(Σ(uroot file sizes) mod 0x40000)</c>. It encodes the sub-256KiB remainder of the
    /// total uroot payload size. sce_sys module files and the inner metadata tables are not files in the afid
    /// list, so they are naturally excluded from the sum. The stored little-endian value is that big-endian
    /// result with bytes stored in b2,b1,b0 order; a single global constant is used, with no per-package discriminator.</para>
    /// </summary>
    /// <param name="urootFileSizeSum">Sum of the uncompressed sizes of the uroot (non-sce_sys) inner files.</param>
    private static byte[] BuildBlockInfoTable(long urootFileSizeSum)
    {
        // 4·Σ mod 0x100000 == 4·(Σ mod 0x40000); the base always exceeds this, so no borrow.
        uint sub = (uint)((4L * urootFileSizeSum) & 0xFFFFF);
        uint bigEndian = (BlockInfoBase - sub) & 0xFFFFFF;
        uint value = ((bigEndian & 0xFF) << 16) | (bigEndian & 0xFF00) | ((bigEndian >> 16) & 0xFF);

        var table = new byte[32];
        WriteBlockInfoEntry(table, 0, BlockInfoTemplate);
        WriteBlockInfoEntry(table, 8, BlockInfoTemplate);
        WriteBlockInfoEntry(table, 16, BlockInfoTemplate);
        WriteBlockInfoEntry(table, 24, value);
        return table;

        static void WriteBlockInfoEntry(byte[] buffer, int offset, uint entryValue)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), entryValue);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset + 4), BlockInfoVersion);
        }
    }
}
