// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
//
// PFS image structures, builder and reader primitives.
#nullable disable
using LibProsperoPkg.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace LibProsperoPkg.PFS;

/// <summary>
/// Contains the functionality to construct a PFS disk image.
/// </summary>
public class ProsperoPfsBuilder
{
    static int CeilDiv(int a, int b) => a / b + (a % b == 0 ? 0 : 1);
    static long CeilDiv(long a, long b) => a / b + (a % b == 0 ? 0 : 1);

    private ProsperoPfsHeader hdr;
    private List<ProsperoInode> inodes;
    private List<ProsperoPfsDirent> super_root_dirents;

    private ProsperoInode super_root_ino, fpt_ino, cr_ino;

    private List<ProsperoFsDir> allDirs;
    private List<ProsperoFsFile> allFiles;
    private List<ProsperoFsNode> allNodes;

    private ProsperoFlatPathTable fpt;
    private ProsperoCollisionResolver colResolver;

    private ProsperoPfsProperties properties;

    private int emptyBlock = 0x4;
    const int xtsSectorSize = 0x1000;

    private struct BlockSigInfo
    {
        public long Block;
        public long SigOffset;
        public int Size;
        public BlockSigInfo(long block, long offset, int size = 0x10000)
        {
            Block = block;
            SigOffset = offset;
            Size = size;
        }
    }
    private Stack<BlockSigInfo> final_sigs = new Stack<BlockSigInfo>();
    private Stack<BlockSigInfo> data_sigs = new Stack<BlockSigInfo>();

    /// <summary>
    /// When set before <see cref="WriteImage(Stream)"/>, captures the <c>sce_sys/imagedigs.dat</c>
    /// preimage into <see cref="ImageDigests"/>: one per-block descriptor digest for every
    /// block of the plaintext signed image, stored from last byte to first. The PS5 image builder
    /// gathers the signer's per-block HMAC-SHA256 descriptor digests and writes each digest from
    /// byte 31 down to byte 0; reproduced here from this image's own signing key. Populated only for a signed image.
    /// </summary>
    public bool CaptureImageDigests;

    /// <summary>
    /// The captured <c>imagedigs.dat</c> body (N * 32 bytes for N image blocks), or <c>null</c> until
    /// a signed image is written with <see cref="CaptureImageDigests"/> set. See that property.
    /// </summary>
    public byte[] ImageDigests;

    /// <summary>
    /// When set before <see cref="WriteImage(Stream)"/>, captures this image's superblock integrity
    /// value into <see cref="SuperblockIcv"/>: the 32-byte HMAC-SHA256 self-signature of the
    /// superblock (final signature block 0 @ offset 0x380), computed from this image's own signing
    /// key during signing (before XTS encryption). Used for the supplemental <c>pfsimage.xml</c>
    /// <c>&lt;icv&gt;</c> element. Populated only for a signed image.
    /// </summary>
    public bool CaptureSuperblockIcv;

    /// <summary>
    /// The captured 32-byte superblock ICV (see <see cref="CaptureSuperblockIcv"/>), or <c>null</c>
    /// until a signed image is written with that flag set.
    /// </summary>
    public byte[] SuperblockIcv;

    Action<string> logger;
    private void Log(string s) => logger?.Invoke(s);

    /// <summary>
    /// Constructs a PfsBuilder with the given properties and logger.
    /// </summary>
    /// <param name="p">Properties for the image to be built</param>
    /// <param name="logger">Function that is called to report realtime PFS build status.</param>
    public ProsperoPfsBuilder(ProsperoPfsProperties p, Action<string> logger = null)
    {
        this.logger = logger;
        properties = p;
        Setup();
    }

    /// <summary>
    /// Computes the final size of this image as it will be written to disk.
    /// </summary>
    /// <returns>PFS Image size</returns>
    public long CalculatePfsSize()
    {
        return hdr.Ndblock * hdr.BlockSize;
    }

    /// <summary>
    /// Captures a self-consistent snapshot of this image's inode tree and geometry AFTER
    /// <see cref="WriteImage(Stream)"/> has assigned every inode's block layout (and, for a signed
    /// image with <see cref="CaptureSuperblockIcv"/> set, computed the superblock ICV). The snapshot
    /// drives the supplemental <c>pfsimage.xml</c> sections (<c>&lt;pfs-image&gt;</c> /
    /// <c>&lt;nested-image&gt;</c>), which describe the exact bytes this builder produced.
    /// </summary>
    /// <returns>A snapshot of the built image's super-root tree and superblock geometry.</returns>
    public ProsperoPfsImageTreeInfo CaptureImageTree()
    {
        var root = ImageNodeFromInode(super_root_ino, name: "", isDir: true, isInternal: false);

        // The PFS super-root holds the flat path table (+ optional collision resolver) and the user
        // root ("uroot"). These internal pseudo files are not part of the user tree, so synthesize
        // them from their dedicated inodes to mirror the reference super-root layout.
        root.Children.Add(ImageNodeFromInode(fpt_ino, "inode_flat_path_table", isDir: false, isInternal: true));
        if (cr_ino != null)
            root.Children.Add(ImageNodeFromInode(cr_ino, "collision_resolver", isDir: false, isInternal: true));
        root.Children.Add(ImageNodeFromDir(properties.root));

        return new ProsperoPfsImageTreeInfo
        {
            BlockSize = (int)hdr.BlockSize,
            ImageBlocks = hdr.Ndblock,
            InodeCount = inodes.Count,
            DinodeBlockCount = (int)hdr.DinodeBlockCount,
            RootInodeNumber = super_root_ino.Number,
            DinodeBlock = hdr.InodeBlockSig.StartBlock,
            DinodeSize = hdr.InodeBlockSig.Size,
            DinodeFlags = (uint)hdr.InodeBlockSig.Flags,
            Seed = hdr.Seed,
            SuperblockIcv = SuperblockIcv,
            Signed = hdr.Mode.HasFlag(ProsperoPfsMode.Signed),
            Encrypted = hdr.Mode.HasFlag(ProsperoPfsMode.Encrypted),
            Root = root,
        };
    }

    static ProsperoPfsImageNode ImageNodeFromInode(ProsperoInode ino, string name, bool isDir, bool isInternal) => new()
    {
        Name = name,
        IsDirectory = isDir,
        Internal = isInternal,
        InodeNumber = ino.Number,
        StoredSize = ino.Size,
        PlainSize = ino.SizeCompressed == 0 ? ino.Size : ino.SizeCompressed,
        Flags = (uint)ino.Flags,
        Mode = (ushort)ino.Mode,
        Nlink = ino.Nlink,
        StartBlock = ino.StartBlock,
        Blocks = ino.Blocks,
        Compressed = (ino.Flags & ProsperoInodeFlags.compressed) != 0,
    };

    static ProsperoPfsImageNode ImageNodeFromDir(ProsperoFsDir dir)
    {
        var node = ImageNodeFromFsNode(dir, isDir: true);
        foreach (var d in dir.Dirs.OrderBy(d => d.name, StringComparer.Ordinal))
            node.Children.Add(ImageNodeFromDir(d));
        // Files whose sce_sys path is a known outer-CNT entry are filtered out of the inner image in
        // Setup() (they receive no inode and no dirent), yet they linger in the in-memory FSDir.Files
        // list. Skip any file that never got an inode so the snapshot mirrors the materialized image
        // rather than the pre-filter tree (otherwise such a node would collide on inode 0).
        foreach (var f in dir.Files.Where(f => f.ino != null).OrderBy(f => f.name, StringComparer.Ordinal))
            node.Children.Add(ImageNodeFromFsNode(f, isDir: false));
        return node;
    }

    static ProsperoPfsImageNode ImageNodeFromFsNode(ProsperoFsNode n, bool isDir)
    {
        var ino = n.ino;
        return new ProsperoPfsImageNode
        {
            Name = n.name ?? "",
            IsDirectory = isDir,
            InodeNumber = ino?.Number ?? 0,
            StoredSize = ino?.Size ?? n.Size,
            PlainSize = ino != null ? (ino.SizeCompressed == 0 ? ino.Size : ino.SizeCompressed) : n.CompressedSize,
            Flags = (uint)(ino?.Flags ?? 0),
            Mode = (ushort)(ino?.Mode ?? 0),
            Nlink = ino?.Nlink ?? 0,
            StartBlock = ino?.StartBlock ?? 0,
            Blocks = ino?.Blocks ?? 0,
            Compressed = ino != null && (ino.Flags & ProsperoInodeFlags.compressed) != 0,
        };
    }

    /// <summary>
    /// This gets called by the constructor.
    /// </summary>
    void Setup()
    {
        // Insert header digest to be calculated with the rest of the digests
        final_sigs.Push(new BlockSigInfo(0, 0x380, 0x5A0));
        hdr = new ProsperoPfsHeader
        {
            Version = properties.Version,
            BlockSize = properties.BlockSize,
            ReadOnly = 1,
            Mode = (properties.Sign ? ProsperoPfsMode.Signed : 0)
               | (properties.Encrypt ? ProsperoPfsMode.Encrypted : 0)
               | ProsperoPfsMode.UnknownFlagAlwaysSet,
            UnknownIndex = 1,
            Seed = properties.Encrypt || properties.Sign ? properties.Seed : null
        };
        inodes = new List<ProsperoInode>();

        Log("Setting up filesystem structure...");
        allDirs = properties.root.GetAllChildrenDirs();
        allFiles = properties.root.GetAllChildrenFiles().Where((f) =>
        {
            bool is_sce_sys = false;
            var name = f.name;
            var parent = f.Parent;
            while (parent != null && parent != properties.root)
            {
                if (parent.Parent == properties.root && parent.name == "sce_sys")
                {
                    is_sce_sys = true;
                    break;
                }
                name = parent.name + "/" + name;
                parent = parent.Parent;
            }
            return !is_sce_sys || !PKG.ProsperoCntEntryNames.NameToId.ContainsKey(name);
        }).ToList();
        allNodes = new List<ProsperoFsNode>(allDirs.OrderBy(d => d.FullPath()).ToList());
        allNodes.AddRange(allFiles);

        SetupRootStructure(ProsperoFlatPathTable.HasCollision(allNodes));

        Log($"Creating inodes ({allDirs.Count} dirs and {allFiles.Count} files)...");
        addDirInodes();
        addFileInodes();

        (fpt, colResolver) = ProsperoFlatPathTable.Create(allNodes);

        Log("Calculating data block layout...");
        allNodes.Insert(0, properties.root);
        CalculateDataBlockLayout();
    }

    private void WriteData(Stream stream)
    {
        Log("Writing data...");
        hdr.WriteToStream(stream);
        WriteInodes(stream);
        WriteSuperrootDirents(stream);

        allNodes.Insert(0, new ProsperoFsFile(s => fpt.WriteToStream(s), "flat_path_table", fpt.Size)
        {
            ino = fpt_ino
        });
        if (colResolver != null)
        {
            allNodes.Insert(1, new ProsperoFsFile(s => colResolver.WriteToStream(s), "collision_resolver", colResolver.Size)
            {
                ino = cr_ino
            });
        }

        for (var x = 0; x < allNodes.Count; x++)
        {
            var f = allNodes[x];
            stream.Position = f.ino.StartBlock * hdr.BlockSize;
            WriteFSNode(stream, f);
        }
    }

    /// <summary>
    /// Enumerates the sectors that should be encrypted with AES-XTS
    /// </summary>
    /// <returns>Sector indices</returns>
    private IEnumerable<long> XtsSectorGen()
    {
        long totalSectors = (CalculatePfsSize() + 0xFFF) / xtsSectorSize;
        long xtsSector = 16;
        while (xtsSector < totalSectors)
        {
            if (xtsSector / 0x10 == emptyBlock)
            {
                xtsSector += 16;
            }
            yield return xtsSector;
            xtsSector += 1;
        }
    }

    /// <summary>
    /// Writes the PFS image using a memory mapped file. This allows for parallelization of signing and encrypting.
    /// </summary>
    /// <param name="file">The memory mapped file</param>
    /// <param name="offset">Start offset of the PFS image in the file</param>
    public void WriteImage(MemoryMappedFile file, long offset)
    {
        using (var viewStream = file.CreateViewStream(offset, CalculatePfsSize(), MemoryMappedFileAccess.ReadWrite))
        {
            WriteData(viewStream);
        }
        using (var view = file.CreateViewAccessor(offset, CalculatePfsSize(), MemoryMappedFileAccess.ReadWrite))
        {
            if (hdr.Mode.HasFlag(ProsperoPfsMode.Signed))
            {
                Log("Signing in parallel...");
                var signKey = Crypto.PfsGenSignKey(properties.EKPFS, hdr.Seed);
                // We can do the actual data blocks in parallel
                Parallel.ForEach(
                  data_sigs,
                  () => Tuple.Create(new byte[properties.BlockSize], new HMACSHA256(signKey)),
                  (sig, status, local) =>
                  {
                      var (sig_buffer, hmac) = local;
                      var position = sig.Block * sig_buffer.Length;
                      view.ReadArray(position, sig_buffer, 0, sig_buffer.Length);
                      position = sig.SigOffset;
                      view.WriteArray(position, Crypto.HmacSha256(signKey, sig_buffer), 0, 32);
                      view.Write(position + 32, (int)sig.Block);
                      return local;
                  },
                  local => local.Item2.Dispose());
                // The indirect blocks must be done after, since they rely on data block signatures
                foreach (var sig in final_sigs)
                {
                    var sig_buffer = new byte[sig.Size];
                    var position = sig.Block * properties.BlockSize;
                    view.ReadArray(position, sig_buffer, 0, sig_buffer.Length);
                    position = sig.SigOffset;
                    view.WriteArray(position, Crypto.HmacSha256(signKey, sig_buffer), 0, 32);
                    view.Write(position + 32, (int)sig.Block);
                }
            }

            if (hdr.Mode.HasFlag(ProsperoPfsMode.Encrypted))
            {
                Log("Encrypting in parallel...");
                var (tweakKey, dataKey) = Crypto.PfsGenEncKey(properties.EKPFS, hdr.Seed);
                Parallel.ForEach(
                  // generates sector indices for each sector to be encrypted
                  XtsSectorGen(),
                  // generates thread-local data
                  () => Tuple.Create(new XtsBlockTransform(dataKey, tweakKey), new byte[xtsSectorSize]),
                  // Loop body
                  (xtsSector, loopState, localData) =>
                  {
                      var (transformer, sectorBuffer) = localData;
                      var sectorOffset = xtsSector * xtsSectorSize;
                      view.ReadArray(sectorOffset, sectorBuffer, 0, xtsSectorSize);
                      transformer.EncryptSector(sectorBuffer, (ulong)xtsSector);
                      view.WriteArray(sectorOffset, sectorBuffer, 0, xtsSectorSize);
                      return localData;
                  },
                  // Finalizer
                  local => { });
            }
        }
    }

    /// <summary>
    /// Writes the PFS image to the given stream
    /// </summary>
    public void WriteImage(Stream stream)
    {
        WriteData(stream);

        if (hdr.Mode.HasFlag(ProsperoPfsMode.Signed))
        {
            Log("Signing...");
            var signKey = Crypto.PfsGenSignKey(properties.EKPFS, hdr.Seed);
            foreach (var sig in data_sigs.Concat(final_sigs))
            {
                var sig_buffer = new byte[sig.Size];
                stream.Position = sig.Block * properties.BlockSize;
                stream.ReadExactly(sig_buffer, 0, sig.Size);
                stream.Position = sig.SigOffset;
                byte[] mac = Crypto.HmacSha256(signKey, sig_buffer);
                stream.Write(mac, 0, 32);
                stream.WriteLE((int)sig.Block);
                // The superblock self-signature (block 0 @ 0x380) is this image's integrity value,
                // surfaced for the supplemental pfsimage.xml <icv> element.
                if (CaptureSuperblockIcv && sig.Block == 0 && sig.SigOffset == 0x380)
                    SuperblockIcv = mac;
            }
        }

        if (CaptureImageDigests && hdr.Mode.HasFlag(ProsperoPfsMode.Signed))
        {
            // sce_sys/imagedigs.dat preimage: one per-block descriptor digest for every block
            // of the plaintext signed image (captured here, before XTS encryption), stored from last
            // byte to first. The PS5 image builder gathers the signer's per-block HMAC-SHA256
            // descriptor digests and writes each digest from byte 31 down to byte 0; reproduced from
            // this image's own signing key.
            var idKey = Crypto.PfsGenSignKey(properties.EKPFS, hdr.Seed);
            int bs = (int)properties.BlockSize;
            int idCount = (int)(CalculatePfsSize() / bs);
            var digs = new byte[idCount * 32];
            var blockBuf = new byte[bs];
            for (int i = 0; i < idCount; i++)
            {
                stream.Position = (long)i * bs;
                stream.ReadExactly(blockBuf);
                byte[] h = Crypto.HmacSha256(idKey, blockBuf);
                Array.Reverse(h);
                h.CopyTo(digs, i * 32);
            }
            ImageDigests = digs;
        }

        if (hdr.Mode.HasFlag(ProsperoPfsMode.Encrypted))
        {
            Log("Encrypting...");
            var (tweakKey, dataKey) = Crypto.PfsGenEncKey(properties.EKPFS, hdr.Seed);
            var transformer = new XtsBlockTransform(dataKey, tweakKey);
            byte[] sectorBuffer = new byte[xtsSectorSize];
            foreach (var xtsSector in XtsSectorGen())
            {
                stream.Position = xtsSector * xtsSectorSize;
                stream.ReadExactly(sectorBuffer, 0, xtsSectorSize);
                transformer.EncryptSector(sectorBuffer, (ulong)xtsSector);
                stream.Position = xtsSector * xtsSectorSize;
                stream.Write(sectorBuffer, 0, xtsSectorSize);
            }
        }
    }

    /// <summary>
    /// Adds inodes for each dir.
    /// </summary>
    void addDirInodes()
    {
        inodes.Add(properties.root.ino);
        foreach (var dir in allDirs.OrderBy(x => x.FullPath()))
        {
            var ino = MakeInode(
              Mode: ProsperoInodeMode.dir | ProsperoInode.RXOnly,
              Number: (uint)inodes.Count,
              Blocks: 1,
              Size: 65536,
              Flags: ProsperoInodeFlags.@readonly,
              Nlink: 2 // 1 link each for its own dirent and its . dirent
            );
            dir.ino = ino;
            dir.Dirents.Add(new ProsperoPfsDirent { Name = ".", InodeNumber = ino.Number, Type = ProsperoDirentType.Dot });
            dir.Dirents.Add(new ProsperoPfsDirent { Name = "..", InodeNumber = dir.Parent.ino.Number, Type = ProsperoDirentType.DotDot });

            var dirent = new ProsperoPfsDirent { Name = dir.name, InodeNumber = (uint)inodes.Count, Type = ProsperoDirentType.Directory };
            dir.Parent.Dirents.Add(dirent);
            dir.Parent.ino.Nlink++;
            inodes.Add(ino);
        }
    }

    /// <summary>
    /// Adds inodes for each file.
    /// </summary>
    void addFileInodes()
    {
        foreach (var file in allFiles.OrderBy(x => x.FullPath()))
        {
            var ino = MakeInode(
              Mode: ProsperoInodeMode.file | ProsperoInode.RXOnly,
              Size: file.Size,
              SizeCompressed: file.CompressedSize,
              Number: (uint)inodes.Count,
              Blocks: (uint)CeilDiv(file.Size, hdr.BlockSize),
              Flags: ProsperoInodeFlags.@readonly | (file.Compress ? ProsperoInodeFlags.compressed : 0)
            );
            if (properties.Sign) // Outer PFS images clear the readonly flag.
            {
                ino.Flags &= ~ProsperoInodeFlags.@readonly;
            }
            file.ino = ino;
            var dirent = new ProsperoPfsDirent { Name = file.name, Type = ProsperoDirentType.File, InodeNumber = (uint)inodes.Count };
            file.Parent.Dirents.Add(dirent);
            inodes.Add(ino);
        }
    }

    long roundUpSizeToBlock(long size) => CeilDiv(size, hdr.BlockSize) * hdr.BlockSize;
    long calculateIndirectBlocks(long size)
    {
        var sigs_per_block = hdr.BlockSize / 36;
        var blocks = CeilDiv(size, hdr.BlockSize);
        var ib = 0L;
        if (blocks > 12)
        {
            blocks -= 12;
            ib++;
        }
        if (blocks > sigs_per_block)
        {
            blocks -= sigs_per_block;
            ib += 1 + CeilDiv(blocks, sigs_per_block);
        }
        return ib;
    }

    ///<summary>
    ///Given an inode number and an index into the db[] array, returns the absolute offset of that array value
    ///</summary>
    long inoNumberToOffset(uint number, int db = 0)
      => hdr.BlockSize + (ProsperoDinodeS32.SizeOf * number) + 0x64 + (36 * db);

    /// <summary>
    /// Sets the data blocks. Also updates header for total number of data blocks.
    /// </summary>
    void CalculateDataBlockLayout()
    {
        if (properties.Sign)
        {
            // Include the header block in the total count
            hdr.Ndblock = 1;
            var inodesPerBlock = hdr.BlockSize / ProsperoDinodeS32.SizeOf;
            hdr.DinodeCount = inodes.Count;
            hdr.DinodeBlockCount = CeilDiv(inodes.Count, inodesPerBlock);
            hdr.InodeBlockSig.Blocks = (uint)hdr.DinodeBlockCount;
            hdr.InodeBlockSig.Size = hdr.DinodeBlockCount * hdr.BlockSize;
            hdr.InodeBlockSig.SizeCompressed = hdr.DinodeBlockCount * hdr.BlockSize;
            hdr.InodeBlockSig.SetTime(properties.FileTime);
            hdr.InodeBlockSig.Flags = 0;
            for (var i = 0; i < hdr.DinodeBlockCount; i++)
            {
                hdr.InodeBlockSig.SetDirectBlock(i, 1 + i);
                final_sigs.Push(new BlockSigInfo(1 + i, 0xB8 + (36 * i)));
            }
            hdr.Ndblock += hdr.DinodeBlockCount;
            super_root_ino.SetDirectBlock(0, (int)(hdr.DinodeBlockCount + 1));
            final_sigs.Push(new BlockSigInfo(super_root_ino.StartBlock, inoNumberToOffset(super_root_ino.Number)));
            hdr.Ndblock += super_root_ino.Blocks;

            // flat path table
            fpt_ino.SetDirectBlock(0, super_root_ino.StartBlock + 1);
            fpt_ino.Size = fpt.Size;
            fpt_ino.SizeCompressed = fpt.Size;
            fpt_ino.Blocks = (uint)CeilDiv(fpt.Size, hdr.BlockSize);
            final_sigs.Push(new BlockSigInfo(fpt_ino.StartBlock, inoNumberToOffset(fpt_ino.Number)));

            for (int i = 1; i < fpt_ino.Blocks && i < 12; i++)
            {
                fpt_ino.SetDirectBlock(i, (int)hdr.Ndblock++);
                final_sigs.Push(new BlockSigInfo(fpt_ino.StartBlock, inoNumberToOffset(fpt_ino.Number, i)));
            }

            // An empty block follows the flat path table.
            hdr.Ndblock++;
            // The outer PFS reserves an unencrypted zero block here.
            emptyBlock = (int)hdr.Ndblock;
            hdr.Ndblock++;

            var ibStartBlock = hdr.Ndblock;
            hdr.Ndblock += allNodes.Select(s => calculateIndirectBlocks(s.Size)).Sum();

            var sigs_per_block = hdr.BlockSize / 36;
            // Fill in DB/IB pointers
            foreach (var n in allNodes)
            {
                var blocks = CeilDiv(n.Size, hdr.BlockSize);
                n.ino.SetDirectBlock(0, (int)hdr.Ndblock);
                n.ino.Blocks = (uint)blocks;
                n.ino.Size = n is ProsperoFsDir ? roundUpSizeToBlock(n.Size) : n.Size;
                if (n.ino.SizeCompressed == 0)
                    n.ino.SizeCompressed = n.ino.Size;

                for (var i = 0; (blocks - i) > 0 && i < 12; i++)
                {
                    data_sigs.Push(new BlockSigInfo((int)hdr.Ndblock++, inoNumberToOffset(n.ino.Number, i)));
                }
                if (blocks > 12)
                {
                    // More than 12 blocks -> use 1 indirect block
                    // ib[0]
                    final_sigs.Push(new BlockSigInfo(ibStartBlock, inoNumberToOffset(n.ino.Number, 12)));
                    for (int i = 12, pointerOffset = 0; (blocks - i) > 0 && i < (12 + sigs_per_block); i++, pointerOffset += 36)
                    {
                        // ib[0][i]
                        data_sigs.Push(new BlockSigInfo((int)hdr.Ndblock++, ibStartBlock * hdr.BlockSize + pointerOffset));
                    }
                    ibStartBlock++;
                }
                if (blocks > 12 + sigs_per_block)
                {
                    uint blockSigsDone = 12 + sigs_per_block;
                    // More than 12 + one block of pointers -> use 1 doubly-indirect block + any number of indirect blocks
                    // ib[1] = signature for block of signatures for block of signatures for data blocks
                    final_sigs.Push(new BlockSigInfo(ibStartBlock, inoNumberToOffset(n.ino.Number, 13)));
                    var ib_1_block = ibStartBlock;
                    for (var i = 0; i < sigs_per_block && blockSigsDone < blocks; i++)
                    {
                        // ib[1][i] = signature for block of signatures for data blocks
                        final_sigs.Push(new BlockSigInfo((int)++ibStartBlock, ib_1_block * hdr.BlockSize + i * 36));
                        for (int j = 0; j < sigs_per_block && blockSigsDone < blocks; j++, blockSigsDone++)
                        {
                            // ib[1][i][j] = signature for data block
                            data_sigs.Push(new BlockSigInfo((int)hdr.Ndblock++, ibStartBlock * hdr.BlockSize + (j * 36)));
                        }
                    }
                }
            }
        }
        else
        {
            // Include the header block in the total count
            hdr.Ndblock = 1;
            var inodesPerBlock = hdr.BlockSize / ProsperoDinodeD32.SizeOf;
            hdr.DinodeCount = inodes.Count;
            hdr.DinodeBlockCount = CeilDiv(inodes.Count, inodesPerBlock);
            hdr.InodeBlockSig.Blocks = (uint)hdr.DinodeBlockCount;
            hdr.InodeBlockSig.Size = hdr.DinodeBlockCount * hdr.BlockSize;
            hdr.InodeBlockSig.SizeCompressed = hdr.DinodeBlockCount * hdr.BlockSize;
            hdr.InodeBlockSig.SetDirectBlock(0, (int)hdr.Ndblock++);
            hdr.InodeBlockSig.SetTime(properties.FileTime);
            for (var i = 1; i < hdr.DinodeBlockCount; i++)
            {
                if (i < 12)
                    hdr.InodeBlockSig.SetDirectBlock(i, -1);
                hdr.Ndblock++;
            }
            super_root_ino.SetDirectBlock(0, (int)hdr.Ndblock);
            hdr.Ndblock += super_root_ino.Blocks;

            // flat path table
            fpt_ino.SetDirectBlock(0, (int)hdr.Ndblock++);
            fpt_ino.Size = fpt.Size;
            fpt_ino.SizeCompressed = fpt.Size;
            fpt_ino.Blocks = (uint)CeilDiv(fpt.Size, hdr.BlockSize);

            for (int i = 1; i < fpt_ino.Blocks && i < 12; i++)
                fpt_ino.SetDirectBlock(i, (int)hdr.Ndblock++);

            // An empty block follows the flat path table when no collision resolver is present.
            if (cr_ino == null)
            {
                hdr.Ndblock++;
            }
            else
            {
                // collision resolver
                cr_ino.SetDirectBlock(0, (int)hdr.Ndblock++);
                cr_ino.Size = colResolver.Size;
                cr_ino.SizeCompressed = colResolver.Size;
                cr_ino.Blocks = (uint)CeilDiv(colResolver.Size, hdr.BlockSize);

                for (int i = 1; i < cr_ino.Blocks && i < 12; i++)
                    cr_ino.SetDirectBlock(i, (int)hdr.Ndblock++);
            }

            // Calculate length of all dirent blocks
            foreach (var n in allNodes)
            {
                var blocks = CeilDiv(n.Size, hdr.BlockSize);
                n.ino.SetDirectBlock(0, (int)hdr.Ndblock);
                n.ino.Blocks = (uint)blocks;
                n.ino.Size = n is ProsperoFsDir ? roundUpSizeToBlock(n.Size) : n.Size;
                if (n.ino.SizeCompressed == 0)
                    n.ino.SizeCompressed = n.ino.Size;
                for (int i = 1; i < blocks && i < 12; i++)
                {
                    n.ino.SetDirectBlock(i, -1);
                }
                hdr.Ndblock += blocks;
            }
        }
        // Enforce the configured minimum PFS image size.
        hdr.Ndblock = Math.Max(hdr.Ndblock, properties.MinBlocks);
    }

    ProsperoInode MakeInode(ProsperoInodeMode Mode, uint Blocks, long Size = 0, long SizeCompressed = 0, ushort Nlink = 1, uint Number = 0, ProsperoInodeFlags Flags = 0)
    {
        ProsperoInode ret;
        if (properties.Sign)
        {
            ret = new ProsperoDinodeS32()
            {
                Mode = Mode,
                Blocks = Blocks,
                Size = Size,
                SizeCompressed = SizeCompressed,
                Nlink = Nlink,
                Number = Number,
                Flags = Flags | ProsperoInodeFlags.unk2 | ProsperoInodeFlags.unk3,
            };
        }
        else
        {
            ret = new ProsperoDinodeD32()
            {
                Mode = Mode,
                Blocks = Blocks,
                Size = Size,
                SizeCompressed = SizeCompressed,
                Nlink = Nlink,
                Number = Number,
                Flags = Flags
            };
        }
        ret.SetTime(properties.FileTime);
        return ret;
    }

    /// <summary>
    /// Creates inodes and dirents for superroot, flat_path_table, and uroot.
    /// Also, creates the root node for the FS tree.
    /// </summary>
    void SetupRootStructure(bool hasCollision)
    {
        var inodeNum = 0u;
        inodes.Add(super_root_ino = MakeInode(
          Mode: ProsperoInodeMode.dir | ProsperoInode.RXOnly,
          Blocks: 1,
          Size: 65536,
          SizeCompressed: 65536,
          Nlink: 1,
          Number: inodeNum++,
          Flags: ProsperoInodeFlags.@internal | ProsperoInodeFlags.@readonly
        ));
        inodes.Add(fpt_ino = MakeInode(
          Mode: ProsperoInodeMode.file | ProsperoInode.RXOnly,
          Blocks: 1,
          Number: inodeNum++,
          Flags: ProsperoInodeFlags.@internal | ProsperoInodeFlags.@readonly
        ));
        if (hasCollision)
        {
            inodes.Add(cr_ino = MakeInode(
              Mode: ProsperoInodeMode.file | ProsperoInode.RXOnly,
              Blocks: 1,
              Number: inodeNum++,
              Flags: ProsperoInodeFlags.@internal | ProsperoInodeFlags.@readonly
            ));
        }
        var uroot_ino = MakeInode(
          Mode: ProsperoInodeMode.dir | ProsperoInode.RXOnly,
          Number: inodeNum++,
          Size: 65536,
          SizeCompressed: 65536,
          Blocks: 1,
          Flags: ProsperoInodeFlags.@readonly,
          Nlink: 3
        );

        super_root_dirents = new List<ProsperoPfsDirent>
  {
    new ProsperoPfsDirent { InodeNumber = fpt_ino.Number, Name = "flat_path_table", Type = ProsperoDirentType.File },
  };
        if (hasCollision)
        {
            super_root_dirents.Add(
              new ProsperoPfsDirent { InodeNumber = cr_ino.Number, Name = "collision_resolver", Type = ProsperoDirentType.File });
        }
        super_root_dirents.Add(
          new ProsperoPfsDirent { InodeNumber = uroot_ino.Number, Name = "uroot", Type = ProsperoDirentType.Directory });

        properties.root.name = "uroot";
        properties.root.ino = uroot_ino;
        properties.root.Dirents = new List<ProsperoPfsDirent>
  {
    new ProsperoPfsDirent { Name = ".", Type = ProsperoDirentType.Dot, InodeNumber = uroot_ino.Number },
    new ProsperoPfsDirent { Name = "..", Type = ProsperoDirentType.DotDot, InodeNumber = uroot_ino.Number }
  };
        if (properties.Sign) // Outer PFS clears readonly flags.
        {
            super_root_ino.Flags &= ~ProsperoInodeFlags.@readonly;
            fpt_ino.Flags &= ~ProsperoInodeFlags.@readonly;
            uroot_ino.Flags &= ~ProsperoInodeFlags.@readonly;
        }
    }

    /// <summary>
    /// Writes all the inodes to the image file. 
    /// </summary>
    /// <param name="s"></param>
    void WriteInodes(Stream s)
    {
        s.Position = hdr.BlockSize;
        foreach (var di in inodes)
        {
            di.WriteToStream(s);
            if (s.Position % hdr.BlockSize > hdr.BlockSize - (properties.Sign ? ProsperoDinodeS32.SizeOf : ProsperoDinodeD32.SizeOf))
            {
                s.Position += hdr.BlockSize - (s.Position % hdr.BlockSize);
            }
        }
    }

    /// <summary>
    /// Writes the dirents for the superroot, which precede the flat_path_table.
    /// </summary>
    /// <param name="stream"></param>
    void WriteSuperrootDirents(Stream stream)
    {
        stream.Position = hdr.BlockSize * (hdr.DinodeBlockCount + 1);
        foreach (var d in super_root_dirents)
        {
            d.WriteToStream(stream);
        }
    }

    /// <summary>
    /// Writes all the data blocks.
    /// </summary>
    /// <param name="s"></param>
    /// <param name="f"></param>
    void WriteFSNode(Stream s, ProsperoFsNode f)
    {
        if (f is ProsperoFsDir)
        {
            var dir = (ProsperoFsDir)f;
            var startBlock = f.ino.StartBlock;
            foreach (var d in dir.Dirents)
            {
                d.WriteToStream(s);
                if (s.Position % hdr.BlockSize > hdr.BlockSize - ProsperoPfsDirent.MaxSize)
                {
                    s.Position = (++startBlock * hdr.BlockSize);
                }
            }
        }
        else if (f is ProsperoFsFile)
        {
            var file = (ProsperoFsFile)f;
            file.Write(s);
        }
    }
}
