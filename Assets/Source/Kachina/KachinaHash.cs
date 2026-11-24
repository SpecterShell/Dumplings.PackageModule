// SPDX-License-Identifier: Apache-2.0

using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using Standart.Hash.xxHash;

namespace Dumplings.Kachina
{
    /// <summary>Computes the source-defined Kachina XXH3-128 digest without buffering a payload.</summary>
    public static unsafe class KachinaHash
    {
        /// <summary>
        /// Hashes one resolved file with seed zero and formats the numeric UInt128 exactly like
        /// Rust's lower-hex formatter used by Kachina.
        /// </summary>
        public static string ComputeXxHash3_128(string path)
        {
            if (path == null) { throw new ArgumentNullException(nameof(path)); }
            string fullPath = Path.GetFullPath(path);
            FileInfo file = new FileInfo(fullPath);
            if (!file.Exists) { throw new FileNotFoundException("The Kachina payload does not exist.", fullPath); }
            if (file.Length > int.MaxValue) { throw new InvalidDataException("XXH3-128 validation is limited to 2147483647-byte payload files."); }

            uint128 hash;
            if (file.Length == 0)
            {
                // The compact upstream implementation expects an address even when length is zero.
                hash = xxHash128.ComputeHash(new byte[1], 0);
            }
            else
            {
                using (MemoryMappedFile mapping = MemoryMappedFile.CreateFromFile(fullPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read))
                using (MemoryMappedViewAccessor view = mapping.CreateViewAccessor(0, file.Length, MemoryMappedFileAccess.Read))
                {
                    byte* pointer = null;
                    try
                    {
                        view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
                        pointer += view.PointerOffset;
                        hash = xxHash128.ComputeHash(new ReadOnlySpan<byte>(pointer, checked((int)file.Length)), checked((int)file.Length));
                    }
                    finally
                    {
                        if (pointer != null) { view.SafeMemoryMappedViewHandle.ReleasePointer(); }
                    }
                }
            }

            return hash.high64 == 0
                ? hash.low64.ToString("x")
                : hash.high64.ToString("x") + hash.low64.ToString("x16");
        }
    }
}
