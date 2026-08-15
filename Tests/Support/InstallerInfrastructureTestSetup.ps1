# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  if (-not ([Management.Automation.PSTypeName]'Dumplings.Tests.VirtualLargeReadStream').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;

namespace Dumplings.Tests
{
    // Exposes a small real prefix followed by sparse zero bytes so tests can
    // model multi-gigabyte PE overlays without allocating or writing them.
    public sealed class VirtualLargeReadStream : Stream
    {
        private readonly byte[] prefix;
        private readonly long length;
        private long position;

        public VirtualLargeReadStream(byte[] prefix, long length)
        {
            this.prefix = prefix ?? throw new ArgumentNullException(nameof(prefix));
            if (length < prefix.LongLength) throw new ArgumentOutOfRangeException(nameof(length));
            this.length = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position
        {
            get => position;
            set
            {
                if (value < 0 || value > length) throw new ArgumentOutOfRangeException(nameof(value));
                position = value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException();
            if (position >= length || count == 0) return 0;

            int total = (int)Math.Min((long)count, length - position);
            int fromPrefix = position < prefix.LongLength
                ? (int)Math.Min((long)total, prefix.LongLength - position)
                : 0;
            if (fromPrefix > 0) Buffer.BlockCopy(prefix, checked((int)position), buffer, offset, fromPrefix);
            if (fromPrefix < total) Array.Clear(buffer, offset + fromPrefix, total - fromPrefix);
            position += total;
            return total;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long next = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(position + offset),
                SeekOrigin.End => checked(length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            Position = next;
            return position;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
'@
  }
  $Script:TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) 'DumplingsCommonInstallerInfrastructureTests'
  $null = New-Item -ItemType Directory -Path $Script:TemporaryRoot -Force
}

AfterAll {
  if (Test-Path -LiteralPath $Script:TemporaryRoot) { Remove-Item -LiteralPath $Script:TemporaryRoot -Recurse -Force }
}
