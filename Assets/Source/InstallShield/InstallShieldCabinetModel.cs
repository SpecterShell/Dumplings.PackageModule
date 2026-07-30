// SPDX-License-Identifier: Apache-2.0
// InstallShield cabinet handling is derived from MIT-licensed Unshield.
// Source: https://github.com/twogood/unshield

namespace Dumplings.InstallShield
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
    using System.Security.Cryptography;
    using System.Text;

    public sealed class InstallShieldCabinetEntry
    {
        internal InstallShieldCabinetEntry(
            int index,
            string name,
            string directory,
            ushort flags,
            long expandedSize,
            long compressedSize,
            long dataOffset,
            byte[] md5,
            ushort volume,
            uint linkPrevious,
            uint linkNext,
            byte linkFlags)
        {
            Index = index;
            Name = name;
            Directory = directory;
            Flags = flags;
            ExpandedSize = expandedSize;
            CompressedSize = compressedSize;
            DataOffset = dataOffset;
            Md5 = md5;
            Volume = volume;
            LinkPrevious = linkPrevious;
            LinkNext = linkNext;
            LinkFlags = linkFlags;
        }

        public int Index { get; private set; }
        public string Name { get; private set; }
        public string Directory { get; private set; }
        public ushort Flags { get; private set; }
        public long ExpandedSize { get; private set; }
        public long CompressedSize { get; private set; }
        public long DataOffset { get; private set; }
        public byte[] Md5 { get; private set; }
        public ushort Volume { get; private set; }
        public uint LinkPrevious { get; private set; }
        public uint LinkNext { get; private set; }
        public byte LinkFlags { get; private set; }
        public bool IsCompressed { get { return (Flags & 4) != 0; } }
        public bool IsObfuscated { get { return (Flags & 2) != 0; } }
        public bool IsSplit { get { return (Flags & 1) != 0; } }
        public bool IsValid { get { return (Flags & 8) == 0 && DataOffset > 0 && !string.IsNullOrWhiteSpace(Name); } }
    }

    /// <summary>
    /// One project Component-table name and its contiguous cabinet file range.
    /// InstallShield calls this record a file group in the ISc( descriptor.
    /// </summary>
    public sealed class InstallShieldCabinetFileGroup
    {
        internal InstallShieldCabinetFileGroup(string name, int firstFileIndex, int lastFileIndex)
        {
            Name = name;
            FirstFileIndex = firstFileIndex;
            LastFileIndex = lastFileIndex;
        }

        public string Name { get; private set; }
        public int FirstFileIndex { get; private set; }
        public int LastFileIndex { get; private set; }
    }

    /// <summary>
    /// One InstallShield feature path and the project components transferred
    /// with it. The binary format calls this record a component.
    /// </summary>
    public sealed class InstallShieldCabinetComponent
    {
        internal InstallShieldCabinetComponent(string name, List<string> fileGroups)
        {
            Name = name;
            FileGroups = fileGroups;
        }

        public string Name { get; private set; }
        public List<string> FileGroups { get; private set; }
    }

    /// <summary>One locale-specific setup type and its included feature paths.</summary>
    public sealed class InstallShieldMediaSetupType
    {
        internal InstallShieldMediaSetupType(
            uint language,
            int ordinal,
            string name,
            string description,
            string displayName,
            List<string> features)
        {
            Language = language;
            Ordinal = ordinal;
            Name = name;
            Description = description;
            DisplayName = displayName;
            Features = features;
        }

        public uint Language { get; private set; }
        public int Ordinal { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }
        public string DisplayName { get; private set; }
        public List<string> Features { get; private set; }
    }

    /// <summary>One component-scoped registry set stored in InstallScript media.</summary>
    public sealed class InstallShieldMediaRegistrySet
    {
        internal InstallShieldMediaRegistrySet(string qualifiedName, string name, bool isDefault, List<string> components)
        {
            QualifiedName = qualifiedName;
            Name = name;
            IsDefault = isDefault;
            Components = components;
        }

        public string QualifiedName { get; private set; }
        public string Name { get; private set; }
        public bool IsDefault { get; private set; }
        public List<string> Components { get; private set; }
    }

    /// <summary>One literal registry value authored in an InstallScript registry set.</summary>
    public sealed class InstallShieldMediaRegistryWrite
    {
        internal InstallShieldMediaRegistryWrite(
            string root,
            string key,
            string name,
            string type,
            ushort typeCode,
            object data,
            string registrySet,
            string qualifiedRegistrySet,
            bool isDefaultSet,
            List<string> components,
            List<string> features,
            List<string> setupTypes,
            bool complete)
        {
            Root = root;
            Key = key;
            Name = name;
            Type = type;
            TypeCode = typeCode;
            Data = data;
            RegistrySet = registrySet;
            QualifiedRegistrySet = qualifiedRegistrySet;
            IsDefaultSet = isDefaultSet;
            Components = components;
            Features = features;
            SetupTypes = setupTypes;
            Complete = complete;
        }

        public string Root { get; private set; }
        public string Key { get; private set; }
        public string Name { get; private set; }
        public string Type { get; private set; }
        public ushort TypeCode { get; private set; }
        public object Data { get; private set; }
        public string RegistrySet { get; private set; }
        public string QualifiedRegistrySet { get; private set; }
        public bool IsDefaultSet { get; private set; }
        public List<string> Components { get; private set; }
        public List<string> Features { get; private set; }
        public List<string> SetupTypes { get; private set; }
        public bool Complete { get; private set; }
    }

    /// <summary>One media-authored shell folder and its contained shortcuts.</summary>
    public sealed class InstallShieldMediaShellFolder
    {
        internal InstallShieldMediaShellFolder(string installShieldName, string directoryName, List<InstallShieldMediaShortcut> shortcuts)
        {
            InstallShieldName = installShieldName;
            DirectoryName = directoryName;
            Shortcuts = shortcuts;
        }

        public string InstallShieldName { get; private set; }
        public string DirectoryName { get; private set; }
        public List<InstallShieldMediaShortcut> Shortcuts { get; private set; }
    }

    /// <summary>Verified fields from one packed InstallScript shortcut record.</summary>
    public sealed class InstallShieldMediaShortcut
    {
        internal InstallShieldMediaShortcut(
            string name,
            string installShieldName,
            string target,
            string arguments,
            string workingDirectory,
            string component,
            string folder,
            string encodedProperties,
            int? hotKey,
            uint showCommand,
            List<string> features,
            List<string> setupTypes)
        {
            Name = name;
            InstallShieldName = installShieldName;
            Target = target;
            Arguments = arguments;
            WorkingDirectory = workingDirectory;
            Component = component;
            Folder = folder;
            EncodedProperties = encodedProperties;
            HotKey = hotKey;
            ShowCommand = showCommand;
            Features = features;
            SetupTypes = setupTypes;
        }

        public string Name { get; private set; }
        public string InstallShieldName { get; private set; }
        public string Target { get; private set; }
        public string Arguments { get; private set; }
        public string WorkingDirectory { get; private set; }
        public string Component { get; private set; }
        public string Folder { get; private set; }
        public string EncodedProperties { get; private set; }
        public int? HotKey { get; private set; }
        public uint ShowCommand { get; private set; }
        public List<string> Features { get; private set; }
        public List<string> SetupTypes { get; private set; }
    }

    /// <summary>Bounded InstallScript authoring records recovered from one data*.hdr.</summary>
    public sealed class InstallShieldMediaMetadata
    {
        internal InstallShieldMediaMetadata(string headerPath, int majorVersion)
        {
            HeaderPath = headerPath;
            MajorVersion = majorVersion;
            RegistrySets = new List<InstallShieldMediaRegistrySet>();
            RegistryWrites = new List<InstallShieldMediaRegistryWrite>();
            FileGroups = new List<InstallShieldCabinetFileGroup>();
            Components = new List<InstallShieldCabinetComponent>();
            SetupTypes = new List<InstallShieldMediaSetupType>();
            ShellFolders = new List<InstallShieldMediaShellFolder>();
            Shortcuts = new List<InstallShieldMediaShortcut>();
            Warnings = new List<string>();
        }

        public string HeaderPath { get; private set; }
        public int MajorVersion { get; private set; }
        public List<InstallShieldMediaRegistrySet> RegistrySets { get; private set; }
        public List<InstallShieldMediaRegistryWrite> RegistryWrites { get; private set; }
        public List<InstallShieldCabinetFileGroup> FileGroups { get; private set; }
        public List<InstallShieldCabinetComponent> Components { get; private set; }
        public List<InstallShieldMediaSetupType> SetupTypes { get; private set; }
        public List<InstallShieldMediaShellFolder> ShellFolders { get; private set; }
        public List<InstallShieldMediaShortcut> Shortcuts { get; private set; }
        public List<string> Warnings { get; private set; }
    }

    /// <summary>Catalog entries and media metadata decoded from one bounded header read.</summary>
    public sealed class InstallShieldCabinetInspection
    {
        internal InstallShieldCabinetInspection(List<InstallShieldCabinetEntry> entries, InstallShieldMediaMetadata mediaMetadata)
        {
            Entries = entries;
            MediaMetadata = mediaMetadata;
        }

        public List<InstallShieldCabinetEntry> Entries { get; private set; }
        public InstallShieldMediaMetadata MediaMetadata { get; private set; }
    }

    /// <summary>
    /// Reads bounded InstallShield 6+ cabinet catalogs and selected entries.
    /// The caller owns destination selection and safe-path/collision policy.
    /// </summary>
}
