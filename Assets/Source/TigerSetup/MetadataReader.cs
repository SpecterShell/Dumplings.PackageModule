// SPDX-License-Identifier: Apache-2.0
// Wire schema grounded in the MIT-licensed rkozlowski/TigerSetup proto/tigersetup.proto
// (0ae38de44e37f0c98fc764c7cd33a278b45616c6). No assembly or payload is executed.
// Protobuf: tag varint = field_number << 3 | wire_type; wire 0 = varint,
// wire 1 = 8 bytes, wire 2 = length varint + bytes, wire 5 = 4 bytes LE.
// The explicit schema prevents binary submessages from being mistaken for UTF-8 text.
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Buffers;
using System.Security.Cryptography;

namespace Dumplings.TigerSetup
{
    public static class MetadataReader
    {
        private sealed class Field
        {
            public string Name, Type;
            public bool Repeated;
        }
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        private static readonly Dictionary<string, Dictionary<int, Field>> Schema = BuildSchema();
        private static readonly uint[] CrcTable = BuildCrcTable();

        private static uint[] BuildCrcTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < table.Length; i++) {
                uint crc = i;
                for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xEDB88320u : 0u);
                table[i] = crc;
            }
            return table;
        }

        /// <summary>Verify a borrowed bounded entry stream in one sequential read; leave it open at EOF.</summary>
        /// <param name="source">Entry-limited stream positioned at its beginning; ownership stays with the caller.</param>
        /// <param name="length">Exact expanded byte count, including zero-length files.</param>
        /// <param name="expectedCrc">IEEE CRC32 of the complete entry.</param>
        /// <param name="expectedHash">Hex SHA256, or null for ZIP generations without a metadata hash witness.</param>
        public static void VerifyEntry(Stream source, long length, uint expectedCrc, string expectedHash)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(65536);
            try {
                using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)) {
                    uint crc = uint.MaxValue;
                    long remaining = length;
                    while (remaining > 0) {
                        int count = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (count == 0) throw new InvalidDataException("TigerSetup payload length mismatch.");
                        for (int i = 0; i < count; i++) crc = CrcTable[(crc ^ buffer[i]) & 255] ^ (crc >> 8);
                        if (!string.IsNullOrEmpty(expectedHash)) hash.AppendData(buffer, 0, count);
                        remaining -= count;
                    }
                    if (source.ReadByte() != -1) throw new InvalidDataException("TigerSetup payload length mismatch.");
                    if ((crc ^ uint.MaxValue) != expectedCrc) throw new InvalidDataException("TigerSetup payload CRC32 mismatch.");
                    if (!string.IsNullOrEmpty(expectedHash) && !Convert.ToHexString(hash.GetHashAndReset()).Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("TigerSetup payload SHA256 mismatch.");
                }
            } finally { ArrayPool<byte>.Shared.Return(buffer); }
        }

        // Entries are field-number:name:type; '+' means repeated. u/i are 64-bit,
        // U/I are 32-bit (including enums), b Boolean, s UTF-8, x bytes, f fixed32.
        private static Dictionary<string, Dictionary<int, Field>> BuildSchema()
        {
            var result = new Dictionary<string, Dictionary<int, Field>>();
            string[] definitions = {
                "Metadata|1:schema:U 2:package:Package 3:install:Install 4:files:+File 5:directories:+Directory 6:engine:Engine 7:role:I 8:uninstaller_scope:I 9:options:+InstallOption 10:shortcuts:+Shortcut 11:path_entries:+PathEntry 12:registry_values:+RegistryValue 13:registration:Registration 14:legacy:Legacy 15:dependencies:+Dependency 16:environment_variables:+EnvironmentVariable 17:file_associations:+FileAssociation 18:url_protocols:+UrlProtocol 19:app_paths:+AppPath 20:context_menu_verbs:+ContextMenuVerb 21:firewall_rules:+FirewallRule 22:actions:+Action 23:payload:+PayloadEntry 24:quiescence:+Quiescence 25:file_batches:+FileBatch 26:launch:Launch",
                "Package|1:id:s 2:name:s 3:version:s 4:publisher:s 5:description:s 6:copyright:s 7:license:s 8:license_text:s 9:website_url:s 10:support_url:s 11:help_url:s 12:icon:x 13:file_version:s",
                "Install|1:scopes:+I 2:user_root:s 3:machine_root:s 4:minimum_build:U 5:architecture:s 6:estimated_size:u 7:existing_scope:I",
                "File|1:path:s 2:size:u 3:entry:s 4:when:Predicate",
                "Directory|1:path:s",
                "Engine|1:tigersetup_version:s 2:engine_sha256:s 3:engine_block_sha256:s 4:loader_sha256:s 5:loader_block_sha256:s",
                "Registration|1:key_name:s 2:display_name:s 3:display_version:s 4:display_icon:s",
                "PayloadEntry|1:entry:s 2:offset:u 3:length:u 4:crc32:f 5:sha256:s",
                "Predicate|1:option:s 2:equals:s",
                "FileBatch|1:first_file:U 2:file_count:U 3:bytes:u",
                "Launch|1:executable:s 2:arguments:+s 3:working_directory:s 4:checked:b",
                "InstallOption|1:name:s 2:default:b 3:kind:I 4:labels:+Label 5:choices:+OptionChoice 6:default_choice:s",
                "OptionChoice|1:value:s 2:labels:+Label",
                "Label|1:key:s 2:value:s",
                "Shortcut|1:location:I 2:name:s 3:target:s 4:arguments:s 5:description:s 6:icon:s 7:option:s 8:folder:s 9:when:Predicate 10:working_directory:s 11:app_user_model_id:s 12:url:s",
                "PathEntry|1:path:s 2:option:s 3:when:Predicate",
                "RegistryValue|1:key:s 2:name:s 3:kind:I 4:data:s 5:when:Predicate 6:root:I",
                "Legacy|1:installer_type:s 2:registration_key:s",
                "Dependency|1:id:s 2:display_name:s 3:minimum_version:s 4:detect:Detector 5:acquisition:Acquisition 6:install:DependencyInstall 7:elevation_required:b 8:when:Predicate",
                "Detector|1:kind:I 2:path:s 3:keys:+s 4:value:s 5:pattern:s",
                "Acquisition|1:source:I 2:package_identifier:s 3:version:s 4:url:s 5:sha256:s 6:architecture:s 7:resolved_at:i 8:max_age_days:U 9:scope:s 10:installer_type:s 11:entry:s 12:size:u",
                "DependencyInstall|1:arguments:+s 2:success_codes:+I 3:reboot_codes:+I 4:declared:b",
                "EnvironmentVariable|1:name:s 2:value:s 3:expandable:b 4:when:Predicate",
                "FileAssociation|1:prog_id:s 2:extensions:+s 3:description:s 4:icon:s 5:executable:s 6:arguments:s 7:when:Predicate",
                "UrlProtocol|1:scheme:s 2:prog_id:s 3:description:s 4:icon:s 5:executable:s 6:arguments:s 7:when:Predicate",
                "AppPath|1:executable:s 2:add_directory:b 3:when:Predicate",
                "ContextMenuVerb|1:target:I 2:verb:s 3:label:s 4:executable:s 5:arguments:s 6:icon:s 7:extensions:+s 8:when:Predicate",
                "FirewallRule|1:name:s 2:description:s 3:program:s 4:direction:I 5:action:I 6:protocol:I 7:local_ports:s 8:when:Predicate",
                "Action|1:name:s 2:phase:I 3:run_on:+I 4:kind:I 5:command:s 6:entry:s 7:file_name:s 8:size:u 9:sha256:s 10:arguments:+s 11:working_directory:s 12:timeout_seconds:U 13:success_codes:+I 14:reboot_codes:+I 15:on_failure:I 16:when:Predicate",
                "Quiescence|1:name:s 2:run_on:+I 3:stop:Action 4:resume:Action 5:not_running_codes:+I 6:when:Predicate"
            };
            foreach (var definition in definitions)
            {
                var parts = definition.Split('|');
                var fields = new Dictionary<int, Field>();
                foreach (var item in parts[1].Split(' '))
                {
                    var p = item.Split(':');
                    fields.Add(int.Parse(p[0]), new Field { Name = p[1], Type = p[2].TrimStart('+'), Repeated = p[2][0] == '+' });
                }
                result.Add(parts[0], fields);
            }
            return result;
        }

        /// <summary>Decode the additive schema-1/2 wire fields. The container selects the required schema; bounds apply to every submessage.</summary>
        /// <param name="data">Caller-owned raw metadata, capped at 64 MiB and never modified.</param>
        /// <returns>Detached schema tree with unknown-field paths and explicit field-presence sets.</returns>
        public static Dictionary<string, object> Read(byte[] data)
        {
            if (data == null || data.Length > 67108864) throw new InvalidDataException("TigerSetup metadata exceeds 64 MiB.");
            int position = 0, remainingFields = 200000;
            var result = Message(data, ref position, data.Length, "Metadata", 0, ref remainingFields);
            var unknown = new List<string>();
            CollectUnknown(result, "Metadata", unknown);
            result.Add("UnknownPaths", unknown);
            return result;
        }

        private static void CollectUnknown(Dictionary<string, object> node, string path, List<string> paths)
        {
            foreach (int number in (List<int>)node["UnknownFields"]) paths.Add(path + "." + number);
            foreach (var pair in node)
            {
                var child = pair.Value as Dictionary<string, object>;
                if (child != null) CollectUnknown(child, path + "." + pair.Key, paths);
                var list = pair.Value as List<object>;
                if (list == null) continue;
                for (int n = 0; n < list.Count; n++)
                {
                    child = list[n] as Dictionary<string, object>;
                    if (child != null) CollectUnknown(child, path + "." + pair.Key + "[" + n + "]", paths);
                }
            }
        }

        private static bool Numeric(string type) { return type == "u" || type == "U" || type == "i" || type == "I" || type == "b" || type == "f"; }

        private static Dictionary<string, object> Message(byte[] data, ref int pos, int end, string type, int depth, ref int budget, Dictionary<string, object> existing = null)
        {
            if (depth > 32) throw new InvalidDataException("TigerSetup Protobuf nesting exceeds 32.");
            var result = existing ?? new Dictionary<string, object>(StringComparer.Ordinal);
            var fields = Schema[type];
            foreach (var field in fields.Values)
            {
                if (existing != null) break;
                object value = null;
                if (field.Repeated) value = new List<object>();
                else if (field.Type == "s") value = "";
                else if (field.Type == "x") value = Array.Empty<byte>();
                else if (field.Type == "b") value = false;
                else if (field.Type == "i") value = 0L;
                else if (field.Type == "I") value = 0;
                else if (field.Type == "U") value = 0U;
                else if (field.Type == "u" || field.Type == "f") value = 0UL;
                result.Add(field.Name, value);
            }
            if (existing == null) {
                result.Add("UnknownFields", new List<int>());
                result.Add("PresentFields", new HashSet<string>(StringComparer.Ordinal));
            }
            var unknown = (List<int>)result["UnknownFields"];
            while (pos < end)
            {
                if (--budget < 0) throw new InvalidDataException("TigerSetup metadata field limit exceeded.");
                ulong tag = Varint(data, ref pos, end);
                if ((tag >> 3) == 0 || (tag >> 3) > 536870911) throw new InvalidDataException("Invalid Protobuf field number.");
                int number = (int)(tag >> 3), wire = (int)(tag & 7);
                Field field;
                if (!fields.TryGetValue(number, out field))
                {
                    Skip(data, ref pos, end, wire);
                    unknown.Add(number);
                    continue;
                }
                // Packed numeric repeated fields share wire 2 with strings and messages.
                ((HashSet<string>)result["PresentFields"]).Add(field.Name);
                if (field.Repeated && wire == 2 && Numeric(field.Type))
                {
                    int packedEnd = LengthEnd(data, ref pos, end);
                    var list = (List<object>)result[field.Name];
                    while (pos < packedEnd)
                    {
                        if (--budget < 0 || list.Count >= 65536) throw new InvalidDataException("TigerSetup repeated-field limit exceeded.");
                        list.Add(Scalar(data, ref pos, packedEnd, field.Type, field.Type == "f" ? 5 : 0, depth, ref budget));
                    }
                    continue;
                }
                // Protobuf merges successive singular messages; absent child fields
                // must not overwrite earlier values with their scalar defaults.
                object decoded = Scalar(data, ref pos, end, field.Type, wire, depth, ref budget,
                    field.Repeated ? null : result[field.Name] as Dictionary<string, object>);
                if (field.Repeated)
                {
                    var list = (List<object>)result[field.Name];
                    if (list.Count >= 65536) throw new InvalidDataException("TigerSetup repeated-field limit exceeded.");
                    list.Add(decoded);
                }
                else result[field.Name] = decoded;
            }
            return result;
        }

        private static object Scalar(byte[] data, ref int pos, int end, string type, int wire, int depth, ref int budget, Dictionary<string, object> existing = null)
        {
            int expected = type == "f" ? 5 : Numeric(type) ? 0 : 2;
            if (wire != expected) throw new InvalidDataException("Incorrect TigerSetup Protobuf wire type.");
            if (wire == 0)
            {
                ulong value = Varint(data, ref pos, end);
                if (type == "b") return value != 0;
                if (type == "i") return unchecked((long)value);
                // Prost/protobuf integer decoding uses the low declared-width bits.
                // In particular negative int32 codes may use ten wire bytes.
                if (type == "I") return unchecked((int)value);
                if (type == "U") return unchecked((uint)value);
                return value;
            }
            if (wire == 5)
            {
                Require(pos, 4, end);
                uint value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(pos, 4));
                pos += 4;
                return (ulong)value;
            }
            int next = LengthEnd(data, ref pos, end);
            if (Schema.ContainsKey(type)) return Message(data, ref pos, next, type, depth + 1, ref budget, existing);
            int start = pos;
            pos = next;
            if (type == "s") return Utf8.GetString(data, start, next - start);
            var bytes = new byte[next - start];
            Buffer.BlockCopy(data, start, bytes, 0, bytes.Length);
            return bytes;
        }

        private static void Require(int pos, int length, int end)
        {
            if (length < 0 || length > end - pos) throw new InvalidDataException("Truncated TigerSetup Protobuf field.");
        }
        private static ulong Varint(byte[] data, ref int pos, int end)
        {
            ulong value = 0;
            for (int n = 0; n < 10; n++)
            {
                Require(pos, 1, end);
                byte b = data[pos++];
                if (n == 9 && b > 1) throw new InvalidDataException("Overflowing Protobuf varint.");
                value |= ((ulong)(b & 127)) << (n * 7);
                if (b < 128) return value;
            }
            throw new InvalidDataException("Unterminated Protobuf varint.");
        }
        private static int LengthEnd(byte[] data, ref int pos, int end)
        {
            ulong length = Varint(data, ref pos, end);
            if (length > (ulong)(end - pos)) throw new InvalidDataException("Protobuf length exceeds its enclosing message.");
            return pos + (int)length;
        }
        private static void Skip(byte[] data, ref int pos, int end, int wire)
        {
            switch (wire)
            {
                case 0: Varint(data, ref pos, end); break;
                case 1: Require(pos, 8, end); pos += 8; break;
                case 2: pos = LengthEnd(data, ref pos, end); break;
                case 5: Require(pos, 4, end); pos += 4; break;
                default: throw new InvalidDataException("Unsupported Protobuf wire type.");
            }
        }

        /// <summary>Preserve unknown fields while changing role/scope and removing the payload index.</summary>
        public static byte[] UninstallerMetadata(byte[] data, int scope)
        {
            using (var output = new MemoryStream())
            {
                int pos = 0;
                while (pos < data.Length)
                {
                    int start = pos;
                    ulong tag = Varint(data, ref pos, data.Length);
                    Skip(data, ref pos, data.Length, (int)(tag & 7));
                    int number = (int)(tag >> 3);
                    if (number != 7 && number != 8 && number != 23) output.Write(data, start, pos - start);
                }
                output.Write(new byte[] { 56, 2, 64, checked((byte)scope) });
                return output.ToArray();
            }
        }

        /// <summary>Encode one Zstandard raw-block frame, matching compose_without_payload.</summary>
        public static byte[] StoredZstd(byte[] data)
        {
            using (var output = new MemoryStream())
            using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
            {
                writer.Write(0xFD2FB528u);
                writer.Write((byte)0xE0);
                writer.Write((ulong)data.Length);
                int pos = 0;
                do
                {
                    int size = Math.Min(131072, data.Length - pos);
                    uint header = ((uint)size << 3) | (pos + size == data.Length ? 1u : 0u);
                    output.WriteByte((byte)header); output.WriteByte((byte)(header >> 8)); output.WriteByte((byte)(header >> 16));
                    output.Write(data, pos, size);
                    pos += size;
                } while (pos < data.Length);
                return output.ToArray();
            }
        }
    }
}
