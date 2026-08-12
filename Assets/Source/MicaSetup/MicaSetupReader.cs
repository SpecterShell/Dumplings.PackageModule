// SPDX-License-Identifier: Apache-2.0
// Format sources: https://github.com/lemutec/MicaSetup and
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace Dumplings.MicaSetup
{
    /// <summary>Describes one primitive or stream value stored in a WPF .g.resources container.</summary>
    public sealed class MicaSetupResourceEntry
    {
        public string ContainerName { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public int TypeCode { get; set; }
        public string TypeName { get; set; } = string.Empty;
        public long Offset { get; set; }
        public long Length { get; set; }
        public object Value { get; set; }
    }

    /// <summary>Describes one statically evaluated assignment to MicaSetup.Option.</summary>
    public sealed class MicaSetupOptionEvidence
    {
        public string Name { get; set; } = string.Empty;
        public object Value { get; set; }
        public bool IsResolved { get; set; }
        public string Expression { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public int IlOffset { get; set; }
        public int ArrayLength { get; set; } = -1;
    }

    /// <summary>Describes one literal Microsoft.Win32.Registry.SetValue call found in managed installer code.</summary>
    public sealed class MicaSetupRegistryWriteEvidence
    {
        public string Key { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public object Value { get; set; }
        public int? ValueKind { get; set; }
        public bool IsResolved { get; set; }
        public string Method { get; set; } = string.Empty;
        public int IlOffset { get; set; }
    }

    /// <summary>Contains bounded CLR and WPF-resource evidence consumed by the PowerShell parser.</summary>
    public sealed class MicaSetupManagedInfo
    {
        public string FileKind { get; set; } = string.Empty;
        public bool HasOptionType { get; set; }
        public bool HasUseOptionsMethod { get; set; }
        public bool HasPackType { get; set; }
        public bool HasUsePackMethod { get; set; }
        public string BuilderGeneration { get; set; } = string.Empty;
        public string ConfigurationModel { get; set; } = string.Empty;
        public string TargetFramework { get; set; } = string.Empty;
        public string RequestExecutionLevel { get; set; } = string.Empty;
        public bool? UseElevated { get; set; }
        public string AssemblyName { get; set; } = string.Empty;
        public string AssemblyTitle { get; set; } = string.Empty;
        public string AssemblyProduct { get; set; } = string.Empty;
        public string AssemblyCompany { get; set; } = string.Empty;
        public string AssemblyVersion { get; set; } = string.Empty;
        public List<MicaSetupResourceEntry> Resources { get; } = new List<MicaSetupResourceEntry>();
        public List<MicaSetupOptionEvidence> Options { get; } = new List<MicaSetupOptionEvidence>();
        public List<MicaSetupRegistryWriteEvidence> RegistryWrites { get; } = new List<MicaSetupRegistryWriteEvidence>();
        public List<string> Evidence { get; } = new List<string>();
        public List<string> Warnings { get; } = new List<string>();
    }

    internal sealed class TypeNameProvider : ISignatureTypeProvider<string, object>
    {
        private readonly MetadataReader _reader;

        internal TypeNameProvider(MetadataReader reader) { _reader = reader; }

        public string GetArrayType(string elementType, ArrayShape shape) { return elementType + "[]"; }
        public string GetByReferenceType(string elementType) { return elementType + "&"; }
        public string GetFunctionPointerType(MethodSignature<string> signature) { return "method"; }
        public string GetGenericInstantiation(string genericType, System.Collections.Immutable.ImmutableArray<string> typeArguments) { return genericType; }
        public string GetGenericMethodParameter(object genericContext, int index) { return "!!" + index; }
        public string GetGenericTypeParameter(object genericContext, int index) { return "!" + index; }
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) { return unmodifiedType; }
        public string GetPinnedType(string elementType) { return elementType; }
        public string GetPointerType(string elementType) { return elementType + "*"; }
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) { return "System." + typeCode; }
        public string GetSZArrayType(string elementType) { return elementType + "[]"; }
        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) { return MicaSetupReader.GetTypeName(reader, handle); }
        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) { return MicaSetupReader.GetTypeName(reader, handle); }
        public string GetTypeFromSpecification(MetadataReader reader, object genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
        {
            return reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
        }
    }

    internal sealed class MethodReferenceInfo
    {
        internal string DeclaringType = string.Empty;
        internal string Name = string.Empty;
        internal int ParameterCount;
        internal bool IsInstance;
        internal string ReturnType = string.Empty;
        internal string[] ParameterTypes = Array.Empty<string>();
    }

    internal sealed class SymbolicValue
    {
        internal object Value;
        internal bool Resolved;
        internal string Expression = "unknown";
        internal int ArrayLength = -1;
        internal int LocalAddress = -1;

        internal static SymbolicValue Constant(object value, string expression = null)
        {
            return new SymbolicValue { Value = value, Resolved = true, Expression = expression ?? (value == null ? "null" : value.ToString()) };
        }

        internal static SymbolicValue Unknown(string expression)
        {
            return new SymbolicValue { Resolved = false, Expression = expression ?? "unknown" };
        }

        internal static SymbolicValue Array(int length)
        {
            return new SymbolicValue { Resolved = length == 0, Value = length == 0 ? System.Array.Empty<object>() : null, Expression = "array[" + length + "]", ArrayLength = length };
        }

        internal SymbolicValue Clone()
        {
            return new SymbolicValue { Value = Value, Resolved = Resolved, Expression = Expression, ArrayLength = ArrayLength, LocalAddress = LocalAddress };
        }
    }

    internal sealed class IlInstruction
    {
        internal int Offset;
        internal OpCode OpCode;
        internal object Operand;
        internal int NextOffset;
    }

    /// <summary>
    /// Reads MicaSetup's managed metadata and nested WPF resources without loading the target assembly.
    /// Caller-owned streams are left open and their original position is restored.
    /// </summary>
    public static class MicaSetupReader
    {
        private const uint ResourceManagerMagic = 0xBEEFCACE;
        private const int ResourceTypeString = 1;
        private const int ResourceTypeByteArray = 32;
        private const int ResourceTypeStream = 33;
        private const int ResourceTypeStartOfUserTypes = 64;
        private static readonly Dictionary<short, OpCode> OpCodesByValue = BuildOpCodeTable();

        public static MicaSetupManagedInfo Analyze(string path, int maximumResources = 8192, int maximumMethods = 32768, int maximumInstructions = 250000)
        {
            if (path == null) { throw new ArgumentNullException(nameof(path)); }
            using (FileStream stream = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                return Analyze(stream, maximumResources, maximumMethods, maximumInstructions);
            }
        }

        public static MicaSetupManagedInfo Analyze(Stream stream, int maximumResources = 8192, int maximumMethods = 32768, int maximumInstructions = 250000)
        {
            if (stream == null) { throw new ArgumentNullException(nameof(stream)); }
            if (!stream.CanRead || !stream.CanSeek) { throw new ArgumentException("The MicaSetup reader requires a readable, seekable stream.", nameof(stream)); }
            if (maximumResources < 1 || maximumMethods < 1 || maximumInstructions < 1) { throw new ArgumentOutOfRangeException("Parser limits must be positive."); }

            long originalPosition = stream.Position;
            try
            {
                stream.Position = 0;
                using (PEReader peReader = new PEReader(stream, PEStreamOptions.LeaveOpen))
                {
                    if (!peReader.HasMetadata || peReader.PEHeaders.CorHeader == null) { throw new BadImageFormatException("The PE does not contain CLR metadata."); }
                    MetadataReader reader = peReader.GetMetadataReader();
                    MicaSetupManagedInfo result = new MicaSetupManagedInfo();
                    Characteristics characteristics = peReader.PEHeaders.CoffHeader.Characteristics;
                    result.FileKind = (characteristics & Characteristics.Dll) != 0 ? "Dll" :
                        ((characteristics & Characteristics.ExecutableImage) != 0 ? "Executable" : "UnknownPE");
                    ReadIdentity(reader, result);
                    ReadTypeAndMethodEvidence(peReader, reader, result, maximumMethods, maximumInstructions);
                    ReadWpfResources(stream, peReader, reader, result, maximumResources);
                    return result;
                }
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private static void ReadIdentity(MetadataReader reader, MicaSetupManagedInfo result)
        {
            AssemblyDefinition assembly = reader.GetAssemblyDefinition();
            result.AssemblyName = reader.GetString(assembly.Name);
            result.AssemblyVersion = assembly.Version.ToString();
            foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
            {
                CustomAttribute attribute = reader.GetCustomAttribute(handle);
                string typeName = GetAttributeTypeName(reader, attribute.Constructor);
                string value = ReadSingleStringAttribute(reader, attribute);
                if (typeName.EndsWith("TargetFrameworkAttribute", StringComparison.Ordinal)) { result.TargetFramework = value ?? string.Empty; }
                else if (typeName.EndsWith("RequestExecutionLevelAttribute", StringComparison.Ordinal)) { result.RequestExecutionLevel = value ?? string.Empty; }
                else if (typeName.EndsWith("AssemblyTitleAttribute", StringComparison.Ordinal)) { result.AssemblyTitle = value ?? string.Empty; }
                else if (typeName.EndsWith("AssemblyProductAttribute", StringComparison.Ordinal)) { result.AssemblyProduct = value ?? string.Empty; }
                else if (typeName.EndsWith("AssemblyCompanyAttribute", StringComparison.Ordinal)) { result.AssemblyCompany = value ?? string.Empty; }
            }
        }

        private static void ReadTypeAndMethodEvidence(PEReader peReader, MetadataReader reader, MicaSetupManagedInfo result, int maximumMethods, int maximumInstructions)
        {
            HashSet<string> optionMembers = new HashSet<string>(StringComparer.Ordinal);
            int methodCount = 0;
            foreach (TypeDefinitionHandle typeHandle in reader.TypeDefinitions)
            {
                TypeDefinition type = reader.GetTypeDefinition(typeHandle);
                string typeName = GetTypeName(reader, typeHandle);
                if (typeName == "MicaSetup.Option")
                {
                    result.HasOptionType = true;
                    foreach (PropertyDefinitionHandle propertyHandle in type.GetProperties())
                    {
                        optionMembers.Add(reader.GetString(reader.GetPropertyDefinition(propertyHandle).Name));
                    }
                }
                else if (typeName == "MicaSetup.Core.Pack")
                {
                    result.HasPackType = true;
                    foreach (PropertyDefinitionHandle propertyHandle in type.GetProperties())
                    {
                        optionMembers.Add(reader.GetString(reader.GetPropertyDefinition(propertyHandle).Name));
                    }
                }

                foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
                {
                    if (++methodCount > maximumMethods) { throw new InvalidDataException("The CLR method table exceeds the configured MicaSetup parser limit."); }
                    MethodDefinition method = reader.GetMethodDefinition(methodHandle);
                    string methodName = reader.GetString(method.Name);
                    if (methodName == "UseOptions" && typeName.StartsWith("MicaSetup.", StringComparison.Ordinal)) { result.HasUseOptionsMethod = true; }
                    if (methodName == "UsePack" && typeName.StartsWith("MicaSetup.", StringComparison.Ordinal)) { result.HasUsePackMethod = true; }
                }
            }

            // v1.0 embeds MicaSetup.Core through Costura, so Pack is a TypeRef/MemberRef in the outer
            // setup rather than a TypeDef. The generated initializer still calls its property setters
            // directly, which is sufficient structural evidence without decompressing or loading the DLL.
            foreach (MemberReferenceHandle memberHandle in reader.MemberReferences)
            {
                MemberReference member = reader.GetMemberReference(memberHandle);
                if (GetTypeName(reader, member.Parent) != "MicaSetup.Core.Pack") { continue; }
                string memberName = reader.GetString(member.Name);
                if (!memberName.StartsWith("set_", StringComparison.Ordinal) && !memberName.StartsWith("get_", StringComparison.Ordinal)) { continue; }
                result.HasPackType = true;
                optionMembers.Add(memberName.Substring(4));
            }

            result.ConfigurationModel = result.HasPackType ? "Pack" :
                (optionMembers.Contains("IsUninstLower") || optionMembers.Contains("IsUseInstallPathPreferAppDataLocalPrograms") ? "OptionModern" :
                (result.HasOptionType ? "OptionLegacy" : string.Empty));
            result.BuilderGeneration = result.ConfigurationModel == "OptionModern" ? "v2" :
                (result.ConfigurationModel == "Pack" || result.ConfigurationModel == "OptionLegacy" ? "v1" : string.Empty);
            if (result.HasOptionType) { result.Evidence.Add("CLR type MicaSetup.Option"); }
            if (result.HasUseOptionsMethod) { result.Evidence.Add("MicaSetup UseOptions host-builder method"); }
            if (result.HasPackType) { result.Evidence.Add("CLR type MicaSetup.Core.Pack"); }
            if (result.HasUsePackMethod) { result.Evidence.Add("MicaSetup UsePack host-builder method"); }
            if (!string.IsNullOrEmpty(result.ConfigurationModel)) { result.Evidence.Add("MicaSetup " + result.ConfigurationModel + " configuration model (" + result.BuilderGeneration + "-compatible)"); }

            Dictionary<string, MicaSetupOptionEvidence> assignments = new Dictionary<string, MicaSetupOptionEvidence>(StringComparer.Ordinal);
            int totalInstructions = 0;
            foreach (MethodDefinitionHandle methodHandle in reader.MethodDefinitions)
            {
                MethodDefinition method = reader.GetMethodDefinition(methodHandle);
                if (method.RelativeVirtualAddress == 0) { continue; }
                MethodBodyBlock body;
                try { body = peReader.GetMethodBody(method.RelativeVirtualAddress); }
                catch (BadImageFormatException ex) { result.Warnings.Add("Skipped malformed CLR method body: " + ex.Message); continue; }
                List<IlInstruction> instructions = DecodeInstructions(body.GetILBytes());
                totalInstructions += instructions.Count;
                if (totalInstructions > maximumInstructions) { throw new InvalidDataException("The CLR instruction count exceeds the configured MicaSetup parser limit."); }
                int optionSetterCount = CountMicaConfigurationSetters(reader, instructions);
                bool containsUseElevated = MethodContainsUseElevated(reader, instructions);
                bool containsLiteralRegistryWrite = MethodContainsLiteralRegistryWrite(reader, instructions);
                if (optionSetterCount < 4 && !containsUseElevated && !containsLiteralRegistryWrite) { continue; }
                string declaringType = GetTypeName(reader, method.GetDeclaringType());
                string displayName = declaringType + "::" + reader.GetString(method.Name);
                Dictionary<string, MicaSetupOptionEvidence> targetAssignments = optionSetterCount >= 4
                    ? assignments
                    : new Dictionary<string, MicaSetupOptionEvidence>(StringComparer.Ordinal);
                EvaluateMethod(reader, instructions, body.LocalSignature, displayName, targetAssignments, result, optionSetterCount >= 4);
            }

            foreach (MicaSetupOptionEvidence evidence in assignments.Values.OrderBy(value => value.Name, StringComparer.Ordinal)) { result.Options.Add(evidence); }
        }

        private static int CountMicaConfigurationSetters(MetadataReader reader, List<IlInstruction> instructions)
        {
            int count = 0;
            foreach (IlInstruction instruction in instructions)
            {
                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) { continue; }
                MethodReferenceInfo method = ResolveMethod(reader, (int)instruction.Operand);
                if (method != null && IsMicaSetupConfigurationType(method.DeclaringType) && method.Name.StartsWith("set_", StringComparison.Ordinal)) { count++; }
            }
            return count;
        }

        private static bool MethodContainsUseElevated(MetadataReader reader, List<IlInstruction> instructions)
        {
            foreach (IlInstruction instruction in instructions)
            {
                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) { continue; }
                MethodReferenceInfo method = ResolveMethod(reader, (int)instruction.Operand);
                if (method != null && method.Name == "UseElevated" && method.DeclaringType.StartsWith("MicaSetup.", StringComparison.Ordinal)) { return true; }
            }
            return false;
        }

        private static bool MethodContainsLiteralRegistryWrite(MetadataReader reader, List<IlInstruction> instructions)
        {
            foreach (IlInstruction instruction in instructions)
            {
                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) { continue; }
                MethodReferenceInfo method = ResolveMethod(reader, (int)instruction.Operand);
                if (method != null && method.DeclaringType == "Microsoft.Win32.Registry" && method.Name == "SetValue") { return true; }
            }
            return false;
        }

        private static void EvaluateMethod(MetadataReader reader, List<IlInstruction> instructions, StandaloneSignatureHandle localSignature, string methodName, Dictionary<string, MicaSetupOptionEvidence> assignments, MicaSetupManagedInfo result, bool reportBranchWarnings)
        {
            Dictionary<int, int> indexByOffset = instructions.Select((instruction, index) => new { instruction.Offset, index }).ToDictionary(value => value.Offset, value => value.index);
            SymbolicValue[] locals = CreateLocals(reader, localSignature);
            List<SymbolicValue> stack = new List<SymbolicValue>();
            Dictionary<int, int> visits = new Dictionary<int, int>();
            int index = 0;
            int steps = 0;
            while (index >= 0 && index < instructions.Count && steps++ < Math.Max(4096, instructions.Count * 8))
            {
                IlInstruction instruction = instructions[index];
                visits.TryGetValue(instruction.Offset, out int visitCount);
                if (visitCount >= 8) { result.Warnings.Add("Stopped a cyclic or ambiguous IL path in " + methodName + "."); break; }
                visits[instruction.Offset] = visitCount + 1;
                int nextIndex = index + 1;

                switch (instruction.OpCode.Value)
                {
                    case 0x00: break; // nop
                    case 0x02: Push(stack, SymbolicValue.Unknown("arg0")); break;
                    case 0x03: Push(stack, SymbolicValue.Unknown("arg1")); break;
                    case 0x04: Push(stack, SymbolicValue.Unknown("arg2")); break;
                    case 0x05: Push(stack, SymbolicValue.Unknown("arg3")); break;
                    case 0x06: Push(stack, GetLocal(locals, 0)); break;
                    case 0x07: Push(stack, GetLocal(locals, 1)); break;
                    case 0x08: Push(stack, GetLocal(locals, 2)); break;
                    case 0x09: Push(stack, GetLocal(locals, 3)); break;
                    case 0x0A: SetLocal(locals, 0, Pop(stack)); break;
                    case 0x0B: SetLocal(locals, 1, Pop(stack)); break;
                    case 0x0C: SetLocal(locals, 2, Pop(stack)); break;
                    case 0x0D: SetLocal(locals, 3, Pop(stack)); break;
                    case 0x0E: Push(stack, SymbolicValue.Unknown("arg" + Convert.ToInt32(instruction.Operand))); break;
                    case 0x0F: Push(stack, SymbolicValue.Unknown("&arg" + Convert.ToInt32(instruction.Operand))); break;
                    case 0x10: Pop(stack); break;
                    case 0x11: Push(stack, GetLocal(locals, Convert.ToInt32(instruction.Operand))); break;
                    case 0x12:
                    {
                        int localIndex = Convert.ToInt32(instruction.Operand);
                        Push(stack, new SymbolicValue { Resolved = false, Expression = "&local" + localIndex, LocalAddress = localIndex });
                        break;
                    }
                    case 0x13: SetLocal(locals, Convert.ToInt32(instruction.Operand), Pop(stack)); break;
                    case 0x14: Push(stack, SymbolicValue.Constant(null)); break;
                    case 0x15: Push(stack, SymbolicValue.Constant(-1)); break;
                    case 0x16: Push(stack, SymbolicValue.Constant(0)); break;
                    case 0x17: Push(stack, SymbolicValue.Constant(1)); break;
                    case 0x18: Push(stack, SymbolicValue.Constant(2)); break;
                    case 0x19: Push(stack, SymbolicValue.Constant(3)); break;
                    case 0x1A: Push(stack, SymbolicValue.Constant(4)); break;
                    case 0x1B: Push(stack, SymbolicValue.Constant(5)); break;
                    case 0x1C: Push(stack, SymbolicValue.Constant(6)); break;
                    case 0x1D: Push(stack, SymbolicValue.Constant(7)); break;
                    case 0x1E: Push(stack, SymbolicValue.Constant(8)); break;
                    case 0x1F:
                    case 0x20: Push(stack, SymbolicValue.Constant(Convert.ToInt32(instruction.Operand))); break;
                    case 0x21: Push(stack, SymbolicValue.Constant(Convert.ToInt64(instruction.Operand))); break;
                    case 0x22: Push(stack, SymbolicValue.Constant(Convert.ToSingle(instruction.Operand))); break;
                    case 0x23: Push(stack, SymbolicValue.Constant(Convert.ToDouble(instruction.Operand))); break;
                    case 0x25: Push(stack, stack.Count == 0 ? SymbolicValue.Unknown("dup") : stack[stack.Count - 1].Clone()); break;
                    case 0x26: Pop(stack); break;
                    case 0x2A: return;
                    case 0x2B:
                    case 0x38: nextIndex = GetBranchIndex(indexByOffset, Convert.ToInt32(instruction.Operand), nextIndex); break;
                    case 0x2C:
                    case 0x39:
                    case 0x2D:
                    case 0x3A:
                    {
                        SymbolicValue condition = Pop(stack);
                        bool? truth = ToBoolean(condition);
                        bool branchOnTrue = instruction.OpCode.Value == 0x2D || instruction.OpCode.Value == 0x3A;
                        if (truth.HasValue && truth.Value == branchOnTrue) { nextIndex = GetBranchIndex(indexByOffset, Convert.ToInt32(instruction.Operand), nextIndex); }
                        else if (!truth.HasValue && reportBranchWarnings) { result.Warnings.Add("An unresolved branch in " + methodName + " may hide conditional MicaSetup option values."); }
                        break;
                    }
                    case 0x28:
                    case 0x6F: EvaluateCall(reader, (int)instruction.Operand, false, instruction.Offset, methodName, stack, assignments, result); break;
                    case 0x72: Push(stack, SymbolicValue.Constant(reader.GetUserString(MetadataTokens.UserStringHandle((int)instruction.Operand)), "string")); break;
                    case 0x73: EvaluateCall(reader, (int)instruction.Operand, true, instruction.Offset, methodName, stack, assignments, result); break;
                    case 0x8D:
                    {
                        SymbolicValue length = Pop(stack);
                        Push(stack, length.Resolved && length.Value is int ? SymbolicValue.Array((int)length.Value) : SymbolicValue.Unknown("array"));
                        break;
                    }
                    case 0x8C: // box preserves the literal value needed by Registry.SetValue(object)
                    {
                        SymbolicValue value = Pop(stack);
                        Push(stack, value);
                        break;
                    }
                    case 0xA2: Pop(stack); Pop(stack); Pop(stack); break;
                    default:
                        if (instruction.OpCode.Value == unchecked((short)0xFE15))
                        {
                            SymbolicValue address = Pop(stack);
                            if (address.LocalAddress >= 0) { SetLocal(locals, address.LocalAddress, SymbolicValue.Constant(null)); }
                        }
                        else { ApplyGenericStackBehaviour(instruction.OpCode, stack); }
                        break;
                }
                index = nextIndex;
            }
        }

        private static void EvaluateCall(MetadataReader reader, int token, bool isNewObject, int ilOffset, string containingMethod, List<SymbolicValue> stack, Dictionary<string, MicaSetupOptionEvidence> assignments, MicaSetupManagedInfo result)
        {
            MethodReferenceInfo method = ResolveMethod(reader, token);
            if (method == null) { Push(stack, SymbolicValue.Unknown("call")); return; }
            SymbolicValue[] arguments = new SymbolicValue[method.ParameterCount];
            for (int i = method.ParameterCount - 1; i >= 0; i--) { arguments[i] = Pop(stack); }
            if (method.IsInstance && !isNewObject) { Pop(stack); }

            if (IsMicaSetupConfigurationType(method.DeclaringType) && method.Name.StartsWith("set_", StringComparison.Ordinal) && arguments.Length == 1)
            {
                string propertyName = NormalizeConfigurationProperty(method.DeclaringType, method.Name.Substring(4));
                SymbolicValue value = CoerceValue(arguments[0], method.ParameterTypes.Length == 0 ? string.Empty : method.ParameterTypes[0]);
                assignments[propertyName] = new MicaSetupOptionEvidence
                {
                    Name = propertyName,
                    Value = value.Resolved ? value.Value : null,
                    IsResolved = value.Resolved,
                    Expression = value.Expression,
                    Method = containingMethod,
                    IlOffset = ilOffset,
                    ArrayLength = value.ArrayLength
                };
                return;
            }

            if (IsMicaSetupConfigurationType(method.DeclaringType) && method.Name.StartsWith("get_", StringComparison.Ordinal))
            {
                string propertyName = NormalizeConfigurationProperty(method.DeclaringType, method.Name.Substring(4));
                if (assignments.TryGetValue(propertyName, out MicaSetupOptionEvidence evidence) && evidence.IsResolved)
                {
                    Push(stack, SymbolicValue.Constant(evidence.Value, "option." + propertyName));
                }
                else { Push(stack, SymbolicValue.Unknown("option." + propertyName)); }
                return;
            }

            if (method.Name == "UseElevated" && method.DeclaringType.StartsWith("MicaSetup.", StringComparison.Ordinal))
            {
                SymbolicValue requested = arguments.Length > 1 ? arguments[arguments.Length - 1] : SymbolicValue.Constant(1);
                bool? value = ToBoolean(requested);
                if (requested.Resolved && requested.Value == null) { result.UseElevated = null; }
                else if (value.HasValue) { result.UseElevated = value.Value; }
                else { result.Warnings.Add("The MicaSetup UseElevated argument could not be resolved statically."); }
            }

            // MicaSetup forks can add arbitrary C# around the generated host builder. Preserve only direct,
            // fully literal Registry.SetValue calls; RegistryKey instances and computed expressions remain
            // unresolved because following arbitrary object state would turn this bounded evaluator into a CLR.
            if (method.DeclaringType == "Microsoft.Win32.Registry" && method.Name == "SetValue" && arguments.Length >= 3)
            {
                bool resolved = arguments[0].Resolved && arguments[0].Value is string && arguments[1].Resolved &&
                    (arguments[1].Value == null || arguments[1].Value is string) && arguments[2].Resolved;
                int? valueKind = null;
                if (arguments.Length >= 4 && arguments[3].Resolved)
                {
                    try { valueKind = Convert.ToInt32(arguments[3].Value); }
                    catch (Exception) { resolved = false; }
                }
                result.RegistryWrites.Add(new MicaSetupRegistryWriteEvidence
                {
                    Key = resolved ? (string)arguments[0].Value : string.Empty,
                    Name = resolved ? (arguments[1].Value == null ? string.Empty : (string)arguments[1].Value) : string.Empty,
                    Value = resolved ? arguments[2].Value : null,
                    ValueKind = valueKind,
                    IsResolved = resolved,
                    Method = containingMethod,
                    IlOffset = ilOffset
                });
                if (!resolved) { result.Warnings.Add("A custom Registry.SetValue call in " + containingMethod + " could not be resolved statically."); }
            }

            SymbolicValue returnValue = EvaluateKnownReturn(method, arguments, isNewObject);
            if (isNewObject || !IsVoid(method.ReturnType)) { Push(stack, returnValue); }
        }

        private static bool IsMicaSetupConfigurationType(string typeName)
        {
            return typeName == "MicaSetup.Option" || typeName == "MicaSetup.Core.Pack";
        }

        private static string NormalizeConfigurationProperty(string typeName, string propertyName)
        {
            if (typeName != "MicaSetup.Core.Pack") { return propertyName; }
            switch (propertyName)
            {
                case "Uninst": return "IsUninst";
                case "CreateUninst": return "IsCreateUninst";
                case "DesktopShortcut": return "IsCreateDesktopShortcut";
                case "RegistryKeys": return "IsCreateRegistryKeys";
                case "AutoRun": return "IsCreateAsAutoRun";
                case "FolderPickerPreferClassic": return "UseFolderPickerPreferClassic";
                case "InstallPathPreferX86": return "UseInstallPathPreferX86";
                case "RegistryPreferX86": return "IsUseRegistryPreferX86";
                case "AllowFullFolderSecurity": return "IsAllowFullFolderSecurity";
                default: return propertyName;
            }
        }

        private static SymbolicValue EvaluateKnownReturn(MethodReferenceInfo method, SymbolicValue[] arguments, bool isNewObject)
        {
            if (method.DeclaringType == "System.String" && method.Name == "Concat" && arguments.All(value => value.Resolved))
            {
                return SymbolicValue.Constant(string.Concat(arguments.Select(value => value.Value == null ? string.Empty : Convert.ToString(value.Value))));
            }
            if (method.DeclaringType == "System.String" && method.Name == "Format" && arguments.Length > 0 && arguments[0].Resolved && arguments[0].Value is string)
            {
                try
                {
                    object[] formatArguments = arguments.Skip(1).Select(value => value.Resolved ? value.Value : "{" + value.Expression + "}").ToArray();
                    return SymbolicValue.Constant(string.Format((string)arguments[0].Value, formatArguments));
                }
                catch (FormatException) { return SymbolicValue.Unknown("String.Format"); }
            }
            if (method.DeclaringType.StartsWith("System.Array", StringComparison.Ordinal) && method.Name == "Empty") { return SymbolicValue.Array(0); }
            if (isNewObject) { return SymbolicValue.Unknown("new " + method.DeclaringType); }
            if (!IsVoid(method.ReturnType)) { return SymbolicValue.Unknown(method.DeclaringType + "." + method.Name + "()"); }
            return SymbolicValue.Unknown("void");
        }

        private static void ReadWpfResources(Stream stream, PEReader peReader, MetadataReader reader, MicaSetupManagedInfo result, int maximumResources)
        {
            DirectoryEntry directory = peReader.PEHeaders.CorHeader.ResourcesDirectory;
            long resourceDirectoryOffset = RvaToFileOffset(peReader.PEHeaders, directory.RelativeVirtualAddress);
            int parsedResourceCount = 0;
            foreach (ManifestResourceHandle handle in reader.ManifestResources)
            {
                ManifestResource resource = reader.GetManifestResource(handle);
                if (!resource.Implementation.IsNil) { continue; }
                string name = reader.GetString(resource.Name);
                if (!name.EndsWith(".g.resources", StringComparison.OrdinalIgnoreCase)) { continue; }
                long lengthOffset = CheckedRange(resourceDirectoryOffset, resource.Offset, 4, stream.Length);
                stream.Position = lengthOffset;
                uint length = ReadUInt32(stream);
                long dataOffset = checked(lengthOffset + 4);
                ValidateRange(dataOffset, length, stream.Length);
                ParseResourceFile(stream, dataOffset, length, name, result.Resources, ref parsedResourceCount, maximumResources);
            }
            if (result.Resources.Any(resource => resource.Name.Equals("resources/setups/publish.7z", StringComparison.OrdinalIgnoreCase)))
            {
                result.Evidence.Add("WPF ResourceTypeCode.Stream resources/setups/publish.7z");
            }
        }

        private static void ParseResourceFile(Stream stream, long resourceOffset, long resourceLength, string containerName, List<MicaSetupResourceEntry> output, ref int parsedResourceCount, int maximumResources)
        {
            long end = checked(resourceOffset + resourceLength);
            stream.Position = resourceOffset;
            if (ReadUInt32(stream) != ResourceManagerMagic) { throw new InvalidDataException("The WPF .resources magic is invalid."); }
            int headerVersion = ReadInt32(stream);
            int bytesToSkip = ReadInt32(stream);
            if (headerVersion < 1 || bytesToSkip < 0) { throw new InvalidDataException("The WPF .resources manager header is invalid."); }
            long runtimeHeaderOffset = checked(stream.Position + bytesToSkip);
            ValidateRange(runtimeHeaderOffset, 12, end);
            stream.Position = runtimeHeaderOffset;
            int runtimeVersion = ReadInt32(stream);
            int resourceCount = ReadInt32(stream);
            int typeCount = ReadInt32(stream);
            if ((runtimeVersion != 1 && runtimeVersion != 2) || resourceCount < 0 || typeCount < 0 || resourceCount > maximumResources || typeCount > maximumResources)
            {
                throw new InvalidDataException("The WPF .resources runtime header is unsupported or exceeds parser limits.");
            }
            if (parsedResourceCount + resourceCount > maximumResources) { throw new InvalidDataException("The aggregate WPF resource count exceeds the configured parser limit."); }
            string[] typeNames = new string[typeCount];
            for (int i = 0; i < typeCount; i++) { typeNames[i] = ReadBinaryString(stream, end, 32768); }
            // ResourceReader aligns within the embedded .resources stream, not the containing PE.
            stream.Position = checked(resourceOffset + Align(stream.Position - resourceOffset, 8));
            ValidateRange(stream.Position, checked(resourceCount * 8L + 4), end);
            stream.Position += resourceCount * 4L; // name hashes are not needed for bounded enumeration
            int[] namePositions = new int[resourceCount];
            for (int i = 0; i < resourceCount; i++) { namePositions[i] = ReadInt32(stream); }
            int dataSectionRelativeOffset = ReadInt32(stream);
            long nameSectionOffset = stream.Position;
            long dataSectionOffset = checked(resourceOffset + dataSectionRelativeOffset);
            ValidateRange(dataSectionOffset, 0, end);

            for (int i = 0; i < resourceCount; i++)
            {
                if (namePositions[i] < 0) { throw new InvalidDataException("A WPF resource name position is negative."); }
                long nameOffset = checked(nameSectionOffset + namePositions[i]);
                ValidateRange(nameOffset, 1, dataSectionOffset);
                stream.Position = nameOffset;
                string name = ReadResourceName(stream, dataSectionOffset, 32768);
                int dataPosition = ReadInt32(stream);
                if (dataPosition < 0) { throw new InvalidDataException("A WPF resource data position is negative."); }
                long recordOffset = checked(dataSectionOffset + dataPosition);
                ValidateRange(recordOffset, 1, end);
                stream.Position = recordOffset;
                int encodedType = Read7BitEncodedInt(stream, end);
                int typeCode = encodedType;
                string typeName = string.Empty;
                if (runtimeVersion == 1 && encodedType >= 0)
                {
                    if (encodedType >= typeNames.Length) { throw new InvalidDataException("A v1 WPF resource type index is outside the declared type table."); }
                    typeName = typeNames[encodedType];
                    typeCode = GetLegacyResourceTypeCode(typeName);
                }
                else if (runtimeVersion == 1)
                {
                    typeCode = 0;
                }
                if (typeCode >= ResourceTypeStartOfUserTypes)
                {
                    int typeIndex = typeCode - ResourceTypeStartOfUserTypes;
                    if (runtimeVersion == 2 && typeIndex >= 0 && typeIndex < typeNames.Length) { typeName = typeNames[typeIndex]; }
                    output.Add(new MicaSetupResourceEntry { ContainerName = containerName, Name = name, TypeCode = typeCode, TypeName = typeName, Offset = stream.Position, Length = 0 });
                    parsedResourceCount++;
                    continue;
                }

                MicaSetupResourceEntry entry = new MicaSetupResourceEntry { ContainerName = containerName, Name = name, TypeCode = typeCode, TypeName = typeName };
                if (typeCode == ResourceTypeStream || typeCode == ResourceTypeByteArray)
                {
                    int length = ReadInt32(stream);
                    if (length < 0) { throw new InvalidDataException("A WPF stream resource has a negative length."); }
                    entry.Offset = stream.Position;
                    entry.Length = length;
                    ValidateRange(entry.Offset, entry.Length, end);
                }
                else if (typeCode == ResourceTypeString)
                {
                    long valueOffset = stream.Position;
                    string value = ReadBinaryString(stream, end, 1048576);
                    entry.Offset = valueOffset;
                    entry.Length = stream.Position - valueOffset;
                    entry.Value = value;
                }
                else
                {
                    ReadPrimitiveResource(stream, end, typeCode, entry, runtimeVersion == 1);
                }
                output.Add(entry);
                parsedResourceCount++;
            }
        }

        private static int GetLegacyResourceTypeCode(string assemblyQualifiedTypeName)
        {
            string typeName = assemblyQualifiedTypeName == null ? string.Empty : assemblyQualifiedTypeName.Split(',')[0].Trim();
            switch (typeName)
            {
                case "System.String": return 1;
                case "System.Boolean": return 2;
                case "System.Char": return 3;
                case "System.Byte": return 4;
                case "System.SByte": return 5;
                case "System.Int16": return 6;
                case "System.UInt16": return 7;
                case "System.Int32": return 8;
                case "System.UInt32": return 9;
                case "System.Int64": return 10;
                case "System.UInt64": return 11;
                case "System.Single": return 12;
                case "System.Double": return 13;
                case "System.Decimal": return 14;
                case "System.DateTime": return 15;
                case "System.TimeSpan": return 16;
                default: return ResourceTypeStartOfUserTypes;
            }
        }

        private static void ReadPrimitiveResource(Stream stream, long end, int typeCode, MicaSetupResourceEntry entry, bool legacyDateTime)
        {
            entry.Offset = stream.Position;
            int fixedLength = typeCode == 2 || typeCode == 4 || typeCode == 5 ? 1 :
                (typeCode == 3 || typeCode == 6 || typeCode == 7 ? 2 :
                (typeCode == 8 || typeCode == 9 || typeCode == 12 ? 4 :
                (typeCode == 10 || typeCode == 11 || typeCode == 13 || typeCode == 15 || typeCode == 16 ? 8 :
                (typeCode == 14 ? 16 : 0))));
            if (fixedLength > 0) { ValidateRange(stream.Position, fixedLength, end); }
            switch (typeCode)
            {
                case 0: entry.Value = null; entry.Length = 0; return;
                case 2: entry.Value = ReadByte(stream) != 0; entry.Length = 1; return;
                case 3: entry.Value = (char)ReadUInt16(stream); entry.Length = 2; return;
                case 4: entry.Value = ReadByte(stream); entry.Length = 1; return;
                case 5: entry.Value = unchecked((sbyte)ReadByte(stream)); entry.Length = 1; return;
                case 6: entry.Value = ReadInt16(stream); entry.Length = 2; return;
                case 7: entry.Value = ReadUInt16(stream); entry.Length = 2; return;
                case 8: entry.Value = ReadInt32(stream); entry.Length = 4; return;
                case 9: entry.Value = ReadUInt32(stream); entry.Length = 4; return;
                case 10: entry.Value = ReadInt64(stream); entry.Length = 8; return;
                case 11: entry.Value = ReadUInt64(stream); entry.Length = 8; return;
                case 12: entry.Value = BitConverter.Int32BitsToSingle(ReadInt32(stream)); entry.Length = 4; return;
                case 13: entry.Value = BitConverter.Int64BitsToDouble(ReadInt64(stream)); entry.Length = 8; return;
                case 14:
                    entry.Value = new decimal(new[] { ReadInt32(stream), ReadInt32(stream), ReadInt32(stream), ReadInt32(stream) });
                    entry.Length = 16;
                    return;
                case 15:
                    long dateTimeValue = ReadInt64(stream);
                    entry.Value = legacyDateTime ? new DateTime(dateTimeValue) : DateTime.FromBinary(dateTimeValue);
                    entry.Length = 8;
                    return;
                case 16: entry.Value = TimeSpan.FromTicks(ReadInt64(stream)); entry.Length = 8; return;
                default:
                    entry.Length = 0;
                    return;
            }
        }

        internal static string GetTypeName(MetadataReader reader, EntityHandle handle)
        {
            if (handle.Kind == HandleKind.TypeDefinition)
            {
                TypeDefinition type = reader.GetTypeDefinition((TypeDefinitionHandle)handle);
                string ns = reader.GetString(type.Namespace);
                string name = reader.GetString(type.Name);
                return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
            }
            if (handle.Kind == HandleKind.TypeReference)
            {
                TypeReference type = reader.GetTypeReference((TypeReferenceHandle)handle);
                string ns = reader.GetString(type.Namespace);
                string name = reader.GetString(type.Name);
                return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
            }
            if (handle.Kind == HandleKind.TypeSpecification) { return reader.GetTypeSpecification((TypeSpecificationHandle)handle).DecodeSignature(new TypeNameProvider(reader), null); }
            return string.Empty;
        }

        private static MethodReferenceInfo ResolveMethod(MetadataReader reader, int token)
        {
            EntityHandle handle;
            try { handle = MetadataTokens.EntityHandle(token); }
            catch (ArgumentException) { return null; }
            if (handle.Kind == HandleKind.MethodSpecification) { handle = reader.GetMethodSpecification((MethodSpecificationHandle)handle).Method; }
            TypeNameProvider provider = new TypeNameProvider(reader);
            if (handle.Kind == HandleKind.MethodDefinition)
            {
                MethodDefinition method = reader.GetMethodDefinition((MethodDefinitionHandle)handle);
                MethodSignature<string> signature = method.DecodeSignature(provider, null);
                return new MethodReferenceInfo
                {
                    DeclaringType = GetTypeName(reader, method.GetDeclaringType()),
                    Name = reader.GetString(method.Name),
                    ParameterCount = signature.ParameterTypes.Length,
                    IsInstance = signature.Header.IsInstance,
                    ReturnType = signature.ReturnType,
                    ParameterTypes = signature.ParameterTypes.ToArray()
                };
            }
            if (handle.Kind == HandleKind.MemberReference)
            {
                MemberReference member = reader.GetMemberReference((MemberReferenceHandle)handle);
                MethodSignature<string> signature;
                try { signature = member.DecodeMethodSignature(provider, null); }
                catch (BadImageFormatException) { return null; }
                return new MethodReferenceInfo
                {
                    DeclaringType = GetTypeName(reader, member.Parent),
                    Name = reader.GetString(member.Name),
                    ParameterCount = signature.ParameterTypes.Length,
                    IsInstance = signature.Header.IsInstance,
                    ReturnType = signature.ReturnType,
                    ParameterTypes = signature.ParameterTypes.ToArray()
                };
            }
            return null;
        }

        private static string GetAttributeTypeName(MetadataReader reader, EntityHandle constructor)
        {
            if (constructor.Kind == HandleKind.MethodDefinition) { return GetTypeName(reader, reader.GetMethodDefinition((MethodDefinitionHandle)constructor).GetDeclaringType()); }
            if (constructor.Kind == HandleKind.MemberReference) { return GetTypeName(reader, reader.GetMemberReference((MemberReferenceHandle)constructor).Parent); }
            return string.Empty;
        }

        private static string ReadSingleStringAttribute(MetadataReader reader, CustomAttribute attribute)
        {
            BlobReader blob = reader.GetBlobReader(attribute.Value);
            if (blob.RemainingBytes < 2 || blob.ReadUInt16() != 1) { return null; }
            if (blob.RemainingBytes == 0) { return null; }
            byte first = blob.ReadByte();
            if (first == 0xFF) { return null; }
            int length;
            if ((first & 0x80) == 0) { length = first; }
            else if ((first & 0xC0) == 0x80)
            {
                if (blob.RemainingBytes < 1) { return null; }
                length = ((first & 0x3F) << 8) | blob.ReadByte();
            }
            else
            {
                if (blob.RemainingBytes < 3) { return null; }
                length = ((first & 0x1F) << 24) | (blob.ReadByte() << 16) | (blob.ReadByte() << 8) | blob.ReadByte();
            }
            if (length < 0 || length > blob.RemainingBytes) { return null; }
            return blob.ReadUTF8(length);
        }

        private static List<IlInstruction> DecodeInstructions(byte[] bytes)
        {
            List<IlInstruction> instructions = new List<IlInstruction>();
            int offset = 0;
            while (offset < bytes.Length)
            {
                int instructionOffset = offset;
                short code = bytes[offset++];
                if (code == 0xFE)
                {
                    if (offset >= bytes.Length) { throw new InvalidDataException("A CLR instruction prefix is truncated."); }
                    code = unchecked((short)(0xFE00 | bytes[offset++]));
                }
                if (!OpCodesByValue.TryGetValue(code, out OpCode opCode)) { throw new InvalidDataException("Unknown CLR opcode 0x" + ((ushort)code).ToString("X4") + "."); }
                object operand = null;
                switch (opCode.OperandType)
                {
                    case OperandType.InlineNone: break;
                    case OperandType.ShortInlineI: operand = unchecked((sbyte)ReadByte(bytes, ref offset)); break;
                    case OperandType.InlineI: operand = ReadInt32(bytes, ref offset); break;
                    case OperandType.InlineI8: operand = ReadInt64(bytes, ref offset); break;
                    case OperandType.ShortInlineR: operand = BitConverter.ToSingle(ReadBytes(bytes, ref offset, 4), 0); break;
                    case OperandType.InlineR: operand = BitConverter.ToDouble(ReadBytes(bytes, ref offset, 8), 0); break;
                    case OperandType.ShortInlineVar: operand = (int)ReadByte(bytes, ref offset); break;
                    case OperandType.InlineVar: operand = (int)ReadUInt16(bytes, ref offset); break;
                    case OperandType.ShortInlineBrTarget: { sbyte delta = unchecked((sbyte)ReadByte(bytes, ref offset)); operand = offset + delta; break; }
                    case OperandType.InlineBrTarget: { int delta = ReadInt32(bytes, ref offset); operand = offset + delta; break; }
                    case OperandType.InlineSwitch:
                    {
                        int count = ReadInt32(bytes, ref offset);
                        if (count < 0 || count > 65536) { throw new InvalidDataException("A CLR switch table exceeds parser limits."); }
                        int baseOffset = checked(offset + count * 4);
                        int[] targets = new int[count];
                        for (int i = 0; i < count; i++) { targets[i] = checked(baseOffset + ReadInt32(bytes, ref offset)); }
                        operand = targets;
                        break;
                    }
                    default: operand = ReadInt32(bytes, ref offset); break;
                }
                instructions.Add(new IlInstruction { Offset = instructionOffset, OpCode = opCode, Operand = operand, NextOffset = offset });
            }
            return instructions;
        }

        private static Dictionary<short, OpCode> BuildOpCodeTable()
        {
            Dictionary<short, OpCode> result = new Dictionary<short, OpCode>();
            foreach (FieldInfo field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                if (field.FieldType == typeof(OpCode)) { OpCode opCode = (OpCode)field.GetValue(null); result[opCode.Value] = opCode; }
            }
            return result;
        }

        private static SymbolicValue[] CreateLocals(MetadataReader reader, StandaloneSignatureHandle handle)
        {
            if (handle.IsNil) { return Array.Empty<SymbolicValue>(); }
            try
            {
                int count = reader.GetStandaloneSignature(handle).DecodeLocalSignature(new TypeNameProvider(reader), null).Length;
                SymbolicValue[] locals = new SymbolicValue[count];
                for (int i = 0; i < count; i++) { locals[i] = SymbolicValue.Unknown("local" + i); }
                return locals;
            }
            catch (BadImageFormatException) { return Array.Empty<SymbolicValue>(); }
        }

        private static SymbolicValue CoerceValue(SymbolicValue value, string parameterType)
        {
            if (!value.Resolved) { return value; }
            if ((parameterType == "System.Boolean" || parameterType.Contains("Boolean")) && value.Value is int integer)
            {
                return SymbolicValue.Constant(integer != 0, value.Expression);
            }
            return value;
        }

        private static bool? ToBoolean(SymbolicValue value)
        {
            if (!value.Resolved) { return null; }
            if (value.Value == null) { return false; }
            if (value.Value is bool boolean) { return boolean; }
            if (value.Value is int integer) { return integer != 0; }
            if (value.Value is long longInteger) { return longInteger != 0; }
            if (value.Value is string text) { return text.Length != 0; }
            return null;
        }

        private static void ApplyGenericStackBehaviour(OpCode opCode, List<SymbolicValue> stack)
        {
            int popCount = GetFixedStackCount(opCode.StackBehaviourPop);
            for (int i = 0; i < popCount; i++) { Pop(stack); }
            int pushCount = GetFixedStackCount(opCode.StackBehaviourPush);
            for (int i = 0; i < pushCount; i++) { Push(stack, SymbolicValue.Unknown(opCode.Name)); }
        }

        private static int GetFixedStackCount(StackBehaviour behaviour)
        {
            switch (behaviour)
            {
                case StackBehaviour.Pop0:
                case StackBehaviour.Push0: return 0;
                case StackBehaviour.Pop1:
                case StackBehaviour.Popi:
                case StackBehaviour.Popref:
                case StackBehaviour.Push1:
                case StackBehaviour.Pushi:
                case StackBehaviour.Pushi8:
                case StackBehaviour.Pushr4:
                case StackBehaviour.Pushr8:
                case StackBehaviour.Pushref: return 1;
                case StackBehaviour.Pop1_pop1:
                case StackBehaviour.Popi_pop1:
                case StackBehaviour.Popi_popi:
                case StackBehaviour.Popi_popi8:
                case StackBehaviour.Popi_popr4:
                case StackBehaviour.Popi_popr8:
                case StackBehaviour.Popref_pop1:
                case StackBehaviour.Popref_popi: return 2;
                case StackBehaviour.Popi_popi_popi:
                case StackBehaviour.Popref_popi_popi:
                case StackBehaviour.Popref_popi_popi8:
                case StackBehaviour.Popref_popi_popr4:
                case StackBehaviour.Popref_popi_popr8:
                case StackBehaviour.Popref_popi_popref: return 3;
                default: return 0;
            }
        }

        private static int GetBranchIndex(Dictionary<int, int> indexByOffset, int target, int fallback)
        {
            return indexByOffset.TryGetValue(target, out int index) ? index : fallback;
        }

        private static SymbolicValue Pop(List<SymbolicValue> stack)
        {
            if (stack.Count == 0) { return SymbolicValue.Unknown("stack-underflow"); }
            int index = stack.Count - 1;
            SymbolicValue value = stack[index];
            stack.RemoveAt(index);
            return value;
        }

        private static void Push(List<SymbolicValue> stack, SymbolicValue value) { stack.Add(value ?? SymbolicValue.Unknown("null-value")); }
        private static SymbolicValue GetLocal(SymbolicValue[] locals, int index) { return index >= 0 && index < locals.Length ? locals[index].Clone() : SymbolicValue.Unknown("local" + index); }
        private static void SetLocal(SymbolicValue[] locals, int index, SymbolicValue value) { if (index >= 0 && index < locals.Length) { locals[index] = value.Clone(); } }
        private static bool IsVoid(string typeName) { return typeName == "System.Void"; }

        private static long RvaToFileOffset(PEHeaders headers, int rva)
        {
            foreach (SectionHeader section in headers.SectionHeaders)
            {
                int span = Math.Max(section.VirtualSize, section.SizeOfRawData);
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + span) { return checked((long)section.PointerToRawData + rva - section.VirtualAddress); }
            }
            throw new InvalidDataException("The CLR resource directory RVA is outside the PE section table.");
        }

        private static long CheckedRange(long baseOffset, long relativeOffset, long length, long end)
        {
            long offset = checked(baseOffset + relativeOffset);
            ValidateRange(offset, length, end);
            return offset;
        }

        private static void ValidateRange(long offset, long length, long end)
        {
            if (offset < 0 || length < 0 || offset > end || length > end - offset)
            {
                throw new InvalidDataException("A MicaSetup resource range is outside its containing stream: offset=" + offset + ", length=" + length + ", end=" + end + ".");
            }
        }

        private static long Align(long value, int alignment) { return checked((value + alignment - 1) & ~(alignment - 1)); }

        private static string ReadBinaryString(Stream stream, long end, int maximumBytes)
        {
            int length = Read7BitEncodedInt(stream, end);
            if (length < 0 || length > maximumBytes) { throw new InvalidDataException("A .resources string exceeds the configured parser limit."); }
            ValidateRange(stream.Position, length, end);
            byte[] bytes = new byte[length];
            ReadExactly(stream, bytes, 0, length);
            return new UTF8Encoding(false, true).GetString(bytes);
        }

        private static string ReadResourceName(Stream stream, long end, int maximumBytes)
        {
            int length = Read7BitEncodedInt(stream, end);
            if (length < 0 || length > maximumBytes || (length & 1) != 0) { throw new InvalidDataException("A .resources name has an invalid UTF-16 byte length."); }
            ValidateRange(stream.Position, length, end);
            byte[] bytes = new byte[length];
            ReadExactly(stream, bytes, 0, length);
            return new UnicodeEncoding(false, false, true).GetString(bytes);
        }

        private static int Read7BitEncodedInt(Stream stream, long end)
        {
            int result = 0;
            for (int shift = 0; shift < 35; shift += 7)
            {
                if (stream.Position >= end) { throw new EndOfStreamException("A 7-bit encoded integer is truncated."); }
                byte value = ReadByte(stream);
                result |= (value & 0x7F) << shift;
                if ((value & 0x80) == 0) { return result; }
            }
            throw new InvalidDataException("A 7-bit encoded integer is malformed.");
        }

        private static byte ReadByte(Stream stream)
        {
            int value = stream.ReadByte();
            if (value < 0) { throw new EndOfStreamException(); }
            return (byte)value;
        }

        private static short ReadInt16(Stream stream) { return unchecked((short)ReadUInt16(stream)); }
        private static ushort ReadUInt16(Stream stream) { byte[] bytes = new byte[2]; ReadExactly(stream, bytes, 0, 2); return (ushort)(bytes[0] | (bytes[1] << 8)); }
        private static int ReadInt32(Stream stream) { return unchecked((int)ReadUInt32(stream)); }
        private static uint ReadUInt32(Stream stream) { byte[] bytes = new byte[4]; ReadExactly(stream, bytes, 0, 4); return (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)); }
        private static long ReadInt64(Stream stream) { return unchecked((long)ReadUInt64(stream)); }
        private static ulong ReadUInt64(Stream stream) { byte[] bytes = new byte[8]; ReadExactly(stream, bytes, 0, 8); return BitConverter.ToUInt64(bytes, 0); }
        private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count) { while (count > 0) { int read = stream.Read(buffer, offset, count); if (read <= 0) { throw new EndOfStreamException(); } offset += read; count -= read; } }

        private static byte ReadByte(byte[] bytes, ref int offset) { if (offset >= bytes.Length) { throw new EndOfStreamException("A CLR instruction is truncated."); } return bytes[offset++]; }
        private static byte[] ReadBytes(byte[] bytes, ref int offset, int count) { if (count < 0 || offset > bytes.Length - count) { throw new EndOfStreamException("A CLR instruction operand is truncated."); } byte[] result = new byte[count]; Buffer.BlockCopy(bytes, offset, result, 0, count); offset += count; return result; }
        private static ushort ReadUInt16(byte[] bytes, ref int offset) { byte[] value = ReadBytes(bytes, ref offset, 2); return BitConverter.ToUInt16(value, 0); }
        private static int ReadInt32(byte[] bytes, ref int offset) { byte[] value = ReadBytes(bytes, ref offset, 4); return BitConverter.ToInt32(value, 0); }
        private static long ReadInt64(byte[] bytes, ref int offset) { byte[] value = ReadBytes(bytes, ref offset, 8); return BitConverter.ToInt64(value, 0); }
    }
}
