﻿#nullable disable
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Analyzer.Utilities.PooledObjects;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Config
{
    internal class TaintConfiguration
    {
        private WellKnownTypeProvider WellKnownTypeProvider { get; set; }

        private ImmutableDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SourceInfo>>> SourceSymbolMap { get; set; }

        private ImmutableDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SanitizerInfo>>> SanitizerSymbolMap { get; set; }

        private ImmutableDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SinkInfo>>> SinkSymbolMap { get; set; }

        public TaintedDataSymbolMap<SourceInfo> GetSourceSymbolMap(SinkKind sinkKind)
        {
            return this.GetFromMap<SourceInfo>(sinkKind, this.SourceSymbolMap);
        }

        public TaintedDataSymbolMap<SanitizerInfo> GetSanitizerSymbolMap(SinkKind sinkKind)
        {
            return this.GetFromMap<SanitizerInfo>(sinkKind, this.SanitizerSymbolMap);
        }

        public TaintedDataSymbolMap<SinkInfo> GetSinkSymbolMap(SinkKind sinkKind)
        {
            return this.GetFromMap<SinkInfo>(sinkKind, this.SinkSymbolMap);
        }

        private TaintedDataSymbolMap<T> GetFromMap<T>(SinkKind sinkKind, ImmutableDictionary<SinkKind, Lazy<TaintedDataSymbolMap<T>>> map)
            where T : ITaintedDataInfo
        {
            if (map.TryGetValue(sinkKind, out Lazy<TaintedDataSymbolMap<T>> lazySourceSymbolMap))
            {
                return lazySourceSymbolMap.Value;
            }
            else
            {
                Debug.Fail($"SinkKind {sinkKind} entry missing from {typeof(T).Name} map");
                return new TaintedDataSymbolMap<T>(this.WellKnownTypeProvider, Enumerable.Empty<T>());
            }
        }

        public TaintConfiguration(Compilation compilation, ConfigData config)
        {
            WellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);
            using PooledDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SourceInfo>>> sourceSymbolMapBuilder =
                PooledDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SourceInfo>>>.GetInstance();
            using PooledDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SanitizerInfo>>> sanitizerSymbolMapBuilder =
                PooledDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SanitizerInfo>>>.GetInstance();
            using PooledDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SinkInfo>>> sinkSymbolMapBuilder =
                PooledDictionary<SinkKind, Lazy<TaintedDataSymbolMap<SinkInfo>>>.GetInstance();

            // For tainted data rules with the same set of sources, we'll reuse the same TaintedDataSymbolMap<SourceInfo> instance.
            // Same for sanitizers.
            using PooledDictionary<ImmutableHashSet<SourceInfo>, Lazy<TaintedDataSymbolMap<SourceInfo>>> sourcesToSymbolMap =
                PooledDictionary<ImmutableHashSet<SourceInfo>, Lazy<TaintedDataSymbolMap<SourceInfo>>>.GetInstance();
            using PooledDictionary<ImmutableHashSet<SanitizerInfo>, Lazy<TaintedDataSymbolMap<SanitizerInfo>>> sanitizersToSymbolMap =
                PooledDictionary<ImmutableHashSet<SanitizerInfo>, Lazy<TaintedDataSymbolMap<SanitizerInfo>>>.GetInstance();

            // Build a mapping of (sourceSet, sanitizerSet) -> (sinkKinds, sinkSet), so we'll reuse the same TaintedDataSymbolMap<SinkInfo> instance.
            using PooledDictionary<(ImmutableHashSet<SourceInfo> SourceInfos, ImmutableHashSet<SanitizerInfo> SanitizerInfos), (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SinkInfo>.Builder SinkInfos)> sourceSanitizersToSinks =
                PooledDictionary<(ImmutableHashSet<SourceInfo> SourceInfos, ImmutableHashSet<SanitizerInfo> SanitizerInfos), (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SinkInfo>.Builder SinkInfos)>.GetInstance();

            // Using LazyThreadSafetyMode.ExecutionAndPublication to avoid instantiating multiple times.
            foreach (SinkKind sinkKind in Enum.GetValues(typeof(SinkKind)))
            {
                ImmutableHashSet<SourceInfo> sources = GetSourceInfos(sinkKind, config);
                if (!sourcesToSymbolMap.TryGetValue(sources, out Lazy<TaintedDataSymbolMap<SourceInfo>> lazySourceSymbolMap))
                {
                    lazySourceSymbolMap = new Lazy<TaintedDataSymbolMap<SourceInfo>>(
                        () => { return new TaintedDataSymbolMap<SourceInfo>(WellKnownTypeProvider, sources); },
                        LazyThreadSafetyMode.ExecutionAndPublication);
                    sourcesToSymbolMap.Add(sources, lazySourceSymbolMap);
                }

                sourceSymbolMapBuilder.Add(sinkKind, lazySourceSymbolMap);

                ImmutableHashSet<SanitizerInfo> sanitizers = GetSanitizerInfos(sinkKind, config);
                if (!sanitizersToSymbolMap.TryGetValue(sanitizers, out Lazy<TaintedDataSymbolMap<SanitizerInfo>> lazySanitizerSymbolMap))
                {
                    lazySanitizerSymbolMap = new Lazy<TaintedDataSymbolMap<SanitizerInfo>>(
                        () => { return new TaintedDataSymbolMap<SanitizerInfo>(WellKnownTypeProvider, sanitizers); },
                        LazyThreadSafetyMode.ExecutionAndPublication);
                    sanitizersToSymbolMap.Add(sanitizers, lazySanitizerSymbolMap);
                }

                sanitizerSymbolMapBuilder.Add(sinkKind, lazySanitizerSymbolMap);

                ImmutableHashSet<SinkInfo> sinks = GetSinkInfos(sinkKind, config);
                if (!sourceSanitizersToSinks.TryGetValue((sources, sanitizers), out (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SinkInfo>.Builder SinkInfos) sinksPair))
                {
                    sinksPair = (ImmutableHashSet.CreateBuilder<SinkKind>(), ImmutableHashSet.CreateBuilder<SinkInfo>());
                    sourceSanitizersToSinks.Add((sources, sanitizers), sinksPair);
                }

                sinksPair.SinkKinds.Add(sinkKind);
                sinksPair.SinkInfos.UnionWith(sinks);
            }

            foreach (KeyValuePair<(ImmutableHashSet<SourceInfo> SourceInfos, ImmutableHashSet<SanitizerInfo> SanitizerInfos), (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SinkInfo>.Builder SinkInfos)> kvp in sourceSanitizersToSinks)
            {
                ImmutableHashSet<SinkInfo> sinks = kvp.Value.SinkInfos.ToImmutable();
                Lazy<TaintedDataSymbolMap<SinkInfo>> lazySinkSymbolMap = new Lazy<TaintedDataSymbolMap<SinkInfo>>(
                    () => { return new TaintedDataSymbolMap<SinkInfo>(WellKnownTypeProvider, sinks); },
                    LazyThreadSafetyMode.ExecutionAndPublication);
                foreach (SinkKind sinkKind in kvp.Value.SinkKinds)
                {
                    sinkSymbolMapBuilder.Add(sinkKind, lazySinkSymbolMap);
                }
            }

            SourceSymbolMap = sourceSymbolMapBuilder.ToImmutableDictionary();
            SanitizerSymbolMap = sanitizerSymbolMapBuilder.ToImmutableDictionary();
            SinkSymbolMap = sinkSymbolMapBuilder.ToImmutableDictionary();
        }

        private ImmutableHashSet<SourceInfo> GetSourceInfos(SinkKind sinkKind, ConfigData config)
        {
            return null;
        }

        private ImmutableHashSet<SanitizerInfo> GetSanitizerInfos(SinkKind sinkKind, ConfigData config)
        {
            return null;
        }

        private ImmutableHashSet<SinkInfo> GetSinkInfos(SinkKind sinkKind, ConfigData config)
        {
            return null;
        }
    }

    /// <summary>
    /// Internal configuration optimized for queries
    /// </summary>
    internal class Configuration
    {
        private Configuration()
        {
            _PasswordValidatorRequiredProperties = new HashSet<string>();
            PasswordValidatorRequiredProperties = new ReadOnlyHashSet<string>(_PasswordValidatorRequiredProperties);

            ConfigurationBehavior               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Behavior                            = new Dictionary<string, MethodBehavior>();

            _TaintEntryPoints = new HashSet<string>();
            TaintEntryPoints  = new ReadOnlyHashSet<string>(_TaintEntryPoints);

            _CsrfGroupsList = new LinkedList<CsrfNamedGroup>();
            _CsrfGroups = new Dictionary<string, LinkedListNode<CsrfNamedGroup>>();

            _PasswordFields = new HashSet<string>();
            PasswordFields  = new ReadOnlyHashSet<string>(_PasswordFields);

            _ConstantFields = new HashSet<string>();
            ConstantFields  = new ReadOnlyHashSet<string>(_ConstantFields);

            _TaintTypeNameToBit = new Dictionary<string, int>();
        }

        private readonly Lazy<TaintConfiguration> CachedTaintConfiguration;
        public TaintConfiguration TaintConfiguration { get { return CachedTaintConfiguration.Value; } }

        public Configuration(ConfigData configData, Compilation compilation) : this()
        {
            CachedTaintConfiguration = new Lazy<TaintConfiguration>(() => new TaintConfiguration(compilation, configData));

            if (configData.TaintTypes != null)
                RegisterTaintTypes(configData.TaintTypes);

            ReportAnalysisCompletion           = configData.ReportAnalysisCompletion           ?? false;
            AuditMode                          = configData.AuditMode                          ?? false;
            MinimumPasswordValidatorProperties = configData.MinimumPasswordValidatorProperties ?? 0;
            PasswordValidatorRequiredLength    = configData.PasswordValidatorRequiredLength    ?? 0;

            if (configData.PasswordValidatorRequiredProperties != null)
            {
                foreach (var data in configData.PasswordValidatorRequiredProperties)
                {
                    _PasswordValidatorRequiredProperties.Add(data);
                }
            }

            foreach (var data in configData.Behavior)
            {
                ConfigurationBehavior[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var source in configData.TaintEntryPoints)
            {
                if (source.Value?.Method?.ArgTypes != null)
                    throw new Exception("Taint entry point ArgTypes are not supported.");

                _TaintEntryPoints.Add(MethodBehaviorHelper.GetMethodBehaviorKey(source.Value.Namespace,
                                                                                source.Value.ClassName,
                                                                                source.Value.Name,
                                                                                source.Value?.Method?.ArgTypes));
            }

            foreach (var data in configData.CsrfProtection)
            {
                AddCsrfProtectionToConfiguration(data.Value);
            }

            if (configData.PasswordFields != null)
            {
                foreach (var data in configData.PasswordFields)
                {
                    _PasswordFields.Add(data.ToUpperInvariant());
                }
            }

            if (configData.WebConfigFiles != null)
            {
                WebConfigFilesRegex = new Regex(configData.WebConfigFiles, RegexOptions.IgnoreCase | RegexOptions.Compiled);
            }

            foreach (var data in configData.ConstantFields)
            {
                _ConstantFields.Add(data);
            }
        }

        public bool ReportAnalysisCompletion           { get; private set; }
        public bool AuditMode                          { get; private set; }
        public int  PasswordValidatorRequiredLength    { get; private set; }
        public int  MinimumPasswordValidatorProperties { get; private set; }

        private readonly HashSet<string>         _PasswordValidatorRequiredProperties;
        public           ReadOnlyHashSet<string> PasswordValidatorRequiredProperties { get; }

        private readonly HashSet<string>         _TaintEntryPoints;
        public           ReadOnlyHashSet<string> TaintEntryPoints { get; }

        private readonly HashSet<string>         _PasswordFields;
        public           ReadOnlyHashSet<string> PasswordFields { get; }

        public Regex                             WebConfigFilesRegex { get; private set; }

        private readonly HashSet<string>         _ConstantFields;
        public           ReadOnlyHashSet<string> ConstantFields { get; }

        private Dictionary<string, int> _TaintTypeNameToBit;
        public IReadOnlyDictionary<string, int> TaintTypeNameToBit => _TaintTypeNameToBit;

        // is needed to have allow merging by configuration Id
        private readonly Dictionary<string, KeyValuePair<string, MethodBehavior>> ConfigurationBehavior;
        // once merged the configuration Id is not used: the key is method signature parts
        public IReadOnlyDictionary<string, MethodBehavior> Behavior { get; private set; }

        private readonly LinkedList<CsrfNamedGroup>                         _CsrfGroupsList; // ensure groups are exposed in the same order they were added
        private readonly Dictionary<string, LinkedListNode<CsrfNamedGroup>> _CsrfGroups;
        public IReadOnlyCollection<CsrfNamedGroup> CsrfGoups => _CsrfGroupsList;

        private void RegisterTaintTypes(IEnumerable<string> typeNames)
        {
            var values = Enum.GetValues(typeof(SinkKind));
            int nexVal = (int)values.GetValue(values.Length - 1);

            foreach (var typeName in typeNames)
            {
                if (TaintTypeNameToBit.ContainsKey(typeName))
                    throw new Exception("Duplicate taint type");

                _TaintTypeNameToBit[typeName] = nexVal++;
            }
        }

        private IReadOnlyList<Condition> GetPreConditions(Dictionary<object, object> ifSection,
                                                          IReadOnlyDictionary<int, PostCondition> mainPostConditions)
        {
            if (ifSection == null)
                return null;

            if (!ifSection.TryGetValue("Condition", out object value))
                return null;

            var configConditions = (Dictionary<object, object>)value;

            if (!ifSection.TryGetValue("Then", out value))
                return null;

            var then = (Dictionary<object, object>)value;

            var conditions = new Dictionary<int, object>(configConditions.Count);
            foreach (var argument in configConditions)
            {
                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid precondition format");

                var idx = int.Parse((string)argument.Key);
                if (d.Count != 1)
                    throw new Exception("Only one precondition per argument is supported");

                var condition = d.First();
                if ((string)condition.Key != "Value")
                    throw new Exception("Only 'Value' preconditions are supported");

                var conditionValue = (string)condition.Value;
                if (int.TryParse(conditionValue, out var intVal))
                    conditions.Add(idx, intVal);
                else
                    conditions.Add(idx, conditionValue);
            }

            return new List<Condition> { new Condition(conditions, GetPostConditions(then, mainPostConditions)) };
        }

        private int GetTaintBits(IEnumerable<object> taintTypes)
        {
            int bits = 0;
            foreach (var type in taintTypes)
            {
                var taintType = (string)type;
                bits |= GetTaintBits(taintType, out var negate);
                if (negate)
                    throw new Exception("Negation in arrays is not supported");
            }

            if (bits == 0)
                throw new Exception("Unknown taint type");

            return bits;
        }

        private int GetTaintBits(string taintType, out bool negate)
        {
            negate = false;
            if (taintType.StartsWith("~"))
            {
                negate = true;
                taintType = taintType.Substring(1);
            }

            int taintBits;
            switch (taintType)
            {
                case "Tainted":
                    taintBits = (int)VariableTaint.Tainted;
                    break;
                case "Safe":
                    taintBits = (int)VariableTaint.Safe;
                    break;
                case "Constant":
                    taintBits = (int)VariableTaint.Constant;
                    break;
                default:
                    taintBits = TaintTypeNameToBit[taintType];
                    break;
            }

            return taintBits;
        }

        private IReadOnlyDictionary<int, int> GetArguments(IReadOnlyList<object> arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var outArguments = new Dictionary<int, int>(arguments.Count);
            foreach (var argument in arguments)
            {
                switch (argument)
                {
                    case string s:
                    {
                        int i;
                        switch (s)
                        {
                            case "This":
                                i = (int)ArgumentIndex.This;
                                break;
                            default:
                                i = int.Parse(s);
                                if (i < 0)
                                    throw new Exception("Invalid argument index or name");

                                break;
                        }

                        outArguments.Add(i, (int)VariableTaint.Safe);
                        break;
                    }
                    case Dictionary<object, object> d when d.Count == 1:
                    {
                        var indexToTaintType = d.First();
                        switch (indexToTaintType.Value)
                        {
                            case string taintType:
                            {
                                var i = int.Parse((string)indexToTaintType.Key);
                                if (i < 0)
                                    throw new Exception("Argument index cannot be negative");

                                var taintBit = TaintTypeNameToBit[taintType]; // "Tainted" is not supported
                                outArguments.Add(i, taintBit);
                                break;
                            }
                            case List<object> taintTypes:
                            {
                                int bits = GetTaintBits(taintTypes);
                                outArguments.Add(int.Parse((string)indexToTaintType.Key), bits);
                                break;
                            }
                            default:
                                throw new Exception("Unknown taint type");
                        }

                        break;
                    }
                    default:
                        throw new Exception("Unknown behavior argument");
                }
            }

            return outArguments;
        }

        private IReadOnlyDictionary<int, InjectableArgument> GetInjectableArguments(IReadOnlyList<object> arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var outArguments = new Dictionary<int, InjectableArgument>(arguments.Count);
            foreach (var argument in arguments)
            {
                switch (argument)
                {
                    case Dictionary<object, object> d when d.Count == 1:
                        {
                            var rule = d.First();
                            var ruleId = (string)rule.Key;
                            switch (rule.Value)
                            {
                                case string idxText:
                                {
                                    int idx = int.Parse(idxText);
                                    if (idx < 0)
                                        throw new Exception("Argument index cannot be negative");

                                    outArguments.Add(idx, new InjectableArgument((int)VariableTaint.Safe, ruleId));
                                    break;
                                }
                                case List<object> indices:
                                    foreach (var index in indices)
                                    {
                                        switch (index)
                                        {
                                            case string idxText:
                                            {
                                                int idx = int.Parse(idxText);
                                                if (idx < 0)
                                                    throw new Exception("Argument index cannot be negative");

                                                outArguments.Add(idx, new InjectableArgument((int)VariableTaint.Safe, ruleId));
                                                break;
                                            }
                                            case Dictionary<object, object> idxToTaints when idxToTaints.Count == 1:
                                            {
                                                var idxToTaint = idxToTaints.First();
                                                var idxText = (string)idxToTaint.Key;
                                                int idx = int.Parse(idxText);
                                                if (idx < 0)
                                                    throw new Exception("Argument index cannot be negative");

                                                var taintBit = GetTaintBits((string)idxToTaint.Value, out var negate);
                                                outArguments.Add(idx, new InjectableArgument(taintBit, ruleId, negate));
                                                break;
                                            }
                                            default:
                                                throw new Exception("Unknown behavior argument");
                                        }
                                    }
                                    break;
                                default:
                                    throw new Exception("Unknown behavior argument");
                            }
                            break;
                        }
                    default:
                        throw new Exception("Unknown behavior argument");
                }
            }

            return outArguments;
        }

        private IReadOnlyDictionary<int, PostCondition> GetPostConditions(IReadOnlyDictionary<object, object> arguments,
                                                                          IReadOnlyDictionary<int, PostCondition> defaultPostConditions = null)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var conditions = new Dictionary<int, PostCondition>(arguments.Count);
            foreach (var argument in arguments)
            {
                var argKey = (string)argument.Key;
                if (argKey == "ArgTypes" || argKey == "If" || argKey == "InjectableArguments" || argKey == "Condition")
                    continue;

                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid postcondition format");

                int idx;
                switch (argKey)
                {
                    case "Returns":
                        idx = (int)ArgumentIndex.Returns;
                        break;
                    case "This":
                        idx = (int)ArgumentIndex.This;
                        break;
                    default:
                        idx = int.Parse(argKey);
                        if (idx < 0)
                            throw new Exception("Invalid argument index or name");

                        break;
                }

                int                   taintBit           = 0;
                ImmutableHashSet<int> taintFromArguments = null;

                foreach (var condition in d)
                {
                    var conditionKey = (string)condition.Key;
                    switch (conditionKey)
                    {
                        case "Taint":
                            switch (condition.Value)
                            {
                                case string taintType:
                                    taintBit = GetTaintBits(taintType, out var negate);
                                    if (negate)
                                        throw new Exception("Negation in postconditions is not supported");
                                break;
                                case List<object> taintTypes:
                                    taintBit = GetTaintBits(taintTypes);
                                    break;
                            }

                            break;
                        case "TaintFromArguments":
                            var taintFrom = (List<object>)condition.Value;
                            if (taintFrom != null && taintFrom.Count == 0)
                            {
                                throw new Exception("Do not specify 'TaintFromArguments' or provide at least one value");
                            }

                            var args = GetArguments(taintFrom);
                            if (args.Values.Any(x => x != (int)VariableTaint.Safe))
                                throw new Exception("'TaintFromArguments' supports only array of indices");

                            taintFromArguments = args.Keys.ToImmutableHashSet();
                            break;
                        default:
                            throw new Exception("Only 'Taint' and 'TaintFromArguments' are supported in postconditions");
                    }
                }

                if (defaultPostConditions != null)
                {
                    if (taintBit == 0)
                        taintBit = defaultPostConditions[idx].Taint;

                    if (taintFromArguments == null)
                        taintFromArguments = defaultPostConditions[idx].TaintFromArguments;
                }

                conditions.Add(idx, new PostCondition(taintBit, taintFromArguments));
            }

            return conditions;
        }

        private InjectableArgument GetField(object value)
        {
            if (value == null)
                return null;

            switch (value)
            {
                case string s:
                    return new InjectableArgument((int)VariableTaint.Safe, s);
                case List<object> taintTypes when taintTypes.Count == 1:
                {
                    var types = (Dictionary<object, object>)taintTypes.First();
                    if (types.Count != 1)
                        throw new Exception("Unknown injectable argument");

                    var t = types.First();
                    var taintBits = GetTaintBits((string)t.Value, out var negate);
                    return new InjectableArgument(taintBits, (string)t.Key, negate);
                }
                default:
                    throw new Exception("Unknown injectable argument");
            }
        }

        private readonly char[] Parenthesis = { '(', ')' };

        private void ValidateArgTypes(string argTypes, string nameSpace, string className, string name)
        {
            if (argTypes == null)
                return;

            if (argTypes.Length == 0)
                throw new Exception($"Do not specify 'ArgTypes:' in {nameSpace}.{className}.{name} to match any overload");

            if (argTypes.Trim() != argTypes)
                throw new Exception($"Leading or trailing white space in {nameSpace}.{className}.{name}");

            if (argTypes[0] != '(' || argTypes[argTypes.Length - 1] != ')')
                throw new Exception($"Invalid parenthesis in {nameSpace}.{className}.{name}");

            argTypes = argTypes.Substring(1, argTypes.Length - 2);
            if (argTypes.IndexOfAny(Parenthesis) != -1)
                throw new Exception($"Parenthesis detected inside of 'ArgTypes:' in {nameSpace}.{className}.{name}");

            if (argTypes != string.Empty)
            {
                foreach (var argType in argTypes.Split(new[] { ", " }, StringSplitOptions.None))
                {
                    if (argType.Trim() != argType)
                        throw new Exception(
                            $"Leading or trailing white space in argument of {nameSpace}.{className}.{name}");

                    if (!argType.Contains(".") && !argType.Equals("dynamic"))
                        throw new Exception($"Argument type lacks namespace in {nameSpace}.{className}.{name}");

                    if (argType.Contains("this "))
                        throw new Exception($"'this' keyword should be omitted in {nameSpace}.{className}.{name}");

                    var arg = argType;
                    if (argType.Contains("params "))
                        arg = argType.Replace("params ", "");
                    if (argType.Contains("out "))
                        arg = argType.Replace("out ", "");

                    if (arg.Contains(" "))
                        throw new Exception($"Argument name should be omitted in {nameSpace}.{className}.{name}");
                }
            }
        }

        private void ValidateCondition(IDictionary<object, object> condition)
        {
            foreach (var key in condition.Keys.ToList())
            {
                int conditionIndex;
                var val = condition[key];

                if (key is int)
                {
                    conditionIndex = (int)key;
                }
                else
                {
                    if (!(key is string keyString) || !int.TryParse(keyString, out conditionIndex))
                        throw new Exception("Condition key must be an argument index");

                    // force condition to have a integer typed keys
                    condition.Remove(key);
                    condition[conditionIndex] = val;
                }

                if (conditionIndex < 0)
                    throw new Exception("Condition key must be an argument index >= 0");

                if (!(val is IReadOnlyDictionary<object, object> valDict))
                    throw new Exception("Condition value must be a dictionary");

                if (valDict.Count != 1)
                    throw new Exception("Condition dictionary must have a single value");

                if (!valDict.TryGetValue("Value", out var conditionValue))
                    throw new Exception("Condition dictionary must contain 'Value'");

                if (!(conditionValue is int) && !(conditionValue is bool))
                {
                    var updatedValueDict = new Dictionary<object, object>(1);

                    var asStr = conditionValue as string;

                    if (int.TryParse(asStr, out var asInt))
                    {
                        updatedValueDict["Value"] = asInt;
                    }
                    else if (bool.TryParse(asStr, out var asBool))
                    {
                        updatedValueDict["Value"] = asBool;
                    }
                    else
                    {
                        throw new Exception("Condition value must be a integer, or boolean");
                    }

                    condition[conditionIndex] = updatedValueDict;
                }
            }
        }

        private KeyValuePair<string, MethodBehavior> CreateBehavior(object behavior)
        {
            var behaviorDict = (Dictionary<object, object>)behavior;

            string nameSpace = null;
            if (behaviorDict.TryGetValue("Namespace", out object value))
                nameSpace = (string)value;

            string className = null;
            if (behaviorDict.TryGetValue("ClassName", out value))
                className = (string)value;

            string name = null;
            if (behaviorDict.TryGetValue("Name", out value))
                name = (string)value;

            string                     argTypes            = null;
            Dictionary<object, object> ifCondition         = null;
            IReadOnlyList<object>      injectableArguments = null;
            Dictionary<object, object> condition = null;

            Dictionary<object, object> method = null;
            if (behaviorDict.TryGetValue("Method", out value))
            {
                method = (Dictionary<object, object>)value;
                if (method.TryGetValue("ArgTypes", out value))
                {
                    argTypes = (string)value;
                    ValidateArgTypes(argTypes, nameSpace, className, name);
                }

                if (method.TryGetValue("If", out value))
                    ifCondition = (Dictionary<object, object>)value;

                if (method.TryGetValue("InjectableArguments", out value))
                    injectableArguments = (IReadOnlyList<object>)value;

                if (method.TryGetValue("Condition", out value))
                {
                    condition = (Dictionary<object, object>)value;
                    ValidateCondition(condition);
                }
            }

            object injectable = null;

            if (behaviorDict.TryGetValue("Field", out value))
            {
                var field = (Dictionary<object, object>)value;

                if (field.TryGetValue("Injectable", out value))
                    injectable = value;
            }

            var key = MethodBehaviorHelper.GetMethodBehaviorKey(nameSpace, className, name, argTypes);

            var mainPostConditions = GetPostConditions(method);
            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(condition,
                                                                                    GetPreConditions(ifCondition, mainPostConditions),
                                                                                    mainPostConditions,
                                                                                    GetInjectableArguments(injectableArguments),
                                                                                    GetField(injectable)));
        }

        public void AddCsrfProtectionToConfiguration(CsrfProtectionData csrfData)
        {
            if (string.IsNullOrWhiteSpace(csrfData.Name))
                throw new Exception($"{nameof(CsrfProtectionData.Name)} is required in CsrfProtection");

            if (!_CsrfGroups.TryGetValue(csrfData.Name, out var curGroupNode))
            {
                var curGroup = new CsrfNamedGroup(csrfData);
                var node = _CsrfGroupsList.AddLast(curGroup);
                _CsrfGroups.Add(csrfData.Name, node);
            }
            else
            {
                curGroupNode.Value.AddFrom(csrfData);
            }
        }
    }
}
