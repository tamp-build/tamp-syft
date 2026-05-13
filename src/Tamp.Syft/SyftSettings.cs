namespace Tamp.Syft;

/// <summary>Common shape shared by every <c>syft</c> verb.</summary>
public abstract class SyftSettingsBase
{
    /// <summary>Working directory for the spawned syft process.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Per-invocation environment variables.</summary>
    public Dictionary<string, string> EnvironmentVariables { get; } = new();

    /// <summary>Syft configuration file(s) (<c>-c / --config</c>).</summary>
    public List<string> ConfigFiles { get; } = new();

    /// <summary>Profile(s) to apply from the config (<c>--profile</c>).</summary>
    public List<string> Profiles { get; } = new();

    /// <summary>Quiet mode (<c>-q / --quiet</c>) — suppresses all logging output.</summary>
    public bool Quiet { get; set; }

    /// <summary>Verbosity level (<c>-v</c>, <c>-vv</c>). 0 = none, 1 = info, 2 = debug. Range validated.</summary>
    public int? Verbosity { get; set; }

    protected abstract IEnumerable<string> Verb { get; }
    protected abstract void AppendArguments(List<string> args);
    protected virtual IReadOnlyList<Secret> CollectSecrets() => Array.Empty<Secret>();

    internal CommandPlan ToCommandPlan(Tool tool)
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        if (Verbosity is < 0 or > 2)
            throw new InvalidOperationException($"Verbosity must be 0, 1, or 2; got {Verbosity}.");

        var args = new List<string>(Verb);
        foreach (var cfg in ConfigFiles) { args.Add("-c"); args.Add(cfg); }
        foreach (var prof in Profiles) { args.Add("--profile"); args.Add(prof); }
        if (Quiet) args.Add("-q");
        if (Verbosity is 1) args.Add("-v");
        if (Verbosity is 2) args.Add("-vv");
        AppendArguments(args);

        return new CommandPlan
        {
            Executable = tool.Executable.Value,
            Arguments = args,
            Environment = new Dictionary<string, string>(EnvironmentVariables),
            WorkingDirectory = WorkingDirectory ?? tool.WorkingDirectory,
            Secrets = CollectSecrets(),
        };
    }
}

/// <summary>
/// Settings for <c>syft scan [SOURCE]</c> — the primary verb. Generates an SBOM for a
/// directory, file, or container image source. Outputs can be multi-target via repeated
/// <c>SetOutput</c> calls (<c>cyclonedx-json=sbom.cdx.json</c>, <c>spdx-json=sbom.spdx.json</c>,
/// etc.).
/// </summary>
public sealed class SyftScanSettings : SyftSettingsBase
{
    /// <summary>The scan target. Accepts source schemes: <c>dir:path</c>, <c>file:path</c>, <c>registry:image</c>, <c>docker:image</c>, raw image refs, etc.</summary>
    public string? Source { get; set; }

    /// <summary>Output format=path pairs (<c>-o</c>). Repeat for multi-output. Example: <c>cyclonedx-json=sbom.cdx.json</c>.</summary>
    public List<string> Outputs { get; } = new();

    /// <summary>Source scheme override (<c>--from</c>). Example: <c>registry</c>, <c>docker</c>, <c>oci-dir</c>.</summary>
    public List<string> From { get; } = new();

    /// <summary>Catalogers to add/remove/filter (<c>--select-catalogers</c>). Example: <c>+cargo</c>, <c>-npm</c>.</summary>
    public List<string> SelectCatalogers { get; } = new();

    /// <summary>Replace the default cataloger set entirely (<c>--override-default-catalogers</c>).</summary>
    public List<string> OverrideDefaultCatalogers { get; } = new();

    /// <summary>Layer scope for container images (<c>-s / --scope</c>): <c>squashed</c> (default), <c>all-layers</c>, <c>deep-squashed</c>.</summary>
    public string? Scope { get; set; }

    /// <summary>Glob exclusions (<c>--exclude</c>).</summary>
    public List<string> Excludes { get; } = new();

    /// <summary>Base path — symlinks above this directory are not followed (<c>--base-path</c>).</summary>
    public string? BasePath { get; set; }

    /// <summary>Enrichment data sources (<c>--enrich</c>): <c>all</c>, <c>golang</c>, <c>java</c>, <c>javascript</c>, <c>python</c>.</summary>
    public List<string> Enrich { get; } = new();

    /// <summary>Platform specifier for image scans (<c>--platform</c>). Example: <c>linux/arm64</c>.</summary>
    public string? Platform { get; set; }

    /// <summary>Parallelism — cataloger workers to run concurrently (<c>--parallelism</c>).</summary>
    public int? Parallelism { get; set; }

    /// <summary>Override the source name in the resulting SBOM (<c>--source-name</c>).</summary>
    public string? SourceName { get; set; }

    /// <summary>Override the source version in the resulting SBOM (<c>--source-version</c>).</summary>
    public string? SourceVersion { get; set; }

    /// <summary>Supplier identification stamped into the SBOM (<c>--source-supplier</c>).</summary>
    public string? SourceSupplier { get; set; }

    public SyftScanSettings SetSource(string source) { Source = source; return this; }
    public SyftScanSettings SetDirectorySource(string path) { Source = $"dir:{path}"; return this; }
    public SyftScanSettings SetFileSource(string path) { Source = $"file:{path}"; return this; }
    public SyftScanSettings SetImageSource(string image) { Source = image; return this; }
    public SyftScanSettings SetRegistrySource(string image) { Source = $"registry:{image}"; return this; }
    public SyftScanSettings SetDockerArchiveSource(string path) { Source = $"docker-archive:{path}"; return this; }
    public SyftScanSettings SetOciArchiveSource(string path) { Source = $"oci-archive:{path}"; return this; }
    public SyftScanSettings AddOutput(string formatEqualsPath) { Outputs.Add(formatEqualsPath); return this; }
    public SyftScanSettings AddOutputCycloneDxJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "cyclonedx-json" : $"cyclonedx-json={toFile}"); return this; }
    public SyftScanSettings AddOutputCycloneDxXml(string? toFile = null)
        { Outputs.Add(toFile is null ? "cyclonedx-xml" : $"cyclonedx-xml={toFile}"); return this; }
    public SyftScanSettings AddOutputSpdxJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "spdx-json" : $"spdx-json={toFile}"); return this; }
    public SyftScanSettings AddOutputSpdxTagValue(string? toFile = null)
        { Outputs.Add(toFile is null ? "spdx-tag-value" : $"spdx-tag-value={toFile}"); return this; }
    public SyftScanSettings AddOutputSyftJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "syft-json" : $"syft-json={toFile}"); return this; }
    public SyftScanSettings AddOutputGitHubJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "github-json" : $"github-json={toFile}"); return this; }
    public SyftScanSettings AddOutputPurls(string? toFile = null)
        { Outputs.Add(toFile is null ? "purls" : $"purls={toFile}"); return this; }
    public SyftScanSettings AddFrom(string scheme) { From.Add(scheme); return this; }
    public SyftScanSettings AddSelectCataloger(string spec) { SelectCatalogers.Add(spec); return this; }
    public SyftScanSettings AddOverrideDefaultCataloger(string name) { OverrideDefaultCatalogers.Add(name); return this; }
    public SyftScanSettings SetScope(string scope) { Scope = scope; return this; }
    public SyftScanSettings AddExclude(string glob) { Excludes.Add(glob); return this; }
    public SyftScanSettings AddExcludes(params string[] globs) { Excludes.AddRange(globs); return this; }
    public SyftScanSettings SetBasePath(string path) { BasePath = path; return this; }
    public SyftScanSettings AddEnrich(string source) { Enrich.Add(source); return this; }
    public SyftScanSettings SetPlatform(string platform) { Platform = platform; return this; }
    public SyftScanSettings SetParallelism(int n) { Parallelism = n; return this; }
    public SyftScanSettings SetSourceName(string name) { SourceName = name; return this; }
    public SyftScanSettings SetSourceVersion(string version) { SourceVersion = version; return this; }
    public SyftScanSettings SetSourceSupplier(string supplier) { SourceSupplier = supplier; return this; }
    public SyftScanSettings AddConfigFile(string path) { ConfigFiles.Add(path); return this; }
    public SyftScanSettings AddProfile(string profile) { Profiles.Add(profile); return this; }
    public SyftScanSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public SyftScanSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public SyftScanSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    public SyftScanSettings SetEnvironmentVariable(string name, string value) { EnvironmentVariables[name] = value; return this; }

    protected override IEnumerable<string> Verb => new[] { "scan" };

    protected override void AppendArguments(List<string> args)
    {
        if (string.IsNullOrEmpty(Source))
            throw new InvalidOperationException(
                "Source is required for `syft scan` — set via SetDirectorySource(path), SetImageSource(image), SetRegistrySource(image), or SetSource(rawScheme).");
        if (Parallelism is int p && p < 1)
            throw new InvalidOperationException($"Parallelism must be >= 1; got {p}.");
        if (!string.IsNullOrEmpty(Scope) && Scope is not ("squashed" or "all-layers" or "deep-squashed"))
            throw new InvalidOperationException(
                $"Scope must be one of 'squashed', 'all-layers', 'deep-squashed'; got '{Scope}'.");

        // Positional source comes first per `syft scan [SOURCE] [flags]`.
        args.Add(Source!);

        foreach (var o in Outputs) { args.Add("-o"); args.Add(o); }
        foreach (var f in From) { args.Add("--from"); args.Add(f); }
        foreach (var c in SelectCatalogers) { args.Add("--select-catalogers"); args.Add(c); }
        foreach (var c in OverrideDefaultCatalogers) { args.Add("--override-default-catalogers"); args.Add(c); }
        if (!string.IsNullOrEmpty(Scope)) { args.Add("-s"); args.Add(Scope!); }
        foreach (var x in Excludes) { args.Add("--exclude"); args.Add(x); }
        if (!string.IsNullOrEmpty(BasePath)) { args.Add("--base-path"); args.Add(BasePath!); }
        foreach (var e in Enrich) { args.Add("--enrich"); args.Add(e); }
        if (!string.IsNullOrEmpty(Platform)) { args.Add("--platform"); args.Add(Platform!); }
        if (Parallelism is int par) { args.Add("--parallelism"); args.Add(par.ToString()); }
        if (!string.IsNullOrEmpty(SourceName)) { args.Add("--source-name"); args.Add(SourceName!); }
        if (!string.IsNullOrEmpty(SourceVersion)) { args.Add("--source-version"); args.Add(SourceVersion!); }
        if (!string.IsNullOrEmpty(SourceSupplier)) { args.Add("--source-supplier"); args.Add(SourceSupplier!); }
    }
}

/// <summary>
/// Settings for <c>syft convert [SOURCE-SBOM] -o [FORMAT]</c> — convert between SBOM formats.
/// </summary>
public sealed class SyftConvertSettings : SyftSettingsBase
{
    /// <summary>Source SBOM path, or <c>-</c> for stdin.</summary>
    public string? SourceSbom { get; set; }

    /// <summary>Output format=path pairs (<c>-o</c>).</summary>
    public List<string> Outputs { get; } = new();

    /// <summary>Template path for <c>template</c> output format (<c>-t</c>).</summary>
    public string? TemplatePath { get; set; }

    public SyftConvertSettings SetSourceSbom(string path) { SourceSbom = path; return this; }
    public SyftConvertSettings ReadFromStdin() { SourceSbom = "-"; return this; }
    public SyftConvertSettings AddOutput(string formatEqualsPath) { Outputs.Add(formatEqualsPath); return this; }
    public SyftConvertSettings AddOutputCycloneDxJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "cyclonedx-json" : $"cyclonedx-json={toFile}"); return this; }
    public SyftConvertSettings AddOutputSpdxJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "spdx-json" : $"spdx-json={toFile}"); return this; }
    public SyftConvertSettings AddOutputSpdxTagValue(string? toFile = null)
        { Outputs.Add(toFile is null ? "spdx-tag-value" : $"spdx-tag-value={toFile}"); return this; }
    public SyftConvertSettings SetTemplatePath(string path) { TemplatePath = path; return this; }
    public SyftConvertSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public SyftConvertSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public SyftConvertSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }

    protected override IEnumerable<string> Verb => new[] { "convert" };

    protected override void AppendArguments(List<string> args)
    {
        if (string.IsNullOrEmpty(SourceSbom))
            throw new InvalidOperationException(
                "SourceSbom is required for `syft convert` — set via SetSourceSbom(path) or ReadFromStdin().");
        if (Outputs.Count == 0)
            throw new InvalidOperationException(
                "At least one output format is required for `syft convert` — use AddOutputCycloneDxJson() / AddOutputSpdxJson() / AddOutput(...).");

        args.Add(SourceSbom!);
        foreach (var o in Outputs) { args.Add("-o"); args.Add(o); }
        if (!string.IsNullOrEmpty(TemplatePath)) { args.Add("-t"); args.Add(TemplatePath!); }
    }
}

/// <summary>
/// Settings for <c>syft attest [IMAGE] --output [FORMAT]</c> — generate an SBOM as an in-toto
/// attestation predicate and upload it alongside the container image in the registry. Pairs with
/// cosign for signing.
/// </summary>
public sealed class SyftAttestSettings : SyftSettingsBase
{
    /// <summary>The container image reference to attest (positional argument).</summary>
    public string? Image { get; set; }

    /// <summary>Output format=path pairs (<c>-o / --output</c>).</summary>
    public List<string> Outputs { get; } = new();

    /// <summary>Signing key path (<c>-k / --key</c>). For unencrypted keys.</summary>
    public string? Key { get; set; }

    /// <summary>Signing-key password (cosign-style env-routed). Modeled as <see cref="Secret"/>.</summary>
    public Secret? KeyPassword { get; set; }

    public SyftAttestSettings SetImage(string image) { Image = image; return this; }
    public SyftAttestSettings AddOutput(string formatEqualsPath) { Outputs.Add(formatEqualsPath); return this; }
    public SyftAttestSettings AddOutputCycloneDxJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "cyclonedx-json" : $"cyclonedx-json={toFile}"); return this; }
    public SyftAttestSettings AddOutputSpdxJson(string? toFile = null)
        { Outputs.Add(toFile is null ? "spdx-json" : $"spdx-json={toFile}"); return this; }
    public SyftAttestSettings SetKey(string path) { Key = path; return this; }
    public SyftAttestSettings SetKeyPassword(Secret password) { KeyPassword = password; return this; }
    public SyftAttestSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public SyftAttestSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public SyftAttestSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    public SyftAttestSettings SetEnvironmentVariable(string name, string value) { EnvironmentVariables[name] = value; return this; }

    protected override IEnumerable<string> Verb => new[] { "attest" };

    protected override IReadOnlyList<Secret> CollectSecrets()
        => KeyPassword is null ? Array.Empty<Secret>() : new[] { KeyPassword };

    protected override void AppendArguments(List<string> args)
    {
        if (string.IsNullOrEmpty(Image))
            throw new InvalidOperationException(
                "Image is required for `syft attest` — set via SetImage(imageRef).");
        if (Outputs.Count == 0)
            throw new InvalidOperationException(
                "At least one output format is required for `syft attest` — use AddOutputCycloneDxJson() / AddOutputSpdxJson().");

        // syft attest takes the image as positional; flags follow.
        args.Add(Image!);
        foreach (var o in Outputs) { args.Add("--output"); args.Add(o); }
        if (!string.IsNullOrEmpty(Key)) { args.Add("-k"); args.Add(Key!); }
        // The cosign convention is to pass the key password via env (COSIGN_PASSWORD), not flag —
        // we route the Secret through EnvironmentVariables so it's masked + not in the arg list.
        if (KeyPassword is not null)
            EnvironmentVariables["COSIGN_PASSWORD"] = KeyPassword.Reveal();
    }
}

/// <summary>Settings for <c>syft version</c> — print syft binary version.</summary>
public sealed class SyftVersionSettings : SyftSettingsBase
{
    public SyftVersionSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public SyftVersionSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override IEnumerable<string> Verb => new[] { "version" };
    protected override void AppendArguments(List<string> args) { }
}

/// <summary>Settings for <c>syft cataloger list</c> — print available catalogers and their config.</summary>
public sealed class SyftCatalogerListSettings : SyftSettingsBase
{
    public SyftCatalogerListSettings SetQuiet(bool v = true) { Quiet = v; return this; }
    public SyftCatalogerListSettings SetVerbosity(int level) { Verbosity = level; return this; }
    public SyftCatalogerListSettings SetWorkingDirectory(string? cwd) { WorkingDirectory = cwd; return this; }
    protected override IEnumerable<string> Verb => new[] { "cataloger", "list" };
    protected override void AppendArguments(List<string> args) { }
}
