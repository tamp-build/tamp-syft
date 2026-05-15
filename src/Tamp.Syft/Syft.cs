namespace Tamp.Syft;

/// <summary>
/// Top-level facade for [anchore/syft](https://github.com/anchore/syft) — the leading OSS SBOM
/// generator. Auto-detects 20+ package ecosystems (Rust, npm, .NET, Go, Java, Python, PHP, …)
/// and emits CycloneDX (JSON/XML) or SPDX (JSON/tag-value). Works on directories, files, and
/// container images.
/// </summary>
/// <remarks>
/// <para>
/// <b>Tool resolution:</b>
/// <code>
/// [FromPath("syft")] readonly Tool Syft = null!;
/// </code>
/// Install via <c>brew install syft</c>, the [anchore install script](https://github.com/anchore/syft/blob/main/install.sh),
/// or download a release binary from [github.com/anchore/syft/releases](https://github.com/anchore/syft/releases).
/// </para>
/// </remarks>
public static class Syft
{
    /// <summary>
    /// <c>syft scan [SOURCE]</c> — primary verb. Generate an SBOM for a directory, file, or
    /// container image. Use <c>AddOutputCycloneDxJson(...)</c> / <c>AddOutputSpdxJson(...)</c>
    /// to control format(s); multiple outputs in one invocation supported.
    /// </summary>
    public static CommandPlan Scan(Tool tool, Action<SyftScanSettings> configure)
        => Run<SyftScanSettings>(tool, configure);

    /// <summary><c>syft convert [SOURCE-SBOM] -o [FORMAT]</c> — convert between SBOM formats.</summary>
    public static CommandPlan Convert(Tool tool, Action<SyftConvertSettings> configure)
        => Run<SyftConvertSettings>(tool, configure);

    /// <summary>
    /// <c>syft attest [IMAGE]</c> — generate an SBOM as an in-toto attestation for a container
    /// image; uploads alongside the image in the registry. Pairs with cosign for signing the
    /// resulting attestation. <c>--key</c> path required for unsealed signing; key password is
    /// <see cref="Secret"/>-typed and routed via the <c>COSIGN_PASSWORD</c> env var (cosign's
    /// canonical password channel).
    /// </summary>
    public static CommandPlan Attest(Tool tool, Action<SyftAttestSettings> configure)
        => Run<SyftAttestSettings>(tool, configure);

    /// <summary><c>syft version</c> — diagnostic / version stamp.</summary>
    public static CommandPlan Version(Tool tool, Action<SyftVersionSettings>? configure = null)
        => Run<SyftVersionSettings>(tool, configure);

    /// <summary><c>syft cataloger list</c> — list available catalogers + configuration.</summary>
    public static CommandPlan CatalogerList(Tool tool, Action<SyftCatalogerListSettings>? configure = null)
        => Run<SyftCatalogerListSettings>(tool, configure);

    /// <summary>Raw escape hatch.</summary>
    public static CommandPlan Raw(Tool tool, params string[] arguments)
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        if (arguments is null || arguments.Length == 0)
            throw new ArgumentException("Raw requires at least one argument.", nameof(arguments));
        return new CommandPlan
        {
            Executable = tool.Executable.Value,
            Arguments = arguments.ToList(),
            Environment = new Dictionary<string, string>(),
            WorkingDirectory = tool.WorkingDirectory,
            Secrets = Array.Empty<Secret>(),
        };
    }

    // ---- Object-init overloads (TAM-161) ----
    // Parallel surface to the fluent verbs above. Both styles produce identical
    // CommandPlans; fluent stays canonical in docs and `tamp init` templates.
    //
    //     Syft.Scan(syft, new() { DirectorySource = ".", OutputCycloneDxJson = { sbom } });
    //
    // is equivalent to:
    //
    //     Syft.Scan(syft, s => s.SetDirectorySource(".").AddOutputCycloneDxJson(sbom));
    public static CommandPlan Scan(Tool tool, SyftScanSettings settings) => Plan(tool, settings);
    public static CommandPlan Convert(Tool tool, SyftConvertSettings settings) => Plan(tool, settings);
    public static CommandPlan Attest(Tool tool, SyftAttestSettings settings) => Plan(tool, settings);
    public static CommandPlan Version(Tool tool, SyftVersionSettings settings) => Plan(tool, settings);
    public static CommandPlan CatalogerList(Tool tool, SyftCatalogerListSettings settings) => Plan(tool, settings);

    private static CommandPlan Run<T>(Tool tool, Action<T>? configure) where T : SyftSettingsBase, new()
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        var s = new T();
        configure?.Invoke(s);
        return s.ToCommandPlan(tool);
    }

    private static CommandPlan Plan<T>(Tool tool, T settings) where T : SyftSettingsBase
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        if (settings is null) throw new ArgumentNullException(nameof(settings));
        return settings.ToCommandPlan(tool);
    }
}
