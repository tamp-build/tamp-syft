using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tamp.Syft;

/// <summary>
/// Turns a syft CycloneDX document into one GitLab will actually ingest, by adding the
/// <c>gitlab:*</c> metadata properties GitLab's CycloneDX property taxonomy requires.
/// </summary>
/// <remarks>
/// <para>
/// <b>The problem this solves.</b> GitLab accepts a syft CycloneDX document as a <c>cyclonedx</c>
/// report and the job goes green, then its asynchronous post-processing reports
/// <i>"Required GitLab CycloneDX properties are missing. This will prevent vulnerability scanning and
/// may result in incomplete license and package information."</i> and the Dependency List comes back
/// empty or partial. A green job is not evidence of ingestion. Measured against syft 1.44,
/// <c>metadata.properties</c> is <c>null</c>: syft emits no <c>gitlab:*</c> properties at all, and
/// nothing in the pipeline says so.
/// </para>
/// <para>
/// <b>What it adds.</b> Only what GitLab documents, and only what can be read off the document:
/// <c>gitlab:meta:schema_version</c> (<c>1</c>, in <c>metadata</c>, required),
/// <c>gitlab:dependency_scanning:input_file:path</c> (required in <c>metadata</c> or on each
/// component), and — where syft reported them and GitLab has a documented spelling —
/// <c>gitlab:dependency_scanning:package_manager:name</c> and
/// <c>gitlab:dependency_scanning:language:name</c>. Anything not derivable is omitted rather than
/// filled in: GitLab's error is generic, so a fabricated property that happens to satisfy it would
/// put a wrong fact in a security report and never be contradicted.
/// </para>
/// <para>
/// <b>What it preserves.</b> The document is edited as JSON, not round-tripped through a model, so
/// component identities, <c>bom-ref</c>s, dependency edges, licenses, CPEs, every existing
/// <c>syft:*</c> property and any field this wrapper has never heard of all survive byte-for-byte.
/// This is a profiling pass, not a re-emit. The input document is not modified; keep publishing it
/// alongside the profiled copy.
/// </para>
/// <para>
/// <b>Per-component provenance.</b> Provenance is attached at component level, not by assigning one
/// lock file to the whole document. On a repository with two JavaScript lock files, 899 of 1,028
/// components came from <c>pnpm-lock.yaml</c> and 128 from <c>package-lock.json</c>; a single
/// document-level path would have been wrong for 129 of them. GitLab's taxonomy makes a component
/// value override the metadata value, so this is the supported shape, not a workaround.
/// </para>
/// <para>
/// <b>Caveat.</b> GitLab describes third-party CycloneDX SBOM support as "technically possible but
/// highly subject to change". This profile targets the documented taxonomy; it is not an officially
/// supported integration, and the acceptance test is GitLab's Dependency List read back after
/// asynchronous processing — never a green job.
/// </para>
/// </remarks>
public static class GitLabSbom
{
    /// <summary>CycloneDX spec versions GitLab can ingest. 1.7 and later are rejected outright.</summary>
    public static readonly IReadOnlyList<string> SupportedSpecVersions = ["1.4", "1.5", "1.6"];

    /// <summary>The spec version to pin new scans to: the newest GitLab ingests.</summary>
    public const string PreferredSpecVersion = "1.6";

    internal const string SchemaVersionProperty = "gitlab:meta:schema_version";
    internal const string InputFileProperty = "gitlab:dependency_scanning:input_file:path";
    internal const string PackageManagerProperty = "gitlab:dependency_scanning:package_manager:name";
    internal const string LanguageProperty = "gitlab:dependency_scanning:language:name";

    /// <summary>The properties this profiler owns. Re-profiling replaces exactly these and no others.</summary>
    private static readonly string[] OwnedProperties =
        [SchemaVersionProperty, InputFileProperty, PackageManagerProperty, LanguageProperty];

    /// <summary>
    /// Profile <paramref name="cycloneDxJson"/> for GitLab ingestion and return the new document
    /// alongside a report of what was derived.
    /// </summary>
    /// <param name="cycloneDxJson">A CycloneDX JSON document as syft emitted it.</param>
    /// <param name="options">Source root and strictness. <see cref="GitLabSbomOptions.SourceRoot"/> is required.</param>
    /// <exception cref="ArgumentNullException"><paramref name="cycloneDxJson"/> or <paramref name="options"/> is null.</exception>
    /// <exception cref="InvalidDataException">
    /// The input is not a CycloneDX JSON document, or its <c>specVersion</c> is one GitLab cannot ingest.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Component locations fall outside <see cref="GitLabSbomOptions.SourceRoot"/> and
    /// <see cref="GitLabSbomOptions.ThrowOnUnrootedPaths"/> is set. Emitting a path GitLab cannot
    /// anchor is the failure this guards: it ingests, and the findings point at nothing.
    /// </exception>
    public static GitLabSbomResult Profile(string cycloneDxJson, GitLabSbomOptions options)
    {
        if (cycloneDxJson is null) throw new ArgumentNullException(nameof(cycloneDxJson));
        if (options is null) throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(options.SourceRoot))
            throw new ArgumentException(
                "SourceRoot is required: syft records component locations as absolute paths, and GitLab needs them "
                + "relative to the repository root. It must be expressed in the same space as the locations syft "
                + "emitted — \"/\" when syft reported against the scan's virtual filesystem (paths like "
                + "\"/pnpm-lock.yaml\"), or the scanned directory when it reported host paths.", nameof(options));

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(cycloneDxJson, documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Not valid JSON, so not a CycloneDX document: {ex.Message}", ex);
        }

        if (root is not JsonObject bom)
            throw new InvalidDataException("A CycloneDX document must be a JSON object.");

        var format = (string?)bom["bomFormat"];
        if (!string.Equals(format, "CycloneDX", StringComparison.Ordinal))
            throw new InvalidDataException(
                $"bomFormat is '{format ?? "(absent)"}', not 'CycloneDX'. Emit the scan with "
                + "AddOutputCycloneDxJsonForGitLab(...) — an SPDX or syft-json document cannot be profiled.");

        var spec = (string?)bom["specVersion"] ?? "(absent)";
        if (!SupportedSpecVersions.Contains(spec, StringComparer.Ordinal))
            throw new InvalidDataException(
                $"GitLab cannot ingest CycloneDX {spec}; it accepts {string.Join(", ", SupportedSpecVersions)}. "
                + $"Pin the scan's output to {PreferredSpecVersion} — AddOutputCycloneDxJsonForGitLab(path) does this, "
                + $"or AddOutput(\"cyclonedx-json@{PreferredSpecVersion}=path\").");

        var normalizedRoot = RepositoryPath.NormalizeRoot(options.SourceRoot);
        var inputFiles = new SortedSet<string>(StringComparer.Ordinal);
        var unrooted = new SortedSet<string>(StringComparer.Ordinal);
        var unmappedManagers = new SortedSet<string>(StringComparer.Ordinal);
        var unmappedLanguages = new SortedSet<string>(StringComparer.Ordinal);
        var components = 0;
        var withInputFile = 0;

        foreach (var component in (bom["components"] as JsonArray ?? []).OfType<JsonObject>())
        {
            components++;
            var existing = ReadProperties(component);
            var properties = OwnProperties(component);

            var location = FirstLocation(existing);
            string? inputFile = null;
            if (location is not null)
            {
                inputFile = RepositoryPath.Relativize(location, normalizedRoot);
                if (inputFile is null) unrooted.Add(location);
            }

            if (inputFile is not null)
            {
                withInputFile++;
                inputFiles.Add(inputFile);
                Set(properties, InputFileProperty, inputFile);

                // The lock file is the package-manager signal, never the PURL type: one PURL type
                // (npm) covers pnpm, npm, yarn and bun, and syft reports the same type for all.
                var manager = GitLabSbomVocabulary.PackageManagerForFile(inputFile);
                if (manager is not null) Set(properties, PackageManagerProperty, manager);
                else unmappedManagers.Add(GitLabSbomVocabulary.FileName(inputFile));
            }

            if (existing.TryGetValue("syft:package:language", out var syftLanguage)
                && !string.IsNullOrWhiteSpace(syftLanguage))
            {
                var language = GitLabSbomVocabulary.LanguageName(syftLanguage);
                if (language is not null) Set(properties, LanguageProperty, language);
                else unmappedLanguages.Add(syftLanguage);
            }

            if (properties.Count == 0) component.Remove("properties");
        }

        if (options.ThrowOnUnrootedPaths && unrooted.Count > 0)
            throw new InvalidOperationException(
                $"{unrooted.Count} component location(s) are not under SourceRoot '{options.SourceRoot}', so they "
                + "cannot be made repository-relative and GitLab would not anchor the findings to a file. "
                + $"First: '{unrooted.First()}'. SourceRoot has to be expressed in the same space as the locations "
                + "syft emitted: a virtual path like '/pnpm-lock.yaml' needs SourceRoot = \"/\", and no filesystem "
                + "directory will ever contain it. Use the scanned directory only when syft reported host paths. "
                + "Setting ThrowOnUnrootedPaths = false omits the property for those components instead, which "
                + "produces a document GitLab ingests and anchors nothing to.");

        // metadata: schema_version is required here. The document-level input file is only honest when
        // every component agrees on one; with several lock files the per-component values are the
        // provenance, and a metadata value would be inherited wrongly by any component without one.
        var metadata = bom["metadata"] as JsonObject;
        if (metadata is null)
        {
            metadata = new JsonObject();
            bom["metadata"] = metadata;
        }

        var metadataProperties = OwnProperties(metadata);
        Set(metadataProperties, SchemaVersionProperty, "1");
        if (inputFiles.Count == 1) Set(metadataProperties, InputFileProperty, inputFiles.First());

        var json = bom.ToJsonString(new JsonSerializerOptions { WriteIndented = options.WriteIndented });

        return new GitLabSbomResult
        {
            Json = json,
            SpecVersion = spec,
            Components = components,
            ComponentsWithInputFile = withInputFile,
            InputFiles = [.. inputFiles],
            UnrootedLocations = [.. unrooted],
            UnmappedPackageManagerFiles = [.. unmappedManagers],
            UnmappedLanguages = [.. unmappedLanguages],
        };
    }

    /// <summary>
    /// <see cref="Profile(string, GitLabSbomOptions)"/> over files: read <paramref name="input"/>,
    /// write the profiled document to <paramref name="output"/>, and return the report. The input
    /// file is left untouched, so the unprofiled syft document stays publishable alongside it.
    /// </summary>
    public static GitLabSbomResult ProfileFile(AbsolutePath input, AbsolutePath output, GitLabSbomOptions options)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        var result = Profile(File.ReadAllText(input.Value), options);
        var directory = Path.GetDirectoryName(output.Value);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory!);
        File.WriteAllText(output.Value, result.Json);
        return result;
    }

    /// <summary>Flatten a node's <c>properties</c> array into a name → value map (last wins).</summary>
    private static Dictionary<string, string?> ReadProperties(JsonObject node)
    {
        var map = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var property in (node["properties"] as JsonArray ?? []).OfType<JsonObject>())
            if ((string?)property["name"] is { } name) map[name] = (string?)property["value"];
        return map;
    }

    /// <summary>
    /// The node's <c>properties</c> array, created if absent, with this profiler's own properties
    /// removed. Re-profiling is therefore idempotent, and properties set by anyone else — including
    /// other <c>gitlab:*</c> ones such as <c>category</c> or <c>reachability</c> — are left alone.
    /// </summary>
    private static JsonArray OwnProperties(JsonObject node)
    {
        if (node["properties"] is not JsonArray properties)
        {
            properties = [];
            node["properties"] = properties;
        }

        for (var i = properties.Count - 1; i >= 0; i--)
            if (properties[i] is JsonObject p && (string?)p["name"] is { } name
                && Array.IndexOf(OwnedProperties, name) >= 0)
                properties.RemoveAt(i);

        return properties;
    }

    private static void Set(JsonArray properties, string name, string value)
        => properties.Add(new JsonObject { ["name"] = name, ["value"] = value });

    /// <summary>
    /// The first location syft recorded for a component: <c>syft:location:0:path</c>, falling back to
    /// the lowest index present, since a component catalogued from several files still came from one
    /// primary one and GitLab's property is single-valued.
    /// </summary>
    private static string? FirstLocation(Dictionary<string, string?> properties)
    {
        for (var i = 0; i < 16; i++)
            if (properties.TryGetValue($"syft:location:{i}:path", out var path) && !string.IsNullOrWhiteSpace(path))
                return path;
        return null;
    }

}
