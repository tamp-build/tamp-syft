namespace Tamp.Syft;

/// <summary>Inputs to <see cref="GitLabSbom.Profile(string, GitLabSbomOptions)"/>.</summary>
public sealed class GitLabSbomOptions
{
    /// <summary>
    /// The directory that was scanned — normally the repository root. <b>Required.</b> syft records
    /// component locations as absolute paths; GitLab needs them relative to the repository root, and
    /// nothing in the document says where the root was.
    /// </summary>
    public string? SourceRoot { get; set; }

    /// <summary>
    /// Fail when a component's location is not under <see cref="SourceRoot"/> rather than quietly
    /// omitting its path. On by default: a document that ingests with findings anchored to nothing is
    /// the failure mode this whole profile exists to stop. Turn it off only when some components are
    /// legitimately outside the repository (a scanned container image alongside a checkout, say);
    /// <see cref="GitLabSbomResult.UnrootedLocations"/> then lists what was dropped.
    /// </summary>
    public bool ThrowOnUnrootedPaths { get; set; } = true;

    /// <summary>Indent the emitted JSON. Off by default — this is a CI artifact, not a file to read.</summary>
    public bool WriteIndented { get; set; }

    /// <summary>Set <see cref="SourceRoot"/>.</summary>
    public GitLabSbomOptions SetSourceRoot(string path) { SourceRoot = path; return this; }

    /// <summary>Set <see cref="ThrowOnUnrootedPaths"/>.</summary>
    public GitLabSbomOptions SetThrowOnUnrootedPaths(bool v = true) { ThrowOnUnrootedPaths = v; return this; }

    /// <summary>Set <see cref="WriteIndented"/>.</summary>
    public GitLabSbomOptions SetWriteIndented(bool v = true) { WriteIndented = v; return this; }
}

/// <summary>
/// What <see cref="GitLabSbom.Profile(string, GitLabSbomOptions)"/> produced, and what it could not
/// derive. The unmapped collections exist so a build can log or assert on them: GitLab's ingestion
/// error is generic and asynchronous, so the only place a gap can be seen early is here.
/// </summary>
public sealed record GitLabSbomResult
{
    /// <summary>The profiled CycloneDX document.</summary>
    public required string Json { get; init; }

    /// <summary>The document's <c>specVersion</c>, already checked against what GitLab ingests.</summary>
    public required string SpecVersion { get; init; }

    /// <summary>Components in the document.</summary>
    public required int Components { get; init; }

    /// <summary>
    /// Components that got a repository-relative <c>input_file:path</c>. A shortfall against
    /// <see cref="Components"/> is not necessarily wrong — syft catalogues some components without a
    /// location — but it is the number to watch when the Dependency List looks thin.
    /// </summary>
    public required int ComponentsWithInputFile { get; init; }

    /// <summary>The distinct repository-relative input files found, sorted.</summary>
    public required IReadOnlyList<string> InputFiles { get; init; }

    /// <summary>
    /// Locations that were absolute and not under the source root, so no relative path could be
    /// derived. Empty unless <see cref="GitLabSbomOptions.ThrowOnUnrootedPaths"/> was turned off.
    /// </summary>
    public required IReadOnlyList<string> UnrootedLocations { get; init; }

    /// <summary>
    /// Input file names GitLab has no documented package manager for, so
    /// <c>package_manager:name</c> was omitted rather than guessed. Usually a file syft catalogues and
    /// GitLab does not (<c>package.json</c> alone, a <c>.csproj</c>), which is informational.
    /// </summary>
    public required IReadOnlyList<string> UnmappedPackageManagerFiles { get; init; }

    /// <summary>syft language tokens with no documented GitLab spelling; <c>language:name</c> omitted.</summary>
    public required IReadOnlyList<string> UnmappedLanguages { get; init; }

    /// <summary>A one-line summary for a build log.</summary>
    public override string ToString()
        => $"CycloneDX {SpecVersion}: {Components} component(s), {ComponentsWithInputFile} with an input file, "
           + $"{InputFiles.Count} distinct input file(s)"
           + (UnrootedLocations.Count > 0 ? $", {UnrootedLocations.Count} unrooted" : "")
           + (UnmappedPackageManagerFiles.Count > 0 ? $", {UnmappedPackageManagerFiles.Count} unmapped package manager(s)" : "");
}
