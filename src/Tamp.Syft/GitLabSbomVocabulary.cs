namespace Tamp.Syft;

/// <summary>
/// The GitLab-side vocabulary a profiled SBOM has to speak: which package manager a lock file
/// belongs to, and how GitLab spells a language name.
/// </summary>
/// <remarks>
/// <para>
/// Both tables are transcribed from GitLab's own documentation rather than guessed, and both are
/// deliberately <b>incomplete-safe</b>: an unrecognised file or language yields <c>null</c> and the
/// corresponding property is omitted. A missing optional property costs GitLab nothing; a fabricated
/// one puts a wrong fact in a security report.
/// </para>
/// <para>
/// <b>Why the file name and not the PURL type.</b> A PURL type names the <i>registry</i>, not the
/// package manager that resolved it. Measured on a single repository with two JavaScript lock files,
/// syft emitted purl type <c>npm</c> for all 1,027 JavaScript components, of which 899 came from
/// <c>pnpm-lock.yaml</c> and 128 from <c>package-lock.json</c>. Deriving the package manager from the
/// PURL type would have mislabelled 899 components. The lock file is the honest signal, and it is
/// also the key GitLab's own table is written against.
/// </para>
/// </remarks>
public static class GitLabSbomVocabulary
{
    /// <summary>
    /// GitLab's lock/manifest file to package-manager map, keyed by file name (case-insensitive).
    /// </summary>
    /// <remarks>
    /// Values are lower-cased. GitLab's prose table capitalises inconsistently ("NuGet", "bundler"),
    /// but its own generated SBOM file names — <c>gl-sbom-&lt;package-type&gt;-&lt;package-manager&gt;.cdx.json</c>,
    /// e.g. <c>gl-sbom-gem-bundler.cdx.json</c> — are lower-case, so that is the form used here.
    /// </remarks>
    private static readonly Dictionary<string, string> PackageManagerByFile =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // C#
            ["packages.lock.json"] = "nuget",
            // C/C++
            ["conan.lock"] = "conan",
            ["conda-lock.yml"] = "conda",
            // Dart
            ["pubspec.lock"] = "pub",
            ["pub.graph.json"] = "pub",
            // Go
            ["go.mod"] = "go",
            ["go.graph"] = "go",
            // Java / Kotlin / Scala
            ["ivy-report.xml"] = "ivy",
            ["maven.graph.json"] = "maven",
            ["pom.xml"] = "maven",
            ["gradle.graph.txt"] = "gradle",
            ["dependencies.lock"] = "gradle",
            ["dependencies.direct.lock"] = "gradle",
            ["gradle.lockfile"] = "gradle",
            ["gradle-html-dependency-report.js"] = "gradle",
            ["build.gradle"] = "gradle",
            ["build.gradle.kts"] = "gradle",
            ["dependencies-compile.dot"] = "sbt",
            // JavaScript / TypeScript
            ["bun.lock"] = "bun",
            ["package-lock.json"] = "npm",
            ["npm-shrinkwrap.json"] = "npm",
            ["pnpm-lock.yaml"] = "pnpm",
            ["yarn.lock"] = "yarn",
            // Objective-C — GitLab detects these but does not match them against advisories.
            ["podfile.lock"] = "cocoapods",
            // PHP
            ["composer.lock"] = "composer",
            // Python
            ["pipdeptree.json"] = "pip",
            ["requirements.txt"] = "pip",
            ["pipfile.lock"] = "pipenv",
            ["pipenv.graph.json"] = "pipenv",
            ["poetry.lock"] = "poetry",
            ["uv.lock"] = "uv",
            // Ruby
            ["gemfile.lock"] = "bundler",
            ["gems.locked"] = "bundler",
            // Rust
            ["cargo.lock"] = "cargo",
            // Swift
            ["package.resolved"] = "swift",
        };

    /// <summary>
    /// syft's lower-case language token to GitLab's spelling. syft reports <c>javascript</c>;
    /// GitLab's taxonomy examples are <c>JavaScript</c>, <c>Ruby</c>, <c>Go</c>.
    /// </summary>
    private static readonly Dictionary<string, string> LanguageNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["javascript"] = "JavaScript",
            ["typescript"] = "TypeScript",
            ["dotnet"] = "C#",
            ["go"] = "Go",
            ["java"] = "Java",
            ["kotlin"] = "Kotlin",
            ["scala"] = "Scala",
            ["python"] = "Python",
            ["ruby"] = "Ruby",
            ["rust"] = "Rust",
            ["php"] = "PHP",
            ["swift"] = "Swift",
            ["dart"] = "Dart",
            ["cpp"] = "C++",
            ["c"] = "C",
            ["haskell"] = "Haskell",
            ["elixir"] = "Elixir",
            ["erlang"] = "Erlang",
            ["r"] = "R",
            ["lua"] = "Lua",
            ["swipl"] = "Prolog",
        };

    /// <summary>
    /// The GitLab package-manager name for a lock/manifest file, or <c>null</c> when the file is not
    /// one GitLab recognises. <paramref name="path"/> may be a full path; only the file name is used.
    /// </summary>
    public static string? PackageManagerForFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var name = FileName(path!);
        return name.Length != 0 && PackageManagerByFile.TryGetValue(name, out var pm) ? pm : null;
    }

    /// <summary>
    /// GitLab's spelling of a syft language token, or <c>null</c> when it isn't one we have a
    /// documented spelling for. Never guesses by capitalising the token: a wrong language name is a
    /// wrong fact, and the property is optional.
    /// </summary>
    public static string? LanguageName(string? syftLanguage)
        => !string.IsNullOrWhiteSpace(syftLanguage) && LanguageNames.TryGetValue(syftLanguage!, out var l) ? l : null;

    /// <summary>The last segment of a path, splitting on both separators (syft emits either).</summary>
    internal static string FileName(string path)
    {
        var cut = path.LastIndexOfAny(['/', '\\']);
        return cut < 0 ? path : path[(cut + 1)..];
    }
}
