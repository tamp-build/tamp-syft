using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tamp.Syft;
using Xunit;

namespace Tamp.Syft.Tests;

/// <summary>
/// #8 — a syft CycloneDX document carries no <c>gitlab:*</c> properties, so GitLab accepts it, goes
/// green, and then reports missing required properties asynchronously with an empty Dependency List.
/// </summary>
/// <remarks>
/// The fixtures mirror real syft 1.44 output, including the two details that make this non-trivial:
/// locations are <b>absolute</b>, and one PURL type (<c>npm</c>) covers several package managers that
/// only the lock file name distinguishes.
/// </remarks>
public sealed class GitLabSbomTests
{
    private const string Root = "/src/repo";

    private static string Bom(string specVersion, params string[] componentJson) => $$"""
        {
          "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
          "bomFormat": "CycloneDX",
          "specVersion": "{{specVersion}}",
          "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
          "version": 1,
          "metadata": { "timestamp": "2026-11-05T12:00:00Z", "component": { "bom-ref": "abc", "type": "file", "name": "." } },
          "components": [ {{string.Join(",", componentJson)}} ],
          "dependencies": [ { "ref": "abc", "dependsOn": [ "pkg:npm/left-pad@1.3.0" ] } ]
        }
        """;

    private static string Component(string name, string purlType, string language, string metadataType, string location) => $$"""
        {
          "bom-ref": "pkg:{{purlType}}/{{name}}@1.0.0?package-id=deadbeef",
          "type": "library",
          "name": "{{name}}",
          "version": "1.0.0",
          "purl": "pkg:{{purlType}}/{{name}}@1.0.0",
          "licenses": [ { "license": { "id": "MIT" } } ],
          "properties": [
            { "name": "syft:package:foundBy", "value": "javascript-lock-cataloger" },
            { "name": "syft:package:language", "value": "{{language}}" },
            { "name": "syft:package:type", "value": "{{purlType}}" },
            { "name": "syft:package:metadataType", "value": "{{metadataType}}" },
            { "name": "syft:cpe23", "value": "cpe:2.3:a:{{name}}:{{name}}:1.0.0:*:*:*:*:*:*:*" },
            { "name": "syft:location:0:path", "value": "{{JsonEscape(location)}}" }
          ]
        }
        """;

    /// <summary>
    /// JSON-escape a fixture value. Windows locations carry backslashes, and a raw backslash in a
    /// JSON string is an invalid escape — the fixture has to be valid JSON before the profiler can
    /// be judged on what it does with it.
    /// </summary>
    private static string JsonEscape(string value) => value.Replace("\\", "\\\\");

    private static GitLabSbomResult Profile(string json, string? root = Root, bool strict = true)
        => GitLabSbom.Profile(json, new GitLabSbomOptions { SourceRoot = root, ThrowOnUnrootedPaths = strict });

    /// <summary>The guard message has to name the virtual-root case, which is what #11 was about.</summary>
    private static string RequiredRootMessage
        => Assert.Throws<ArgumentException>(() => Profile(Bom("1.6"), root: null)).Message;

    private static IReadOnlyDictionary<string, string?> Properties(JsonNode? node)
        => ((node?["properties"] as JsonArray) ?? [])
            .OfType<JsonObject>()
            .ToDictionary(p => (string)p["name"]!, p => (string?)p["value"]);

    private static JsonObject Parsed(GitLabSbomResult r) => JsonNode.Parse(r.Json)!.AsObject();

    // ─── the required metadata property ───────────────────────────────────

    [Fact]
    public void Metadata_Gets_The_Required_Schema_Version_Of_One()
    {
        var result = Profile(Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/package-lock.json")));

        var metadata = Properties(Parsed(result)["metadata"]);
        Assert.Equal("1", metadata["gitlab:meta:schema_version"]);
    }

    [Fact]
    public void A_Single_Input_File_Is_Also_Declared_At_Document_Level()
    {
        var result = Profile(Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/package-lock.json")));

        // GitLab requires input_file:path in metadata OR on every component. With one lock file the
        // document-level value is true for every component, so declare it there too.
        Assert.Equal("package-lock.json", Properties(Parsed(result)["metadata"])["gitlab:dependency_scanning:input_file:path"]);
    }

    [Fact]
    public void Several_Input_Files_Are_Not_Collapsed_Into_One_Document_Level_Path()
    {
        var result = Profile(Bom("1.6",
            Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", $"{Root}/frontend/pnpm-lock.yaml"),
            Component("right-pad", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/api/package-lock.json")));

        // A document-level path would be wrong for whichever ecosystem didn't win, and would be
        // inherited by any component lacking its own. Provenance belongs on the components.
        Assert.False(Properties(Parsed(result)["metadata"]).ContainsKey("gitlab:dependency_scanning:input_file:path"));
        Assert.Equal(["api/package-lock.json", "frontend/pnpm-lock.yaml"], result.InputFiles);
    }

    // ─── repository-relative paths ────────────────────────────────────────

    [Fact]
    public void Absolute_Locations_Become_Repository_Relative()
    {
        var result = Profile(Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", $"{Root}/frontend/pnpm-lock.yaml")));

        var component = Properties((Parsed(result)["components"] as JsonArray)![0]);
        Assert.Equal("frontend/pnpm-lock.yaml", component["gitlab:dependency_scanning:input_file:path"]);
        Assert.Equal(1, result.ComponentsWithInputFile);
    }

    // Path relativization itself now lives in Tamp.Core's RepositoryPath and is tested there
    // (tamp-syft#11): this file keeps the profiling behaviour that depends on it.

    [Theory]
    // syft records locations against the scan's virtual filesystem, so a lockfile at the root of the
    // scanned tree is "/pnpm-lock.yaml" and "/" is the root that describes it. That was the one
    // SourceRoot value the API rejected (#11).
    [InlineData("/pnpm-lock.yaml", "/", "pnpm-lock.yaml")]
    [InlineData("/frontend/pnpm-lock.yaml", "/", "frontend/pnpm-lock.yaml")]
    // Host paths against a real directory, including syft's inconsistent drive-letter casing.
    [InlineData(@"C:\TEMP\repo\frontend\pnpm-lock.yaml", @"C:\Temp\repo", "frontend/pnpm-lock.yaml")]
    [InlineData("/src/repo/api/package-lock.json", "/src/repo", "api/package-lock.json")]
    public void A_Component_Location_Becomes_Repository_Relative(string location, string root, string expected)
    {
        var result = Profile(Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", location)), root);

        Assert.Equal(expected, Properties((Parsed(result)["components"] as JsonArray)![0])["gitlab:dependency_scanning:input_file:path"]);
        Assert.Empty(result.UnrootedLocations);
    }

    [Fact]
    public void A_Virtual_Root_Profiles_Every_Component()
    {
        // The whole #11 reproduction: an SBOM whose paths are the *easiest* case to relativize was
        // the one that could not be profiled at all.
        var result = Profile(Bom("1.6",
            Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", "/pnpm-lock.yaml"),
            Component("right-pad", "npm", "javascript", "javascript-npm-package-lock-entry", "/api/package-lock.json")), "/");

        Assert.Equal(2, result.ComponentsWithInputFile);
        Assert.Equal(["api/package-lock.json", "pnpm-lock.yaml"], result.InputFiles);
        Assert.Empty(result.UnrootedLocations);
    }

    [Fact]
    public void An_Unrooted_Location_Fails_Loudly_By_Default()
    {
        var json = Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-npm-package-lock-entry", "/somewhere/else/package-lock.json"));

        // Emitting the absolute path would ingest and anchor the finding to nothing — the exact
        // "looks correct, isn't" failure this profile exists to prevent.
        var ex = Assert.Throws<InvalidOperationException>(() => Profile(json));
        Assert.Contains("/somewhere/else/package-lock.json", ex.Message, StringComparison.Ordinal);
        Assert.Contains("ThrowOnUnrootedPaths", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_Unrooted_Location_Can_Be_Reported_Instead_Of_Thrown()
    {
        var result = Profile(
            Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-npm-package-lock-entry", "/somewhere/else/package-lock.json")),
            strict: false);

        Assert.Equal(["/somewhere/else/package-lock.json"], result.UnrootedLocations);
        Assert.Equal(0, result.ComponentsWithInputFile);
        // Omitted, not guessed: no path is better than one GitLab cannot anchor.
        Assert.False(Properties((Parsed(result)["components"] as JsonArray)![0]).ContainsKey("gitlab:dependency_scanning:input_file:path"));
    }

    // ─── package manager provenance ───────────────────────────────────────

    [Fact]
    public void The_Package_Manager_Comes_From_The_Lock_File_Not_The_Purl_Type()
    {
        // Both components carry PURL type "npm" — as real syft output does for pnpm, npm, yarn and
        // bun alike. Only the lock file distinguishes them. Measured on one repository, inferring
        // from the PURL type mislabelled 899 of 1,028 components.
        var result = Profile(Bom("1.6",
            Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", $"{Root}/frontend/pnpm-lock.yaml"),
            Component("right-pad", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/api/package-lock.json")));

        var components = (Parsed(result)["components"] as JsonArray)!;
        Assert.Equal("pnpm", Properties(components[0])["gitlab:dependency_scanning:package_manager:name"]);
        Assert.Equal("npm", Properties(components[1])["gitlab:dependency_scanning:package_manager:name"]);
    }

    [Theory]
    [InlineData("pnpm-lock.yaml", "pnpm")]
    [InlineData("package-lock.json", "npm")]
    [InlineData("npm-shrinkwrap.json", "npm")]
    [InlineData("yarn.lock", "yarn")]
    [InlineData("bun.lock", "bun")]
    [InlineData("go.mod", "go")]
    [InlineData("packages.lock.json", "nuget")]
    [InlineData("Gemfile.lock", "bundler")]
    [InlineData("poetry.lock", "poetry")]
    [InlineData("Cargo.lock", "cargo")]
    [InlineData("composer.lock", "composer")]
    [InlineData("Podfile.lock", "cocoapods")]
    // Case-insensitive, and a full path resolves by its file name.
    [InlineData("GEMFILE.LOCK", "bundler")]
    [InlineData("/src/repo/frontend/pnpm-lock.yaml", "pnpm")]
    [InlineData(@"C:\src\repo\go.mod", "go")]
    public void Lock_Files_Map_To_GitLabs_Own_Package_Manager_Names(string file, string expected)
        => Assert.Equal(expected, GitLabSbomVocabulary.PackageManagerForFile(file));

    [Theory]
    [InlineData("package.json")]      // a manifest syft catalogues and GitLab's table does not list
    [InlineData("Tamp.Syft.csproj")]
    [InlineData("")]
    [InlineData(null)]
    public void An_Unrecognised_File_Yields_No_Package_Manager(string? file)
        => Assert.Null(GitLabSbomVocabulary.PackageManagerForFile(file));

    [Fact]
    public void An_Unmapped_Lock_File_Omits_The_Property_And_Is_Reported()
    {
        var result = Profile(Bom("1.6", Component("thing", "nuget", "dotnet", "dotnet-portable-executable-entry", $"{Root}/src/App.csproj")));

        var component = Properties((Parsed(result)["components"] as JsonArray)![0]);
        Assert.False(component.ContainsKey("gitlab:dependency_scanning:package_manager:name"));
        Assert.Equal(["App.csproj"], result.UnmappedPackageManagerFiles);
        // The path is still emitted — it is the required property, and it is known to be correct.
        Assert.Equal("src/App.csproj", component["gitlab:dependency_scanning:input_file:path"]);
    }

    // ─── language ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("javascript", "JavaScript")]
    [InlineData("go", "Go")]
    [InlineData("dotnet", "C#")]
    [InlineData("ruby", "Ruby")]
    [InlineData("php", "PHP")]
    public void Language_Uses_GitLabs_Spelling(string syft, string expected)
        => Assert.Equal(expected, GitLabSbomVocabulary.LanguageName(syft));

    [Fact]
    public void An_Unknown_Language_Is_Omitted_Rather_Than_Capitalised()
    {
        // Guessing by capitalising would produce "Brainfuck" and look authoritative. The property is
        // optional; a wrong value in a security report is not.
        Assert.Null(GitLabSbomVocabulary.LanguageName("brainfuck"));

        var result = Profile(Bom("1.6", Component("x", "npm", "brainfuck", "javascript-npm-package-lock-entry", $"{Root}/package-lock.json")));
        Assert.False(Properties((Parsed(result)["components"] as JsonArray)![0]).ContainsKey("gitlab:dependency_scanning:language:name"));
        Assert.Equal(["brainfuck"], result.UnmappedLanguages);
    }

    // ─── preservation: this is a profiling pass, not a re-emit ────────────

    [Fact]
    public void Everything_Already_In_The_Document_Survives()
    {
        var json = Bom("1.6", Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", $"{Root}/pnpm-lock.yaml"));
        var before = JsonNode.Parse(json)!.AsObject();
        var after = Parsed(Profile(json));

        Assert.Equal((string?)before["serialNumber"], (string?)after["serialNumber"]);
        Assert.Equal((string?)before["specVersion"], (string?)after["specVersion"]);
        Assert.Equal((string?)before["$schema"], (string?)after["$schema"]);
        Assert.Equal(
            (before["dependencies"] as JsonArray)!.ToJsonString(),
            (after["dependencies"] as JsonArray)!.ToJsonString());

        var componentBefore = (before["components"] as JsonArray)![0]!;
        var componentAfter = (after["components"] as JsonArray)![0]!;
        Assert.Equal((string?)componentBefore["bom-ref"], (string?)componentAfter["bom-ref"]);
        Assert.Equal((string?)componentBefore["purl"], (string?)componentAfter["purl"]);
        Assert.Equal(componentBefore["licenses"]!.ToJsonString(), componentAfter["licenses"]!.ToJsonString());

        // Every pre-existing property, including the raw evidence we derived from.
        var propertiesAfter = Properties(componentAfter);
        foreach (var (name, value) in Properties(componentBefore))
            Assert.Equal(value, propertiesAfter[name]);
        Assert.Equal("javascript-pnpm-lock-entry", propertiesAfter["syft:package:metadataType"]);
        Assert.Equal($"{Root}/pnpm-lock.yaml", propertiesAfter["syft:location:0:path"]);
    }

    [Fact]
    public void A_Component_Without_Properties_Is_Left_Without_An_Empty_Array()
    {
        var bare = """{ "bom-ref": "bare", "type": "library", "name": "bare", "version": "1.0.0" }""";
        var after = Parsed(Profile(Bom("1.6", bare)));

        Assert.False((after["components"] as JsonArray)![0]!.AsObject().ContainsKey("properties"));
    }

    [Fact]
    public void Profiling_Twice_Changes_Nothing()
    {
        var json = Bom("1.6",
            Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", $"{Root}/frontend/pnpm-lock.yaml"),
            Component("right-pad", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/api/package-lock.json"));

        var once = Profile(json);
        var twice = Profile(once.Json);

        Assert.Equal(once.Json, twice.Json);
        // And no duplicate gitlab:* properties crept in.
        var properties = ((Parsed(twice)["components"] as JsonArray)![0]!["properties"] as JsonArray)!;
        Assert.Single(properties, p => (string?)p!["name"] == "gitlab:dependency_scanning:input_file:path");
    }

    [Fact]
    public void A_Gitlab_Property_This_Profiler_Does_Not_Own_Is_Left_Alone()
    {
        // category and reachability are the caller's to set; re-profiling must not strip them.
        var withCategory = """
            {
              "bom-ref": "c", "type": "library", "name": "dev-thing", "version": "1.0.0",
              "properties": [
                { "name": "syft:location:0:path", "value": "/src/repo/package-lock.json" },
                { "name": "gitlab:dependency_scanning:category", "value": "development" }
              ]
            }
            """;
        var after = Parsed(Profile(Bom("1.6", withCategory)));

        Assert.Equal("development", Properties((after["components"] as JsonArray)![0])["gitlab:dependency_scanning:category"]);
    }

    // ─── rejecting what GitLab cannot ingest ──────────────────────────────

    [Theory]
    [InlineData("1.4")]
    [InlineData("1.5")]
    [InlineData("1.6")]
    public void The_Spec_Versions_GitLab_Ingests_Are_Accepted(string specVersion)
        => Assert.Equal(specVersion, Profile(Bom(specVersion, Component("x", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/package-lock.json"))).SpecVersion);

    [Theory]
    [InlineData("1.7")]   // syft's newer default; GitLab hard-rejects it
    [InlineData("1.3")]
    public void An_Unsupported_Spec_Version_Is_Refused_With_The_Fix_In_The_Message(string specVersion)
    {
        var ex = Assert.Throws<InvalidDataException>(
            () => Profile(Bom(specVersion, Component("x", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/package-lock.json"))));

        Assert.Contains(specVersion, ex.Message, StringComparison.Ordinal);
        Assert.Contains("1.4, 1.5, 1.6", ex.Message, StringComparison.Ordinal);
        Assert.Contains("cyclonedx-json@1.6", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_Spdx_Document_Is_Refused_Rather_Than_Profiled()
    {
        var spdx = """{ "spdxVersion": "SPDX-2.3", "name": "thing", "packages": [] }""";

        var ex = Assert.Throws<InvalidDataException>(() => Profile(spdx));
        Assert.Contains("bomFormat", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Invalid_Json_Says_So()
        => Assert.Throws<InvalidDataException>(() => Profile("{ not json"));

    [Fact]
    public void Source_Root_Is_Required()
    {
        var json = Bom("1.6", Component("x", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/package-lock.json"));

        var ex = Assert.Throws<ArgumentException>(() => Profile(json, root: null));
        Assert.Contains("SourceRoot", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_Required_Root_Message_Names_The_Virtual_Root_Case()
    {
        // The old message said only "set it to the directory that was scanned", which is the advice
        // that leads to the dead end in #11: a virtual path is not under any filesystem directory.
        Assert.Contains("virtual filesystem", RequiredRootMessage, StringComparison.Ordinal);
        Assert.Contains("/pnpm-lock.yaml", RequiredRootMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void The_Unrooted_Message_Explains_The_Space_Mismatch_Rather_Than_Repeating_The_Dead_End()
    {
        // A virtual location with a filesystem root: the mismatch #11 describes.
        var json = Bom("1.6", Component("x", "npm", "javascript", "javascript-npm-package-lock-entry", "/pnpm-lock.yaml"));

        var ex = Assert.Throws<InvalidOperationException>(() => Profile(json, root: "/src/repo"));

        Assert.Contains("same space", ex.Message, StringComparison.Ordinal);
        Assert.Contains("SourceRoot = \"/\"", ex.Message, StringComparison.Ordinal);
        Assert.Contains("anchors nothing", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_Document_With_No_Metadata_Still_Gets_The_Required_Property()
    {
        var noMetadata = """
            { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [] }
            """;
        var after = Parsed(Profile(noMetadata));

        Assert.Equal("1", Properties(after["metadata"])["gitlab:meta:schema_version"]);
    }

    // ─── the scan-side schema pin ─────────────────────────────────────────

    [Fact]
    public void Scan_Can_Pin_The_CycloneDx_Schema_Version()
    {
        var plan = Syft.Scan(new Tool(AbsolutePath.Create("/fake/syft")), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson("1.6", "sbom.cdx.json"));

        Assert.Contains("cyclonedx-json@1.6=sbom.cdx.json", plan.Arguments);
    }

    [Fact]
    public void Scan_Has_A_GitLab_Output_Pinned_To_The_Newest_Version_GitLab_Ingests()
    {
        var plan = Syft.Scan(new Tool(AbsolutePath.Create("/fake/syft")), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJsonForGitLab("gl.cdx.json"));

        Assert.Contains($"cyclonedx-json@{GitLabSbom.PreferredSpecVersion}=gl.cdx.json", plan.Arguments);
        Assert.Equal("1.6", GitLabSbom.PreferredSpecVersion);
    }

    [Fact]
    public void A_Pinned_Output_Needs_A_Version()
        => Assert.Throws<ArgumentException>(() => Syft.Scan(
            new Tool(AbsolutePath.Create("/fake/syft")),
            s => s.SetDirectorySource(".").AddOutputCycloneDxJson(" ", "sbom.json")));

    // ─── the report ───────────────────────────────────────────────────────

    [Fact]
    public void The_Result_Summarises_What_A_Build_Log_Needs()
    {
        var result = Profile(Bom("1.6",
            Component("left-pad", "npm", "javascript", "javascript-pnpm-lock-entry", $"{Root}/frontend/pnpm-lock.yaml"),
            Component("right-pad", "npm", "javascript", "javascript-npm-package-lock-entry", $"{Root}/api/package-lock.json")));

        Assert.Equal(2, result.Components);
        Assert.Equal(2, result.ComponentsWithInputFile);
        Assert.Contains("2 component(s)", result.ToString(), StringComparison.Ordinal);
        Assert.Contains("2 distinct input file(s)", result.ToString(), StringComparison.Ordinal);
    }
}
