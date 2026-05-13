using System;
using System.Collections.Generic;
using System.Linq;
using Tamp;
using Tamp.Syft;
using Xunit;

namespace Tamp.Syft.Tests;

public sealed class SyftTests
{
    private static Tool FakeTool() => new(AbsolutePath.Create("/fake/syft"));

    private static int IndexOf(IReadOnlyList<string> args, string token)
    {
        for (var i = 0; i < args.Count; i++) if (args[i] == token) return i;
        return -1;
    }

    // ─── scan: source modes ───────────────────────────────────────────────

    [Fact]
    public void Scan_Directory_Source_With_CycloneDx_Output()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson("sbom.cdx.json"));
        Assert.Equal("scan", plan.Arguments[0]);
        Assert.Equal("dir:.", plan.Arguments[1]);
        Assert.Equal("cyclonedx-json=sbom.cdx.json",
            plan.Arguments[IndexOf(plan.Arguments, "-o") + 1]);
    }

    [Fact]
    public void Scan_File_Source()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetFileSource("DasBook.msix")
            .AddOutputCycloneDxJson("sbom.cdx.json"));
        Assert.Equal("file:DasBook.msix", plan.Arguments[1]);
    }

    [Fact]
    public void Scan_Image_Source_Bare_Reference()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetImageSource("alpine:latest")
            .AddOutputSpdxJson());
        Assert.Equal("alpine:latest", plan.Arguments[1]);
    }

    [Fact]
    public void Scan_Registry_Source()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetRegistrySource("ghcr.io/tamp-build/dasbook:1.0.6")
            .AddOutputCycloneDxJson("sbom.cdx.json"));
        Assert.Equal("registry:ghcr.io/tamp-build/dasbook:1.0.6", plan.Arguments[1]);
    }

    [Fact]
    public void Scan_Multiple_Outputs_In_One_Invocation()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson("sbom.cdx.json")
            .AddOutputSpdxJson("sbom.spdx.json")
            .AddOutputSyftJson("sbom.syft.json"));
        var outputs = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "-o")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Contains("cyclonedx-json=sbom.cdx.json", outputs);
        Assert.Contains("spdx-json=sbom.spdx.json", outputs);
        Assert.Contains("syft-json=sbom.syft.json", outputs);
    }

    [Fact]
    public void Scan_Outputs_Without_File_Default_To_Stdout_Form()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson());  // no file → "cyclonedx-json" goes to stdout
        Assert.Equal("cyclonedx-json", plan.Arguments[IndexOf(plan.Arguments, "-o") + 1]);
    }

    [Fact]
    public void Scan_All_Format_Helpers_Emit_Correct_Tokens()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxXml("sbom.cdx.xml")
            .AddOutputSpdxTagValue("sbom.spdx")
            .AddOutputGitHubJson("sbom.gh.json")
            .AddOutputPurls("purls.txt"));
        var outputs = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "-o")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Contains("cyclonedx-xml=sbom.cdx.xml", outputs);
        Assert.Contains("spdx-tag-value=sbom.spdx", outputs);
        Assert.Contains("github-json=sbom.gh.json", outputs);
        Assert.Contains("purls=purls.txt", outputs);
    }

    // ─── scan: filter / scope / enrichment / source-metadata ──────────────

    [Fact]
    public void Scan_Exclude_Patterns_Pass_Through()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .AddExcludes("**/node_modules/**", "**/target/**", "**/bin/**", "**/obj/**"));
        var excludes = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "--exclude")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Equal(4, excludes.Count);
        Assert.Contains("**/node_modules/**", excludes);
        Assert.Contains("**/target/**", excludes);
    }

    [Theory]
    [InlineData("squashed")]
    [InlineData("all-layers")]
    [InlineData("deep-squashed")]
    public void Scan_Valid_Scope_Accepted(string scope)
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetImageSource("alpine:latest")
            .AddOutputCycloneDxJson()
            .SetScope(scope));
        Assert.Equal(scope, plan.Arguments[IndexOf(plan.Arguments, "-s") + 1]);
    }

    [Fact]
    public void Scan_Invalid_Scope_Rejected()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Scan(FakeTool(), s => s
                .SetImageSource("alpine:latest")
                .AddOutputCycloneDxJson()
                .SetScope("just-the-good-layers")).Arguments.ToList());
    }

    [Fact]
    public void Scan_Source_Metadata_Overrides()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .SetSourceName("dasbook")
            .SetSourceVersion("1.0.6")
            .SetSourceSupplier("Brewing Coder Software LLC"));
        Assert.Equal("dasbook", plan.Arguments[IndexOf(plan.Arguments, "--source-name") + 1]);
        Assert.Equal("1.0.6", plan.Arguments[IndexOf(plan.Arguments, "--source-version") + 1]);
        Assert.Equal("Brewing Coder Software LLC",
            plan.Arguments[IndexOf(plan.Arguments, "--source-supplier") + 1]);
    }

    [Fact]
    public void Scan_Cataloger_Selection_And_Override()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .AddSelectCataloger("+cargo")
            .AddSelectCataloger("+npm")
            .AddSelectCataloger("-image"));
        var sels = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "--select-catalogers")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Equal(new[] { "+cargo", "+npm", "-image" }, sels);
    }

    [Fact]
    public void Scan_Enrich_Multi_Source()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .AddEnrich("javascript")
            .AddEnrich("python"));
        var enriches = Enumerable.Range(0, plan.Arguments.Count - 1)
            .Where(i => plan.Arguments[i] == "--enrich")
            .Select(i => plan.Arguments[i + 1])
            .ToList();
        Assert.Equal(new[] { "javascript", "python" }, enriches);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(16)]
    public void Scan_Parallelism_Accepted(int n)
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .SetParallelism(n));
        Assert.Equal(n.ToString(), plan.Arguments[IndexOf(plan.Arguments, "--parallelism") + 1]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Scan_Parallelism_Rejected_Below_1(int n)
    {
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Scan(FakeTool(), s => s
                .SetDirectorySource(".")
                .AddOutputCycloneDxJson()
                .SetParallelism(n)).Arguments.ToList());
    }

    [Fact]
    public void Scan_Requires_Source()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Scan(FakeTool(), s => s.AddOutputCycloneDxJson()).Arguments.ToList());
    }

    [Fact]
    public void Scan_BasePath_Override_For_Symlink_Containment()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .SetBasePath("/repo"));
        Assert.Equal("/repo", plan.Arguments[IndexOf(plan.Arguments, "--base-path") + 1]);
    }

    [Fact]
    public void Scan_Platform_For_Image_Targets()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetImageSource("alpine:latest")
            .AddOutputCycloneDxJson()
            .SetPlatform("linux/arm64"));
        Assert.Equal("linux/arm64", plan.Arguments[IndexOf(plan.Arguments, "--platform") + 1]);
    }

    // ─── convert ──────────────────────────────────────────────────────────

    [Fact]
    public void Convert_Requires_Source_And_Output()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Convert(FakeTool(), s => s.AddOutputCycloneDxJson()).Arguments.ToList());
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Convert(FakeTool(), s => s.SetSourceSbom("in.syft.json")).Arguments.ToList());
    }

    [Fact]
    public void Convert_Syft_To_CycloneDx()
    {
        var plan = Syft.Convert(FakeTool(), s => s
            .SetSourceSbom("in.syft.json")
            .AddOutputCycloneDxJson("out.cdx.json"));
        Assert.Equal(new[] { "convert", "in.syft.json", "-o", "cyclonedx-json=out.cdx.json" }, plan.Arguments);
    }

    [Fact]
    public void Convert_Reads_From_Stdin()
    {
        var plan = Syft.Convert(FakeTool(), s => s
            .ReadFromStdin()
            .AddOutputSpdxJson());
        Assert.Equal("-", plan.Arguments[1]);
    }

    [Fact]
    public void Convert_Template_Path()
    {
        var plan = Syft.Convert(FakeTool(), s => s
            .SetSourceSbom("in.syft.json")
            .AddOutput("template=out.txt")
            .SetTemplatePath("./my.tmpl"));
        Assert.Equal("./my.tmpl", plan.Arguments[IndexOf(plan.Arguments, "-t") + 1]);
    }

    // ─── attest ───────────────────────────────────────────────────────────

    [Fact]
    public void Attest_Requires_Image_And_Output()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Attest(FakeTool(), s => s.AddOutputCycloneDxJson()).Arguments.ToList());
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Attest(FakeTool(), s => s.SetImage("alpine:latest")).Arguments.ToList());
    }

    [Fact]
    public void Attest_Basic_Shape()
    {
        var plan = Syft.Attest(FakeTool(), s => s
            .SetImage("ghcr.io/tamp-build/dasbook:1.0.6")
            .AddOutputCycloneDxJson("attestation.cdx.json")
            .SetKey("cosign.key"));
        Assert.Equal("attest", plan.Arguments[0]);
        Assert.Equal("ghcr.io/tamp-build/dasbook:1.0.6", plan.Arguments[1]);
        Assert.Equal("cyclonedx-json=attestation.cdx.json",
            plan.Arguments[IndexOf(plan.Arguments, "--output") + 1]);
        Assert.Equal("cosign.key", plan.Arguments[IndexOf(plan.Arguments, "-k") + 1]);
    }

    [Fact]
    public void Attest_KeyPassword_Routes_Through_Env()
    {
        var pwd = new Secret("cosign_pwd", "supersecret");
        var plan = Syft.Attest(FakeTool(), s => s
            .SetImage("alpine:latest")
            .AddOutputCycloneDxJson("att.cdx.json")
            .SetKey("k.key")
            .SetKeyPassword(pwd));
        Assert.Equal("supersecret", plan.Environment["COSIGN_PASSWORD"]);
        Assert.Contains(pwd, plan.Secrets);
        // Critically the password must NOT appear in the arg list — that would defeat masking.
        Assert.DoesNotContain("supersecret", plan.Arguments);
    }

    // ─── version / cataloger list / raw ──────────────────────────────────

    [Fact]
    public void Version_Verb()
    {
        var plan = Syft.Version(FakeTool());
        Assert.Equal(new[] { "version" }, plan.Arguments);
    }

    [Fact]
    public void CatalogerList_Verb()
    {
        var plan = Syft.CatalogerList(FakeTool());
        Assert.Equal(new[] { "cataloger", "list" }, plan.Arguments);
    }

    [Fact]
    public void Raw_Allows_Arbitrary()
    {
        var plan = Syft.Raw(FakeTool(), "login", "ghcr.io", "-u", "u");
        Assert.Equal(new[] { "login", "ghcr.io", "-u", "u" }, plan.Arguments);
    }

    [Fact]
    public void Raw_Rejects_Empty()
    {
        Assert.Throws<ArgumentException>(() => Syft.Raw(FakeTool()));
    }

    // ─── shared knobs ─────────────────────────────────────────────────────

    [Fact]
    public void Verbosity_Level_Maps_To_Flags()
    {
        var v1 = Syft.Scan(FakeTool(), s => s.SetDirectorySource(".").AddOutputCycloneDxJson().SetVerbosity(1));
        var v2 = Syft.Scan(FakeTool(), s => s.SetDirectorySource(".").AddOutputCycloneDxJson().SetVerbosity(2));
        Assert.Contains("-v", v1.Arguments);
        Assert.Contains("-vv", v2.Arguments);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(3)]
    public void Verbosity_Out_Of_Range_Rejected(int level)
    {
        Assert.Throws<InvalidOperationException>(() =>
            Syft.Scan(FakeTool(), s => s
                .SetDirectorySource(".").AddOutputCycloneDxJson().SetVerbosity(level)).Arguments.ToList());
    }

    [Fact]
    public void Quiet_Flag()
    {
        var plan = Syft.Scan(FakeTool(), s => s.SetDirectorySource(".").AddOutputCycloneDxJson().SetQuiet());
        Assert.Contains("-q", plan.Arguments);
    }

    [Fact]
    public void Config_Files_And_Profiles_Pass_Through()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".")
            .AddOutputCycloneDxJson()
            .AddConfigFile(".syft.yaml")
            .AddProfile("ci"));
        Assert.Equal(".syft.yaml", plan.Arguments[IndexOf(plan.Arguments, "-c") + 1]);
        Assert.Equal("ci", plan.Arguments[IndexOf(plan.Arguments, "--profile") + 1]);
    }

    [Fact]
    public void WorkingDirectory_Propagates()
    {
        var plan = Syft.Scan(FakeTool(), s => s
            .SetDirectorySource(".").AddOutputCycloneDxJson()
            .SetWorkingDirectory("/repo"));
        Assert.Equal("/repo", plan.WorkingDirectory);
    }
}
