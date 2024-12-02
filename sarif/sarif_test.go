package sarif_test

import (
	_ "embed"
	"testing"

	schemav1 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
)

var (
	//go:embed testdata/gosec_v2.1.0.json
	reportV2_1_0 []byte
)

func TestReportFromBytesV2_1_0(t *testing.T) {
	const (
		expectedNumOfRuns      = 1
		expectedNumResults     = 21
		expectedNumTaxonomies  = 1
		expectedNumTaxas       = 12
		expectedNumDriverRules = 15
	)

	report := schemav1.SchemaJson{}
	if err := report.UnmarshalJSON(reportV2_1_0); err != nil {
		t.Fatalf("report unmarshalling failed: %v", err)
	}

	switch {
	case *report.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json":
		t.Fatalf("unexpected schema '%s'", *report.Schema)
	case report.Version != "2.1.0":
		t.Fatalf("Expected version '2.1.0', got '%s'", report.Version)
	case expectedNumOfRuns != len(report.Runs):
		t.Fatalf("expected %d runs. Expected %d", len(report.Runs), expectedNumOfRuns)
	case expectedNumResults != len(report.Runs[0].Results):
		t.Fatalf("expected %d results. Expected %d", len(report.Runs[0].Results), expectedNumResults)
	case expectedNumTaxonomies != len(report.Runs[0].Taxonomies):
		t.Fatalf("expected %d taxonomies. Expected %d", len(report.Runs[0].Taxonomies), expectedNumTaxonomies)
	}

	run := report.Runs[0]

	for _, res := range run.Results {
		switch {
		case res.Level != "error" && res.Level != "warning":
			t.Fatalf("Expected level 'error', got '%s'", res.Level)
		case *res.Message.Text == "":
			t.Fatal("Expected message text to not be empty")
		case *res.RuleId == "":
			t.Fatal("Expected rule id to not be empty")
		}

		for _, loc := range res.Locations {
			if loc.PhysicalLocation == nil {
				t.Fatal("Expected physical location not to be nil")
			}

			switch {
			case loc.PhysicalLocation.ArtifactLocation == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation to not be nil")
			case loc.PhysicalLocation.ArtifactLocation.Uri == nil || *loc.PhysicalLocation.ArtifactLocation.Uri == "":
				t.Fatalf("Expected PhysicalLocation ArtifactLocation Uri to not be empty")
			case loc.PhysicalLocation.Region == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region to not be empty")
			case loc.PhysicalLocation.Region.EndColumn == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region EndColumn to not be empty")
			case loc.PhysicalLocation.Region.StartColumn == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region StartColumn to not be empty")
			case loc.PhysicalLocation.Region.EndLine == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region EndLine to not be empty")
			case loc.PhysicalLocation.Region.StartLine == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region StartLine to not be empty")
			case loc.PhysicalLocation.Region.Snippet == nil:
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region Snippet to not be empty")
			case loc.PhysicalLocation.Region.Snippet.Text == nil || *loc.PhysicalLocation.Region.Snippet.Text == "":
				t.Fatal("Expected PhysicalLocation ArtifactLocation Region Snippet Text to not be empty")
			}
		}
	}

	for _, taxonomy := range run.Taxonomies {
		switch {
		case taxonomy.DownloadUri == nil || *taxonomy.DownloadUri == "":
			t.Fatal("Expected taxonomy URI to not be empty")
		case taxonomy.Guid == nil || *taxonomy.Guid == "":
			t.Fatal("Expected taxonomy Guid to not be empty")
		case taxonomy.InformationUri == nil || *taxonomy.InformationUri == "":
			t.Fatal("Expected taxonomy InformationUri to not be empty")
		case taxonomy.MinimumRequiredLocalizedDataSemanticVersion == nil || *taxonomy.MinimumRequiredLocalizedDataSemanticVersion == "":
			t.Fatal("Expected taxonomy MinimumRequiredLocalizedDataSemanticVersion to not be empty")
		case !taxonomy.IsComprehensive:
			t.Fatal("Expected taxonomy to be comprehensive")
		case taxonomy.Language == "":
			t.Fatal("Expected taxonomy Language to not be empty")
		case taxonomy.Name == "":
			t.Fatal("Expected taxonomy Name to not be empty")
		case taxonomy.Organization == nil || *taxonomy.Organization == "":
			t.Fatal("Expected taxonomy Organization to not be empty")
		case taxonomy.ReleaseDateUtc == nil || *taxonomy.ReleaseDateUtc == "":
			t.Fatal("Expected taxonomy ReleaseDateUtc to not be empty")
		case taxonomy.ShortDescription == nil:
			t.Fatal("Expected taxonomy ShortDescription to not be nil")
		case taxonomy.ShortDescription.Text == "":
			t.Fatal("Expected taxonomy ShortDescription Text to not be nil")
		case taxonomy.Version == nil || *taxonomy.Version == "":
			t.Fatal("Expected taxonomy Version to not be empty")
		case expectedNumTaxas != len(taxonomy.Taxa):
			t.Fatalf("Expected %d taxonomy taxas. Found %d instead", expectedNumTaxas, len(taxonomy.Taxa))
		}

		for _, taxa := range taxonomy.Taxa {
			switch {
			case taxa.FullDescription == nil:
				t.Fatal("Expected taxa FullDescription to not be nil")
			case taxa.FullDescription.Text == "":
				t.Fatal("Expected taxa FullDescription Text to not be empty")
			case taxa.Guid == nil || *taxa.Guid == "":
				t.Fatal("Expected taxa Guid to not be empty")
			case taxa.HelpUri == nil || *taxa.HelpUri == "":
				t.Fatal("Expected taxa HelpUri to not be empty")
			case taxa.ShortDescription == nil:
				t.Fatal("Expected taxa ShortDescription to not be nil")
			case taxa.ShortDescription.Text == "":
				t.Fatal("Expected taxa ShortDescription Text to not be nil")
			case taxa.Id == "":
				t.Fatal("Expected taxa Id to not be empty")
			}
		}
	}

	driver := run.Tool.Driver
	switch {
	case driver.Guid == nil || *driver.Guid == "":
		t.Fatal("Expected Driver Guid to not be empty")
	case driver.InformationUri == nil || *driver.InformationUri == "":
		t.Fatal("Expected Driver InformationUri to not be empty")
	case driver.SemanticVersion == nil || *driver.SemanticVersion == "":
		t.Fatal("Expected Driver SemanticVersion to not be empty")
	case driver.Version == nil || *driver.Version == "":
		t.Fatal("Expected Driver Version to not be empty")
	case driver.Name == "":
		t.Fatal("Expected Driver Name to not be empty")
	case len(driver.SupportedTaxonomies) != 1:
		t.Fatalf("expected 1 Driver SupportedTaxonomy. Got %d instead", len(driver.SupportedTaxonomies))
	case len(driver.Rules) != expectedNumDriverRules:
		t.Fatalf("expected 1 Driver Rules. Got %d instead", len(driver.Rules))
	}

	for _, rule := range driver.Rules {
		switch {
		case rule.DefaultConfiguration == nil:
			t.Fatal("Expected rule DefaultConfiguration to not be nil")
		case rule.FullDescription == nil:
			t.Fatal("Expected rule FullDescription to not be nil")
		case rule.Help == nil:
			t.Fatal("Expected rule Help to not be nil")
		case rule.Properties == nil:
			t.Fatal("Expected rule Properties to not be nil")
		case rule.ShortDescription == nil:
			t.Fatal("Expected rule ShortDescription to not be nil")
		case len(rule.Relationships) == 0:
			t.Fatal("Expected rule Relationships to not be empty")
		case rule.DefaultConfiguration.Level == "":
			t.Fatal("Expected DefaultConfiguration Level to not be empty")
		case rule.FullDescription.Text == "":
			t.Fatal("Expected FullDescription Text to not be empty")
		case rule.Help.Text == "":
			t.Fatal("Expected Help Text to not be empty")
		case rule.Id == "":
			t.Fatal("Expected rule Id to not be empty")
		case rule.Name == nil || *rule.Name == "":
			t.Fatal("Expected rule Name to not be empty")
		case rule.ShortDescription.Text == "":
			t.Fatal("Expected rule ShortDescription Text to not be empty")
		case rule.Properties.AdditionalProperties == nil:
			t.Fatal("Expected rule Properties AdditionalProperties to not be nil")
		case len(rule.Properties.Tags) != 2:
			t.Fatal("Expected rule Properties Tags to have 2 elements")
		}

		props, ok := rule.Properties.AdditionalProperties.(map[string]any)
		if !ok {
			t.Fatal("Expected rule Properties AdditionalProperties to be a map")
		}

		precision, ok := props["precision"]
		switch {
		case !ok:
			t.Fatal("Expected rule Precision to be found in properties")
		case precision == "":
			t.Fatal("Expected rule Precision to not be empty")
		}

		for _, rel := range rule.Relationships {
			switch {
			case rel.Target.Id == nil || *rel.Target.Id == "":
				t.Fatal("Expected rule Target Id to not be empty")
			case rel.Target.Guid == nil || *rel.Target.Guid == "":
				t.Fatal("Expected rule Target Guid to not be empty")
			case rel.Target.ToolComponent == nil:
				t.Fatal("Expected rule Target ToolComponent to not be nil")
			case rel.Target.ToolComponent.Guid == nil:
				t.Fatal("Expected rule Target ToolComponent Guid to not be empty")
			case rel.Target.ToolComponent.Name == nil || *rel.Target.ToolComponent.Name == "":
				t.Fatal("Expected rule Target ToolComponent Name to not be empty")
			case len(rel.Kinds) == 0:
				t.Fatal("Expected rule Kind to not be empty")
			}
		}
	}
}
