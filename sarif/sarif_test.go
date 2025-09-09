package sarif_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	sariftransformer "github.com/smithy-security/pkg/sarif"
	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/pkg/utils"
)

var (
	//go:embed testdata/gosec_v2.1.0.json
	reportV2_1_0 []byte

	staticNow = time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
)

func TestReportFromBytesV2_1_0(t *testing.T) {
	const (
		expectedNumOfRuns      = 1
		expectedNumResults     = 21
		expectedNumTaxonomies  = 1
		expectedNumTaxas       = 12
		expectedNumDriverRules = 15
	)

	report := sarif.SchemaJson{}
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

func Test_ParseOut(t *testing.T) {
	t.Run("gosec testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/gosec_v2.1.0.sarifconversiontests.json")
		require.NoError(t, err)

		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))
		marshalledDataSources := []string{}
		datasource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "file://main.go",
			},
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "github.com/foo/bar",
				Reference:     "main",
			},
		}

		// set for expected results
		datasource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   83,
				EndLine:     0,
				StartColumn: 7,
				EndColumn:   0,
			},
		}
		marshalledDataSource, err := protojson.Marshal(datasource)
		require.NoError(t, err)

		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		datasource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   83,
				EndLine:     83,
				StartColumn: 7,
				EndColumn:   7,
			},
		}
		marshalledDataSource, err = protojson.Marshal(datasource)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		require.NoError(t, err)

		datasource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 83,
			},
		}
		marshalledDataSource, err = protojson.Marshal(datasource)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSources[0]))

		// reset for the test
		datasource.LocationData = nil
		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("[test for missing endLine, common in some tools]"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("gosec"),
					Uid:             "G404",
					Title:           "[test for missing endLine, common in some tools]",
				},
				Message: utils.Ptr("[test for missing endLine, common in some tools]"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("G404"),
					Product: &ocsf.Product{
						Name: utils.Ptr("gosec"),
					},
					Uid: utils.Ptr("5f0f6d49-1db2-5881-a269-a09e69803621"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH, StartTime: utils.Ptr(now.Unix()),
				StatusId: utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:   utils.Ptr("STATUS_ID_NEW"),
				Time:     now.Unix(),
				TimeDt:   timestamppb.New(now),
				TypeName: utils.Ptr("Create"),
				TypeUid:  int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "main.go",
									Path: utils.Ptr("file://main.go"),
								},
								StartLine: utils.Ptr(int32(83)),
							},
						},
						Desc:            utils.Ptr("[test for missing endLine, common in some tools]"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("[test for missing endLine, common in some tools]"),
						VendorName:      utils.Ptr("gosec"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("gosec"),
					Uid:             "G404",
					Title:           "Use of weak random number generator (math/rand instead of crypto/rand)",
				},
				Message: utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("G404"),
					Product: &ocsf.Product{
						Name: utils.Ptr("gosec"),
					},
					Uid: utils.Ptr("9153a915-3b7d-5467-a2de-277ae6185001"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH, StartTime: utils.Ptr(now.Unix()),
				StatusId: utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:   utils.Ptr("STATUS_ID_NEW"),
				Time:     now.Unix(),
				TimeDt:   timestamppb.New(now),
				TypeName: utils.Ptr("Create"),
				TypeUid:  int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{

									Name: "main.go",
									Path: utils.Ptr("file://main.go"),
								},
								StartLine: utils.Ptr(int32(83)),
								EndLine:   utils.Ptr(int32(83)),
							},
						},
						Desc:            utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
						VendorName:      utils.Ptr("gosec"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("gosec"),
					Uid:             "G404",
					Title:           "Use of weak random number generator (math/rand instead of crypto/rand) - nil endline",
				},
				Message: utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("G404"),
					Product: &ocsf.Product{
						Name: utils.Ptr("gosec"),
					},
					Uid: utils.Ptr("76d50156-59b0-5111-93c9-ae6df47015e2"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{

									Name: "main.go",
									Path: utils.Ptr("file://main.go"),
								},
								StartLine: utils.Ptr(int32(83)),
							},
						},
						AffectedPackages: nil, // on purpose, we really want to make sure this is nil as opposed to any other default value since gosec is not handling packages
						Desc:             utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
						FirstSeenTime:    utils.Ptr(now.Unix()),
						FirstSeenTimeDt:  timestamppb.New(now),
						FixAvailable:     utils.Ptr(false),
						IsFixAvailable:   utils.Ptr(false),
						LastSeenTime:     utils.Ptr(now.Unix()),
						LastSeenTimeDt:   timestamppb.New(now),
						Severity:         utils.Ptr("SEVERITY_ID_HIGH"),
						Title:            utils.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
						VendorName:       utils.Ptr("gosec"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "", clock, nil, true, datasource,
		)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())

		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValuesf(t, &expectedDataSource, &actualDatasource, "datasource for finding index %d is not equal", i)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}

		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})

	t.Run("snyk-node testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/snyk-node_output.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		marshalledDataSources := []string{}

		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "github.com/foo/bar",
				Reference:     "main",
			},
		}

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 1,
			},
		}
		marshalledDataSource, err := protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		// unset for the test
		dataSource.LocationData = nil
		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: cookie\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5 › cookie@0.3.1\n# Overview\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) via the cookie `name`, `path`, or `domain`, which can be used to set unexpected values to other cookie fields.\r\n\r\n# Workaround\r\nUsers who are not able to upgrade to the fixed version should avoid passing untrusted or arbitrary values for the cookie fields and ensure they are set by the application instead of user input.\n# Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n## Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n## Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n## How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n# Remediation\nUpgrade `cookie` to version 0.7.0 or higher.\n# References\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n- [Red Hat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=2316549)\n"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Snyk Open Source"),
					Uid:             "SNYK-JS-COOKIE-8163060",
					Title:           "Medium severity - Cross-site Scripting (XSS) vulnerability in cookie",
				},
				Message: utils.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: cookie\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5 › cookie@0.3.1\n# Overview\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) via the cookie `name`, `path`, or `domain`, which can be used to set unexpected values to other cookie fields.\r\n\r\n# Workaround\r\nUsers who are not able to upgrade to the fixed version should avoid passing untrusted or arbitrary values for the cookie fields and ensure they are set by the application instead of user input.\n# Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n## Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n## Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n## How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n# Remediation\nUpgrade `cookie` to version 0.7.0 or higher.\n# References\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n- [Red Hat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=2316549)\n"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("SNYK-JS-COOKIE-8163060"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Snyk Open Source"),
					},
					Uid: utils.Ptr("6aa5ecb7-886c-5851-b60f-ad6e77b02360"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "cookie",
								PackageManager: utils.Ptr("npm"),
								Purl:           utils.Ptr("pkg:npm/cookie@0.3.1"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("(CVE-2024-47764) cookie@0.3.1"),
							Uid:  "CVE-2024-47764",
						},
						Desc:            utils.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: cookie\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5 › cookie@0.3.1\n# Overview\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) via the cookie `name`, `path`, or `domain`, which can be used to set unexpected values to other cookie fields.\r\n\r\n# Workaround\r\nUsers who are not able to upgrade to the fixed version should avoid passing untrusted or arbitrary values for the cookie fields and ensure they are set by the application instead of user input.\n# Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n## Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n## Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n## How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n# Remediation\nUpgrade `cookie` to version 0.7.0 or higher.\n# References\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n- [Red Hat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=2316549)\n"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      utils.Ptr("Medium severity - Cross-site Scripting (XSS) vulnerability in cookie"),
						VendorName: utils.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) via a POST request to the long polling transport.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.0 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/58e274c437e9cbcf69fd913c813aad8fbd253703)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/734f9d1268840722c41219e69eb58318e0b2ac6b)\n- [GitHub Tags](https://github.com/socketio/engine.io/releases/tag/3.6.0)\n- [PoC](https://github.com/bcaller/kill-engine-io)\n- [Research Blogpost](https://blog.caller.xyz/socketio-engineio-dos/)\n"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Snyk Open Source"),
					Uid:             "SNYK-JS-ENGINEIO-1056749",
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) via a POST request to the long polling transport.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.0 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/58e274c437e9cbcf69fd913c813aad8fbd253703)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/734f9d1268840722c41219e69eb58318e0b2ac6b)\n- [GitHub Tags](https://github.com/socketio/engine.io/releases/tag/3.6.0)\n- [PoC](https://github.com/bcaller/kill-engine-io)\n- [Research Blogpost](https://blog.caller.xyz/socketio-engineio-dos/)\n"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("SNYK-JS-ENGINEIO-1056749"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Snyk Open Source"),
					},
					Uid: utils.Ptr("14a13258-7227-501b-a3a4-fd425a92276a"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: utils.Ptr("npm"),
								Purl:           utils.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
							Uid:  "CVE-2020-36048",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) via a POST request to the long polling transport.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.0 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/58e274c437e9cbcf69fd913c813aad8fbd253703)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/734f9d1268840722c41219e69eb58318e0b2ac6b)\n- [GitHub Tags](https://github.com/socketio/engine.io/releases/tag/3.6.0)\n- [PoC](https://github.com/bcaller/kill-engine-io)\n- [Research Blogpost](https://blog.caller.xyz/socketio-engineio-dos/)\n"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName:      utils.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). A malicious client could send a specially crafted HTTP request, triggering an uncaught exception and killing the `Node.js` process.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.1, 6.2.1 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/425e833ab13373edf1dd5a0706f07100db14e3c6)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/83c4071af871fc188298d7d591e95670bf9f9085)\n- [GitHub PR](https://github.com/socketio/engine.io/pull/658)\n"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Snyk Open Source"),
					Uid:             "SNYK-JS-ENGINEIO-3136336",
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). A malicious client could send a specially crafted HTTP request, triggering an uncaught exception and killing the `Node.js` process.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.1, 6.2.1 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/425e833ab13373edf1dd5a0706f07100db14e3c6)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/83c4071af871fc188298d7d591e95670bf9f9085)\n- [GitHub PR](https://github.com/socketio/engine.io/pull/658)\n"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("SNYK-JS-ENGINEIO-3136336"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Snyk Open Source"),
					},
					Uid: utils.Ptr("60ccb666-be4d-5f1d-9501-a14de5fbb30a"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: utils.Ptr("npm"),
								Purl:           utils.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
							Uid:  "CVE-2022-41940",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). A malicious client could send a specially crafted HTTP request, triggering an uncaught exception and killing the `Node.js` process.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.1, 6.2.1 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/425e833ab13373edf1dd5a0706f07100db14e3c6)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/83c4071af871fc188298d7d591e95670bf9f9085)\n- [GitHub PR](https://github.com/socketio/engine.io/pull/658)\n"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName:      utils.Ptr("Snyk Open Source"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "npm", clock, nil, true, dataSource,
		)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())

		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValuesf(t, &expectedDataSource, &actualDatasource, "unequal datasources for finding %d", i)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}

		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})

	t.Run("codeql testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/code-ql.sarif.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		marshalledDataSources := []string{}
		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "file://main.go",
			},
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "github.com/foo/bar",
				Reference:     "main",
			},
		}

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   53,
				StartColumn: 103,
				EndColumn:   117,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      "file://components/consumers/defectdojo/main.go",
		}
		marshalledDataSource, err := protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   106,
				StartColumn: 103,
				EndColumn:   117,
			},
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   209,
				StartColumn: 24,
				EndColumn:   34,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      "file://components/producers/github-codeql/main.go",
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		// unset for the test
		dataSource.LocationData = nil
		dataSource.Uri = nil

		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("CodeQL"),
					Uid:             "go/incorrect-integer-conversion",
					Title:           "Incorrect conversion between integer types",
				},
				Message: utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: utils.Ptr("CodeQL"),
					},
					Uid: utils.Ptr("989bcf18-7386-58e6-8bfa-e6f2e09260a0"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/consumers/defectdojo/main.go",
									Path: utils.Ptr("file://components/consumers/defectdojo/main.go"),
								},
								StartLine: utils.Ptr(int32(53)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:            utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Incorrect conversion between integer types"),
						VendorName:      utils.Ptr("CodeQL"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("CodeQL"),
					Uid:             "go/incorrect-integer-conversion",
					Title:           "Incorrect conversion between integer types",
				},
				Message: utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: utils.Ptr("CodeQL"),
					},
					Uid: utils.Ptr("469a11c6-0581-5297-a5a4-ec5ce3dbb25b"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/consumers/defectdojo/main.go",
									Path: utils.Ptr("file://components/consumers/defectdojo/main.go"),
								},
								StartLine: utils.Ptr(int32(106)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:            utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Incorrect conversion between integer types"),
						VendorName:      utils.Ptr("CodeQL"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("CodeQL"),
					Uid:             "go/incorrect-integer-conversion",
					Title:           "Incorrect conversion between integer types",
				},
				Message: utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: utils.Ptr("CodeQL"),
					},
					Uid: utils.Ptr("61a0495a-4150-5c1b-8bdb-51982994375d"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/producers/github-codeql/main.go",
									Path: utils.Ptr("file://components/producers/github-codeql/main.go"),
								},
								StartLine: utils.Ptr(int32(209)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:            utils.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Incorrect conversion between integer types"),
						VendorName:      utils.Ptr("CodeQL"),
					},
				},
			},
		}

		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "", clock, nil, true, dataSource,
		)
		require.NoError(t, err)

		actualIssues, err := transformer.ToOCSF(context.Background())
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))

		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValuesf(t, &expectedDataSource, &actualDatasource, "unequal datasources for findign %d", i)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}

		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})

	t.Run("semgrep testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/semgrep.sarif.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))
		marshalledDataSources := []string{}

		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "github.com/foo/bar",
				Reference:     "main",
			},
		}

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   15,
				EndLine:     15,
				StartColumn: 26,
				EndColumn:   46,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      "file://terragoat/terraform/aws/ec2.tf",
		}
		marshalledDataSource, err := protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   27,
				EndLine:     31,
				StartColumn: 20,
				EndColumn:   3,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      "file://govwa/user/session/session.go",
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   9,
				EndLine:     9,
				StartColumn: 9,
				EndColumn:   50,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
			Path:      "file://go-dvwa/vulnerable/system.go",
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		// unset for the test
		dataSource.LocationData = nil
		dataSource.Uri = nil

		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.\n\n Help: AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Semgrep OSS"),
					Uid:             "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value",
					Title:           "Semgrep Finding: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value",
				},
				Message: utils.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.\n\n Help: AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
					Uid:    utils.Ptr("c2223123-ad72-543e-9563-1e2f82040ebd"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "terragoat/terraform/aws/ec2.tf",
									Path: utils.Ptr("file://terragoat/terraform/aws/ec2.tf"),
								},
								StartLine: utils.Ptr(int32(15)),
								EndLine:   utils.Ptr(int32(15)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "798",
						},
						Desc:            utils.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.\n\n Help: AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Semgrep Finding: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
						VendorName:      utils.Ptr("Semgrep OSS"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.\n\n Help: A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Semgrep OSS"),
					Uid:             "go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly",
					Title:           "Semgrep Finding: go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly",
				},
				Message: utils.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.\n\n Help: A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
					Uid:    utils.Ptr("23b6d9a5-30fb-5b14-99aa-37c96aa5ec71"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "govwa/user/session/session.go",
									Path: utils.Ptr("file://govwa/user/session/session.go"),
								},
								StartLine: utils.Ptr(int32(27)),
								EndLine:   utils.Ptr(int32(31)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "1004",
						},
						Desc:            utils.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.\n\n Help: A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Semgrep Finding: go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
						VendorName:      utils.Ptr("Semgrep OSS"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            utils.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.\n\n Help: Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Semgrep OSS"),
					Uid:             "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command",
					Title:           "Semgrep Finding: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command",
				},
				Message: utils.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.\n\n Help: Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
					Uid:    utils.Ptr("d6cd4cb9-e6f5-56cf-8cff-069ca0fe8c2c"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "go-dvwa/vulnerable/system.go",
									Path: utils.Ptr("file://go-dvwa/vulnerable/system.go"),
								},
								StartLine: utils.Ptr(int32(9)),
								EndLine:   utils.Ptr(int32(9)),
							},
						},
						Desc:            utils.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.\n\n Help: Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.\n💎 Enable cross-file analysis and Pro rules for free at sg.run/pro\n\n More info: https://semgrep.dev/r/go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Semgrep Finding: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
						VendorName:      utils.Ptr("Semgrep OSS"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "", clock, nil, true, dataSource,
		)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValuesf(t, &expectedDataSource, &actualDatasource, "unequal datasource values for finding %d", i)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}

		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})

	t.Run("trivy testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/trivy_output.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		marshalledDataSources := []string{}
		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "file://main.go",
			},
			OciPackageMetadata: &ocsffindinginfo.DataSource_OCIPackageMetadata{
				PackageUrl: "pkg:docker/ghcr.io/foo/image@v1.2.3",
				Tag:        "v1.2.3",
			},
		}

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   1,
				EndLine:     1,
				StartColumn: 1,
				EndColumn:   1,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_PURL,
			Path:      "pkg:docker/workspace/source-code/image.tar",
		}
		marshalledDataSource, err := protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		// unset for the test
		dataSource.LocationData = nil
		dataSource.Uri = nil

		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.\n\n Help: Vulnerability CVE-2016-2781\nSeverity: LOW\nPackage: coreutils\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.\n\n More info: https://avd.aquasec.com/nvd/cve-2016-2781"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Trivy"),
					Uid:             "CVE-2016-2781",
					Title:           "coreutils: Non-privileged session can escape to the parent session in chroot",
				},
				Message: utils.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.\n\n Help: Vulnerability CVE-2016-2781\nSeverity: LOW\nPackage: coreutils\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.\n\n More info: https://avd.aquasec.com/nvd/cve-2016-2781"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("CVE-2016-2781"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Trivy"),
					},
					Uid: utils.Ptr("ae20db0d-2cb2-5746-970b-d3b26020a6d5"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_INFORMATIONAL"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "image",
								PackageManager: utils.Ptr("docker"),
								Purl:           utils.Ptr("pkg:docker/ghcr.io/foo/image@v1.2.3"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."),
							Uid:  "CVE-2016-2781",
						},
						Desc:            utils.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.\n\n Help: Vulnerability CVE-2016-2781\nSeverity: LOW\nPackage: coreutils\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)\nchroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.\n\n More info: https://avd.aquasec.com/nvd/cve-2016-2781"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_INFORMATIONAL"),
						Title:           utils.Ptr("coreutils: Non-privileged session can escape to the parent session in chroot"),
						VendorName:      utils.Ptr("Trivy"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("Package: gpgv\nInstalled Version: 2.4.4-2ubuntu17.2\nVulnerability CVE-2022-3219\nSeverity: LOW\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\n\n Help: Vulnerability CVE-2022-3219\nSeverity: LOW\nPackage: gpgv\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\nGnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.\n\n More info: https://avd.aquasec.com/nvd/cve-2022-3219"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Trivy"),
					Uid:             "CVE-2022-3219",
					Title:           "gnupg: denial of service issue (resource consumption) using compressed packets",
				},
				Message: utils.Ptr("Package: gpgv\nInstalled Version: 2.4.4-2ubuntu17.2\nVulnerability CVE-2022-3219\nSeverity: LOW\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\n\n Help: Vulnerability CVE-2022-3219\nSeverity: LOW\nPackage: gpgv\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\nGnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.\n\n More info: https://avd.aquasec.com/nvd/cve-2022-3219"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("CVE-2022-3219"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Trivy"),
					},
					Uid: utils.Ptr("3694df72-260b-5514-b969-880b469684e0"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_INFORMATIONAL"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "image",
								PackageManager: utils.Ptr("docker"),
								Purl:           utils.Ptr("pkg:docker/ghcr.io/foo/image@v1.2.3"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB."),
							Uid:  "CVE-2022-3219",
						},
						Desc:            utils.Ptr("Package: gpgv\nInstalled Version: 2.4.4-2ubuntu17.2\nVulnerability CVE-2022-3219\nSeverity: LOW\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\n\n Help: Vulnerability CVE-2022-3219\nSeverity: LOW\nPackage: gpgv\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)\nGnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.\n\n More info: https://avd.aquasec.com/nvd/cve-2022-3219"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_INFORMATIONAL"),
						Title:           utils.Ptr("gnupg: denial of service issue (resource consumption) using compressed packets"),
						VendorName:      utils.Ptr("Trivy"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "docker", clock, nil, true, dataSource,
		)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				require.NoError(t, protojson.Unmarshal([]byte(d), &expectedDataSource))
				require.NoError(t, protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource))
				require.EqualExportedValues(t, &expectedDataSource, &actualDatasource)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}
		require.EqualExportedValues(t, expectedIssues, actualIssues)

	})

	t.Run("zap testcase", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/zap.sarif.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		marshalledDataSources := []string{}
		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_WEBSITE,
			WebsiteMetadata: &ocsffindinginfo.DataSource_WebsiteMetadata{
				Url: "http://bodgeit.com:8080",
			},
		}

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 70,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
			Path:      "/bodgeit/search.jsp?q=%3C%2Ffont%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cfont%3E",
		}
		marshalledDataSource, err := protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 69,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
			Path:      "/bodgeit/contact.jsp",
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 1,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
			Path:      "/bodgeit/basket.jsp",
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 1,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
			Path:      "/",
		}
		marshalledDataSource, err = protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		// unset for the test
		dataSource.LocationData = nil
		dataSource.Uri = nil

		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("ZAP"),
					Uid:             "40012",
					Title:           "Cross Site Scripting (Reflected)",
				},
				Message: utils.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("40012"),
					Product: &ocsf.Product{
						Name: utils.Ptr("ZAP"),
					},
					Uid: utils.Ptr("d12d62ce-a615-527c-8e13-e79655e31a7d"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: utils.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
							Uid:    "79",
						},
						Desc:            utils.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("Cross Site Scripting (Reflected)"),
						VendorName:      utils.Ptr("ZAP"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("ZAP"),
					Uid:             "40012",
					Title:           "Cross Site Scripting (Reflected)",
				},
				Message: utils.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("40012"),
					Product: &ocsf.Product{
						Name: utils.Ptr("ZAP"),
					},
					Uid: utils.Ptr("be3749a7-3e6f-512c-9cd6-f6fd40dea190"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: utils.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
							Uid:    "79",
						},
						Desc:            utils.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("Cross Site Scripting (Reflected)"),
						VendorName:      utils.Ptr("ZAP"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            utils.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("ZAP"),
					Uid:             "40018",
					Title:           "SQL Injection",
				},
				Message: utils.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("40018"),
					Product: &ocsf.Product{
						Name: utils.Ptr("ZAP"),
					},
					Uid: utils.Ptr("cf72f5da-0b15-5607-9da9-73175addad99"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: utils.Ptr("https://cwe.mitre.org/data/definitions/89.html"),
							Uid:    "89",
						},
						Desc:            utils.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("SQL Injection"),
						VendorName:      utils.Ptr("ZAP"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[3])},
					Desc:            utils.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("ZAP"),
					Uid:             "40018",
					Title:           "SQL Injection",
				},
				Message: utils.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("40018"),
					Product: &ocsf.Product{
						Name: utils.Ptr("ZAP"),
					},
					Uid: utils.Ptr("9805b11f-5bd1-5ceb-af02-3b4e90613e90"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: utils.Ptr("https://cwe.mitre.org/data/definitions/89.html"),
							Uid:    "89",
						},
						Desc:            utils.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(false),
						IsFixAvailable:  utils.Ptr(false),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("SQL Injection"),
						VendorName:      utils.Ptr("ZAP"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "", clock, nil, true, dataSource,
		)
		require.NoError(t, err)

		actualIssues, err := transformer.ToOCSF(context.Background())
		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))

		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValuesf(t, &expectedDataSource, &actualDatasource, "unequal values for datasources for finding %d", i)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}

		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})

	t.Run("snyk testcase with automated ecosystem detection", func(t *testing.T) {
		exampleOutput, err := os.ReadFile("./testdata/snyk-node_output.json")
		require.NoError(t, err)
		var sarifOutput sarif.SchemaJson
		require.NoError(t, json.Unmarshal(exampleOutput, &sarifOutput))

		marshalledDataSources := []string{}
		dataSource := &ocsffindinginfo.DataSource{
			TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
			SourceCodeMetadata: &ocsffindinginfo.DataSource_SourceCodeMetadata{
				RepositoryUrl: "github.com/foo/bar",
				Reference:     "main",
			},
		}
		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 1,
			},
		}
		marshalledDataSource, err := protojson.Marshal(dataSource)
		require.NoError(t, err)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		clock := clockwork.NewFakeClockAt(staticNow)
		now := staticNow
		expectedIssues := []*ocsf.VulnerabilityFinding{
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            utils.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: cookie\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5 › cookie@0.3.1\n# Overview\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) via the cookie `name`, `path`, or `domain`, which can be used to set unexpected values to other cookie fields.\r\n\r\n# Workaround\r\nUsers who are not able to upgrade to the fixed version should avoid passing untrusted or arbitrary values for the cookie fields and ensure they are set by the application instead of user input.\n# Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n## Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n## Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n## How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n# Remediation\nUpgrade `cookie` to version 0.7.0 or higher.\n# References\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n- [Red Hat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=2316549)\n"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Snyk Open Source"),
					Uid:             "SNYK-JS-COOKIE-8163060",
					Title:           "Medium severity - Cross-site Scripting (XSS) vulnerability in cookie",
				},
				Message: utils.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: cookie\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5 › cookie@0.3.1\n# Overview\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) via the cookie `name`, `path`, or `domain`, which can be used to set unexpected values to other cookie fields.\r\n\r\n# Workaround\r\nUsers who are not able to upgrade to the fixed version should avoid passing untrusted or arbitrary values for the cookie fields and ensure they are set by the application instead of user input.\n# Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n## Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n## Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n## How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n# Remediation\nUpgrade `cookie` to version 0.7.0 or higher.\n# References\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n- [Red Hat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=2316549)\n"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("SNYK-JS-COOKIE-8163060"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Snyk Open Source"),
					},
					Uid: utils.Ptr("6aa5ecb7-886c-5851-b60f-ad6e77b02360"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "cookie",
								PackageManager: utils.Ptr("npm"),
								Purl:           utils.Ptr("pkg:npm/cookie@0.3.1"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("(CVE-2024-47764) cookie@0.3.1"),
							Uid:  "CVE-2024-47764",
						},
						Desc:            utils.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: cookie\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5 › cookie@0.3.1\n# Overview\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) via the cookie `name`, `path`, or `domain`, which can be used to set unexpected values to other cookie fields.\r\n\r\n# Workaround\r\nUsers who are not able to upgrade to the fixed version should avoid passing untrusted or arbitrary values for the cookie fields and ensure they are set by the application instead of user input.\n# Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n## Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n## Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n## How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n# Remediation\nUpgrade `cookie` to version 0.7.0 or higher.\n# References\n- [GitHub Commit](https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c)\n- [GitHub PR](https://github.com/jshttp/cookie/pull/167)\n- [Red Hat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=2316549)\n"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           utils.Ptr("Medium severity - Cross-site Scripting (XSS) vulnerability in cookie"),
						VendorName:      utils.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) via a POST request to the long polling transport.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.0 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/58e274c437e9cbcf69fd913c813aad8fbd253703)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/734f9d1268840722c41219e69eb58318e0b2ac6b)\n- [GitHub Tags](https://github.com/socketio/engine.io/releases/tag/3.6.0)\n- [PoC](https://github.com/bcaller/kill-engine-io)\n- [Research Blogpost](https://blog.caller.xyz/socketio-engineio-dos/)\n"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Snyk Open Source"),
					Uid:             "SNYK-JS-ENGINEIO-1056749",
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) via a POST request to the long polling transport.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.0 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/58e274c437e9cbcf69fd913c813aad8fbd253703)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/734f9d1268840722c41219e69eb58318e0b2ac6b)\n- [GitHub Tags](https://github.com/socketio/engine.io/releases/tag/3.6.0)\n- [PoC](https://github.com/bcaller/kill-engine-io)\n- [Research Blogpost](https://blog.caller.xyz/socketio-engineio-dos/)\n"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("SNYK-JS-ENGINEIO-1056749"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Snyk Open Source"),
					},
					Uid: utils.Ptr("14a13258-7227-501b-a3a4-fd425a92276a"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: utils.Ptr("npm"),
								Purl:           utils.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
							Uid:  "CVE-2020-36048",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) via a POST request to the long polling transport.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.0 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/58e274c437e9cbcf69fd913c813aad8fbd253703)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/734f9d1268840722c41219e69eb58318e0b2ac6b)\n- [GitHub Tags](https://github.com/socketio/engine.io/releases/tag/3.6.0)\n- [PoC](https://github.com/bcaller/kill-engine-io)\n- [Research Blogpost](https://blog.caller.xyz/socketio-engineio-dos/)\n"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName:      utils.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: utils.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: utils.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    utils.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   utils.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: utils.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        utils.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     utils.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). A malicious client could send a specially crafted HTTP request, triggering an uncaught exception and killing the `Node.js` process.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.1, 6.2.1 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/425e833ab13373edf1dd5a0706f07100db14e3c6)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/83c4071af871fc188298d7d591e95670bf9f9085)\n- [GitHub PR](https://github.com/socketio/engine.io/pull/658)\n"),
					FirstSeenTime:   utils.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    utils.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    utils.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      utils.Ptr("Snyk Open Source"),
					Uid:             "SNYK-JS-ENGINEIO-3136336",
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). A malicious client could send a specially crafted HTTP request, triggering an uncaught exception and killing the `Node.js` process.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.1, 6.2.1 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/425e833ab13373edf1dd5a0706f07100db14e3c6)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/83c4071af871fc188298d7d591e95670bf9f9085)\n- [GitHub PR](https://github.com/socketio/engine.io/pull/658)\n"),
				Metadata: &ocsf.Metadata{
					EventCode: utils.Ptr("SNYK-JS-ENGINEIO-3136336"),
					Product: &ocsf.Product{
						Name: utils.Ptr("Snyk Open Source"),
					},
					Uid: utils.Ptr("60ccb666-be4d-5f1d-9501-a14de5fbb30a"),
				},
				Severity:   utils.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  utils.Ptr(now.Unix()),
				StatusId:   utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     utils.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   utils.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: utils.Ptr("npm"),
								Purl:           utils.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: utils.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
							Uid:  "CVE-2022-41940",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            utils.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability.\n\n Help: * Package Manager: npm\n* Vulnerable module: engine.io\n* Introduced through: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964, socket.io@1.7.4 and others\n### Detailed paths\n* _Introduced through_: realtimechat@extwiii/Nodejs-Real-time-Chat-App#c2ffccab1a6ad4ade9f33eacb647997b8c2ff964 › socket.io@1.7.4 › engine.io@1.8.5\n# Overview\n[engine.io](https://github.com/socketio/engine.io) is a realtime engine behind Socket.IO. It provides the foundation of a bidirectional connection between client and server\n\nAffected versions of this package are vulnerable to Denial of Service (DoS). A malicious client could send a specially crafted HTTP request, triggering an uncaught exception and killing the `Node.js` process.\n\n# Details\n\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\n\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\n\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\n\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\n\nTwo common types of DoS vulnerabilities:\n\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](https://security.snyk.io/vuln/SNYK-JAVA-COMMONSFILEUPLOAD-30082).\n\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)\n\n# Remediation\nUpgrade `engine.io` to version 3.6.1, 6.2.1 or higher.\n# References\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/425e833ab13373edf1dd5a0706f07100db14e3c6)\n- [GitHub Commit](https://github.com/socketio/engine.io/commit/83c4071af871fc188298d7d591e95670bf9f9085)\n- [GitHub PR](https://github.com/socketio/engine.io/pull/658)\n"),
						FirstSeenTime:   utils.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    utils.Ptr(true),
						IsFixAvailable:  utils.Ptr(true),
						LastSeenTime:    utils.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        utils.Ptr("SEVERITY_ID_HIGH"),
						Title:           utils.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName:      utils.Ptr("Snyk Open Source"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(
			&sarifOutput, "", clock, nil, true, dataSource,
		)
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background())

		require.NoError(t, err)
		require.Equal(t, len(actualIssues), len(expectedIssues))
		// handle datasource differently see https://github.com/golang/protobuf/issues/1121
		for i, e := range expectedIssues {
			var expectedDataSource, actualDatasource ocsffindinginfo.DataSource
			require.Equal(t, len(e.FindingInfo.DataSources), len(actualIssues[i].FindingInfo.DataSources))

			for j, d := range e.GetFindingInfo().DataSources {
				protojson.Unmarshal([]byte(d), &expectedDataSource)
				protojson.Unmarshal([]byte(actualIssues[i].FindingInfo.DataSources[j]), &actualDatasource)
				require.EqualExportedValuesf(t, &expectedDataSource, &actualDatasource, "unequal datasource for finding %d", i)
			}
			expectedIssues[i].FindingInfo.DataSources = nil
			actualIssues[i].FindingInfo.DataSources = nil
		}

		require.EqualExportedValues(t, expectedIssues, actualIssues)
	})
}
func Test_MergeDataSources_EcosystemFallback(t *testing.T) {
	// Edge case: SARIF finding for container image, no ecosystem in SARIF, should fallback to datasource's OCI metadata PURL
	sarifResult := sarif.SchemaJson{
		Runs: []sarif.Run{
			{
				Results: []sarif.Result{
					{
						RuleId: utils.Ptr("CVE-2020-36048"),
						Message: sarif.Message{
							Text: utils.Ptr("Denial of Service (DoS) vulnerability in engine.io"),
						},
						Locations: []sarif.Location{
							{
								PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{
										Uri: utils.Ptr("workspace/source-code/image.tar"),
									},
								},
							},
						},
					},
				},
			},
		},
	}
	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
		OciPackageMetadata: &ocsffindinginfo.DataSource_OCIPackageMetadata{
			PackageUrl: "pkg:docker/ghcr.io/foo/image@v1.2.3",
			Tag:        "v1.2.3",
		},
	}
	transformer, err := sariftransformer.NewTransformer(&sarifResult, "", clockwork.NewFakeClock(), nil, false, dataSource)
	require.NoError(t, err)
	issues, err := transformer.ToOCSF(context.Background())
	require.NoError(t, err)
	require.Len(t, issues, 1)
	ds := &ocsffindinginfo.DataSource{}
	err = protojson.Unmarshal([]byte(issues[0].FindingInfo.DataSources[0]), ds)
	require.NoError(t, err)
	require.Equal(t, ds.TargetType, ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE)
	require.Equal(t, ds.Uri.UriSchema, ocsffindinginfo.DataSource_URI_SCHEMA_PURL)
	require.Equal(t, ds.OciPackageMetadata.PackageUrl, "pkg:docker/ghcr.io/foo/image@v1.2.3")
}

func Test_MergeDataSources_MissingMetadataError(t *testing.T) {
	// Edge case: SARIF finding for container image, no ecosystem, no OCI metadata, should error
	sarifResult := sarif.SchemaJson{
		Runs: []sarif.Run{
			{
				Results: []sarif.Result{
					{
						RuleId: utils.Ptr("CVE-2020-36048"),
						Message: sarif.Message{
							Text: utils.Ptr("Denial of Service (DoS) vulnerability in engine.io"),
						},
						Locations: []sarif.Location{
							{
								PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{
										Uri: utils.Ptr("OS%PKGs"),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Instead of calling mergeDataSources directly, use the public ToOCSF method
	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_CONTAINER_IMAGE,
		OciPackageMetadata: &ocsffindinginfo.DataSource_OCIPackageMetadata{
			Tag: "v1.2.3",
		},
	}

	transformer, err := sariftransformer.NewTransformer(
		&sarifResult,
		"",
		clockwork.NewFakeClock(),
		nil,
		false,
		dataSource,
	)
	require.NoError(t, err)

	_, err = transformer.ToOCSF(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "could not parse pURL based on the artifact location URI and no datasource provided")
}
