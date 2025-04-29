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
	"github.com/smithy-security/pkg/sarif/internal/ptr"
	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
)

const fixedUUID = "d258a2dc-b324-46aa-9cea-28ba8d44fcb8"

var (
	//go:embed testdata/gosec_v2.1.0.json
	reportV2_1_0 []byte

	staticNow = time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)
)

type MockUUIDProvider struct {
	FixedUUID string
}

func (m MockUUIDProvider) String() string {
	return m.FixedUUID
}

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
			}}
		marshalledDataSource, err := protojson.Marshal(datasource)
		require.NoError(t, err)

		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))

		datasource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine:   83,
				EndLine:     83,
				StartColumn: 7,
				EndColumn:   7,
			}}
		marshalledDataSource, err = protojson.Marshal(datasource)
		marshalledDataSources = append(marshalledDataSources, string(marshalledDataSource))
		require.NoError(t, err)

		datasource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 83,
			}}
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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("[test for missing endLine, common in some tools]"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("gosec"),
					Uid:             fixedUUID,
					Title:           "[test for missing endLine, common in some tools]",
				},
				Message: ptr.Ptr("[test for missing endLine, common in some tools]"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("G404"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("gosec"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH, StartTime: ptr.Ptr(now.Unix()),
				StatusId: ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:   ptr.Ptr("STATUS_ID_NEW"),
				Time:     now.Unix(),
				TimeDt:   timestamppb.New(now),
				TypeName: ptr.Ptr("Create"),
				TypeUid:  int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "main.go",
									Path: ptr.Ptr("file://main.go"),
								},
								StartLine: ptr.Ptr(int32(83)),
							},
						},
						Desc:            ptr.Ptr("[test for missing endLine, common in some tools]"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:           ptr.Ptr("[test for missing endLine, common in some tools]"),
						VendorName:      ptr.Ptr("gosec"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("gosec"),
					Uid:             fixedUUID,
					Title:           "Use of weak random number generator (math/rand instead of crypto/rand)",
				},
				Message: ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("G404"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("gosec"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH, StartTime: ptr.Ptr(now.Unix()),
				StatusId: ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:   ptr.Ptr("STATUS_ID_NEW"),
				Time:     now.Unix(),
				TimeDt:   timestamppb.New(now),
				TypeName: ptr.Ptr("Create"),
				TypeUid:  int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{

									Name: "main.go",
									Path: ptr.Ptr("file://main.go"),
								},
								StartLine: ptr.Ptr(int32(83)),
								EndLine:   ptr.Ptr(int32(83)),
							},
						},
						Desc:            ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:           ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand)"),
						VendorName:      ptr.Ptr("gosec"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("gosec"),
					Uid:             fixedUUID,
					Title:           "Use of weak random number generator (math/rand instead of crypto/rand) - nil endline",
				},
				Message: ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("G404"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("gosec"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{

									Name: "main.go",
									Path: ptr.Ptr("file://main.go"),
								},
								StartLine: ptr.Ptr(int32(83)),
							},
						},
						AffectedPackages: nil, // on purpose, we really want to make sure this is nil as opposed to any other default value since gosec is not handling packages

						Desc:            ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:           ptr.Ptr("Use of weak random number generator (math/rand instead of crypto/rand) - nil endline"),
						VendorName:      ptr.Ptr("gosec"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), datasource)

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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Snyk Open Source"),
					Uid:             fixedUUID,
					Title:           "Medium severity - Cross-site Scripting (XSS) vulnerability in cookie",
				},
				Message: ptr.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-COOKIE-8163060"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "cookie",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/cookie@0.3.1"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
							Uid:  "CVE-2024-47764",
						},
						Desc:            ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("Medium severity - Cross-site Scripting (XSS) vulnerability in cookie"),
						VendorName: ptr.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Snyk Open Source"),
					Uid:             fixedUUID,
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-ENGINEIO-1056749"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
							Uid:  "CVE-2020-36048",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName: ptr.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Snyk Open Source"),
					Uid:             fixedUUID,
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-ENGINEIO-3136336"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
							Uid:  "CVE-2022-41940",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName: ptr.Ptr("Snyk Open Source"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "npm", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), dataSource)

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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("CodeQL"),
					Uid:             fixedUUID,
					Title:           "Incorrect conversion between integer types",
				},
				Message: ptr.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("CodeQL"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/consumers/defectdojo/main.go",
									Path: ptr.Ptr("file://components/consumers/defectdojo/main.go"),
								},
								StartLine: ptr.Ptr(int32(53)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:            ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           ptr.Ptr("Incorrect conversion between integer types"),
						VendorName:      ptr.Ptr("CodeQL"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("CodeQL"),
					Uid:             fixedUUID,
					Title:           "Incorrect conversion between integer types",
				},
				Message: ptr.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("CodeQL"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/consumers/defectdojo/main.go",
									Path: ptr.Ptr("file://components/consumers/defectdojo/main.go"),
								},
								StartLine: ptr.Ptr(int32(106)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:            ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           ptr.Ptr("Incorrect conversion between integer types"),
						VendorName:      ptr.Ptr("CodeQL"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_HIGH"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("CodeQL"),
					Uid:             fixedUUID,
					Title:           "Incorrect conversion between integer types",
				},
				Message: ptr.Ptr("Incorrect conversion of an integer with architecture-dependent bit size from [strconv.Atoi](1) to a lower bit size type int32 without an upper bound check."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go/incorrect-integer-conversion"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("CodeQL"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "components/producers/github-codeql/main.go",
									Path: ptr.Ptr("file://components/producers/github-codeql/main.go"),
								},
								StartLine: ptr.Ptr(int32(209)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "190",
						},
						Desc:            ptr.Ptr("Converting the result of `strconv.Atoi`, `strconv.ParseInt`, and `strconv.ParseUint` to integer types of smaller bit size can produce unexpected values."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           ptr.Ptr("Incorrect conversion between integer types"),
						VendorName:      ptr.Ptr("CodeQL"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), dataSource)
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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Semgrep OSS"),
					Uid:             fixedUUID,
					Title:           "Semgrep Finding: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value",
				},
				Message: ptr.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "terragoat/terraform/aws/ec2.tf",
									Path: ptr.Ptr("file://terragoat/terraform/aws/ec2.tf"),
								},
								StartLine: ptr.Ptr(int32(15)),
								EndLine:   ptr.Ptr(int32(15)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "798",
						},
						Desc:            ptr.Ptr("AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           ptr.Ptr("Semgrep Finding: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value"),
						VendorName:      ptr.Ptr("Semgrep OSS"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Semgrep OSS"),
					Uid:             fixedUUID,
					Title:           "Semgrep Finding: go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly",
				},
				Message: ptr.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "govwa/user/session/session.go",
									Path: ptr.Ptr("file://govwa/user/session/session.go"),
								},
								StartLine: ptr.Ptr(int32(27)),
								EndLine:   ptr.Ptr(int32(31)),
							},
						},
						Cwe: &ocsf.Cwe{
							Uid: "1004",
						},
						Desc:            ptr.Ptr("A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           ptr.Ptr("Semgrep Finding: go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly"),
						VendorName:      ptr.Ptr("Semgrep OSS"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            ptr.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Semgrep OSS"),
					Uid:             fixedUUID,
					Title:           "Semgrep Finding: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command",
				},
				Message: ptr.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Semgrep OSS"),
					},
					Labels: []string{"{}"},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File: &ocsf.File{
									Name: "go-dvwa/vulnerable/system.go",
									Path: ptr.Ptr("file://go-dvwa/vulnerable/system.go"),
								},
								StartLine: ptr.Ptr(int32(9)),
								EndLine:   ptr.Ptr(int32(9)),
							},
						},
						Desc:            ptr.Ptr("Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:           ptr.Ptr("Semgrep Finding: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"),
						VendorName:      ptr.Ptr("Semgrep OSS"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), dataSource)
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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Trivy"),
					Uid:             "d258a2dc-b324-46aa-9cea-28ba8d44fcb8",
					Title:           "coreutils: Non-privileged session can escape to the parent session in chroot",
				},
				Message: ptr.Ptr("Package: coreutils\nInstalled Version: 9.4-3ubuntu6\nVulnerability CVE-2016-2781\nSeverity: LOW\nFixed Version: \nLink: [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("CVE-2016-2781"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Trivy"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_INFORMATIONAL"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
								EndLine:   ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "image",
								PackageManager: ptr.Ptr("docker"),
								Purl:           ptr.Ptr("pkg:docker/ghcr.io/foo/image@v1.2.3"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."),
							Uid:  "CVE-2016-2781",
						},
						Desc:            ptr.Ptr("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_INFORMATIONAL"),
						Title:           ptr.Ptr("coreutils: Non-privileged session can escape to the parent session in chroot"),
						VendorName:      ptr.Ptr("Trivy"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Trivy"),
					Uid:             "d258a2dc-b324-46aa-9cea-28ba8d44fcb8",
					Title:           "gnupg: denial of service issue (resource consumption) using compressed packets",
				},
				Message: ptr.Ptr("Package: gpgv\nInstalled Version: 2.4.4-2ubuntu17.2\nVulnerability CVE-2022-3219\nSeverity: LOW\nFixed Version: \nLink: [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)"),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("CVE-2022-3219"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Trivy"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_INFORMATIONAL"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
								EndLine:   ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "image",
								PackageManager: ptr.Ptr("docker"),
								Purl:           ptr.Ptr("pkg:docker/ghcr.io/foo/image@v1.2.3"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB."),
							Uid:  "CVE-2022-3219",
						},
						Desc:            ptr.Ptr("GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_INFORMATIONAL"),
						Title:           ptr.Ptr("gnupg: denial of service issue (resource consumption) using compressed packets"),
						VendorName:      ptr.Ptr("Trivy"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "docker", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), dataSource)
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
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      "file://main.go",
			},
			WebsiteMetadata: &ocsffindinginfo.DataSource_WebsiteMetadata{
				Url: "http://bodgeit.com:8080/bodgeit",
			},
		}

		dataSource.LocationData = &ocsffindinginfo.DataSource_FileFindingLocationData_{
			FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
				StartLine: 70,
			},
		}
		dataSource.Uri = &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_WEBSITE,
			Path:      "http://bodgeit.com:8080/bodgeit/search.jsp?q=%3C%2Ffont%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cfont%3E",
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
			Path:      "http://bodgeit.com:8080/bodgeit/contact.jsp",
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
			Path:      "http://bodgeit.com:8080/bodgeit/basket.jsp",
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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("ZAP"),
					Uid:             fixedUUID,
					Title:           "Cross Site Scripting (Reflected)",
				},
				Message: ptr.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("40012"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("ZAP"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: ptr.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
							Uid:    "79",
						},
						Desc:            ptr.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:           ptr.Ptr("Cross Site Scripting (Reflected)"),
						VendorName:      ptr.Ptr("ZAP"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("ZAP"),
					Uid:             fixedUUID,
					Title:           "Cross Site Scripting (Reflected)",
				},
				Message: ptr.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("40012"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("ZAP"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: ptr.Ptr("https://cwe.mitre.org/data/definitions/79.html"),
							Uid:    "79",
						},
						Desc:            ptr.Ptr("Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.\nWhen an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.\n\nThere are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.\nNon-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.\nPersistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:           ptr.Ptr("Cross Site Scripting (Reflected)"),
						VendorName:      ptr.Ptr("ZAP"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            ptr.Ptr("SQL injection may be possible."),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("ZAP"),
					Uid:             fixedUUID,
					Title:           "SQL Injection",
				},
				Message: ptr.Ptr("The original page results were successfully replicated using the expression [5-2] as the parameter value\nThe parameter value being modified was stripped from the HTML output for the purposes of the comparison."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("40018"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("ZAP"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						Cwe: &ocsf.Cwe{
							SrcUrl: ptr.Ptr("https://cwe.mitre.org/data/definitions/89.html"),
							Uid:    "89",
						},
						Desc:            ptr.Ptr("SQL injection may be possible."),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(false),
						IsFixAvailable:  ptr.Ptr(false),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),
						Severity:        ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:           ptr.Ptr("SQL Injection"),
						VendorName:      ptr.Ptr("ZAP"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), dataSource)
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
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[0])},
					Desc:            ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Snyk Open Source"),
					Uid:             fixedUUID,
					Title:           "Medium severity - Cross-site Scripting (XSS) vulnerability in cookie",
				},
				Message: ptr.Ptr("This file introduces a vulnerable cookie package with a medium severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-COOKIE-8163060"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "cookie",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/cookie@0.3.1"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
							Uid:  "CVE-2024-47764",
						},
						Desc:            ptr.Ptr("(CVE-2024-47764) cookie@0.3.1"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   ptr.Ptr("SEVERITY_ID_MEDIUM"),
						Title:      ptr.Ptr("Medium severity - Cross-site Scripting (XSS) vulnerability in cookie"),
						VendorName: ptr.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[1])},
					Desc:            ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Snyk Open Source"),
					Uid:             fixedUUID,
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-ENGINEIO-1056749"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
							Uid:  "CVE-2020-36048",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            ptr.Ptr("(CVE-2020-36048) engine.io@1.8.5"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName: ptr.Ptr("Snyk Open Source"),
					},
				},
			},
			{
				ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
				ActivityName: ptr.Ptr("ACTIVITY_ID_CREATE"),
				CategoryName: ptr.Ptr("CATEGORY_UID_FINDINGS"),
				CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
				ClassName:    ptr.Ptr("CLASS_UID_VULNERABILITY_FINDING"),
				ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
				Confidence:   ptr.Ptr("CONFIDENCE_ID_UNKNOWN"),
				ConfidenceId: ptr.Ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_UNKNOWN),
				Count:        ptr.Ptr(int32(1)),
				FindingInfo: &ocsf.FindingInfo{
					CreatedTime:     ptr.Ptr(now.Unix()),
					CreatedTimeDt:   timestamppb.New(now),
					DataSources:     []string{string(marshalledDataSources[2])},
					Desc:            ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
					FirstSeenTime:   ptr.Ptr(now.Unix()),
					FirstSeenTimeDt: timestamppb.New(now),
					LastSeenTime:    ptr.Ptr(now.Unix()),
					LastSeenTimeDt:  timestamppb.New(now),
					ModifiedTime:    ptr.Ptr(now.Unix()),
					ModifiedTimeDt:  timestamppb.New(now),
					ProductUid:      ptr.Ptr("Snyk Open Source"),
					Uid:             fixedUUID,
					Title:           "High severity - Denial of Service (DoS) vulnerability in engine.io",
				},
				Message: ptr.Ptr("This file introduces a vulnerable engine.io package with a high severity vulnerability."),
				Metadata: &ocsf.Metadata{
					EventCode: ptr.Ptr("SNYK-JS-ENGINEIO-3136336"),
					Product: &ocsf.Product{
						Name: ptr.Ptr("Snyk Open Source"),
					},
				},
				Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
				SeverityId: ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
				StartTime:  ptr.Ptr(now.Unix()),
				StatusId:   ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
				Status:     ptr.Ptr("STATUS_ID_NEW"),
				Time:       now.Unix(),
				TimeDt:     timestamppb.New(now),
				TypeName:   ptr.Ptr("Create"),
				TypeUid:    int64(200201),
				Vulnerabilities: []*ocsf.Vulnerability{
					{
						AffectedCode: []*ocsf.AffectedCode{
							{
								File:      &ocsf.File{},
								StartLine: ptr.Ptr(int32(1)),
							},
						},
						AffectedPackages: []*ocsf.AffectedPackage{
							{
								Name:           "engine.io",
								PackageManager: ptr.Ptr("npm"),
								Purl:           ptr.Ptr("pkg:npm/engine.io@1.8.5"),
							},
						},
						Cve: &ocsf.Cve{
							Desc: ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
							Uid:  "CVE-2022-41940",
						},
						Cwe: &ocsf.Cwe{
							Uid: "400",
						},
						Desc:            ptr.Ptr("(CVE-2022-41940) engine.io@1.8.5"),
						FirstSeenTime:   ptr.Ptr(now.Unix()),
						FirstSeenTimeDt: timestamppb.New(now),
						FixAvailable:    ptr.Ptr(true),
						IsFixAvailable:  ptr.Ptr(true),
						LastSeenTime:    ptr.Ptr(now.Unix()),
						LastSeenTimeDt:  timestamppb.New(now),

						Severity:   ptr.Ptr("SEVERITY_ID_HIGH"),
						Title:      ptr.Ptr("High severity - Denial of Service (DoS) vulnerability in engine.io"),
						VendorName: ptr.Ptr("Snyk Open Source"),
					},
				},
			},
		}
		transformer, err := sariftransformer.NewTransformer(&sarifOutput, "", clock, MockUUIDProvider{FixedUUID: fixedUUID})
		require.NoError(t, err)
		actualIssues, err := transformer.ToOCSF(context.Background(), dataSource)

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
