package sarif

import (
	"testing"

	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStableUUID(t *testing.T) {
	uuidProvider, err := NewBasicStableUUIDProvider()
	require.NoError(t, err)

	t.Run("uuid provider is stable for different places of the rule ID", func(t *testing.T) {
		locations := []sarif.Location{
			{
				PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{
						Uri: utils.Ptr("main.go"),
					},
					Region: &sarif.Region{
						StartLine:      utils.Ptr(80),
						StartColumn:    utils.Ptr(2),
						EndLine:        utils.Ptr(80),
						EndColumn:      utils.Ptr(2),
						SourceLanguage: utils.Ptr("go"),
						Snippet: &sarif.ArtifactContent{
							Text: utils.Ptr("db.Exec(query)"),
						},
					},
				},
			},
		}

		expectedGUID := "637dda5f-20e1-56a2-b9af-09bf179d2950"
		guid, err := uuidProvider.Generate("gosec", &sarif.Result{
			RuleId:    utils.Ptr("G404"),
			Locations: locations,
		})
		require.NoError(t, err)
		assert.Equal(t, expectedGUID, guid)

		guid, err = uuidProvider.Generate("gosec", &sarif.Result{
			Rule: &sarif.ReportingDescriptorReference{
				Id: utils.Ptr("G404"),
			},
			Locations: locations,
		})
		require.NoError(t, err)
		assert.Equal(t, expectedGUID, guid)

		guid, err = uuidProvider.Generate("gosec", &sarif.Result{
			Rule: &sarif.ReportingDescriptorReference{
				Id:   utils.Ptr("G404"),
				Guid: utils.Ptr("0b432955-8550-52cf-a448-c14b3593734e"),
			},
			Locations: locations,
		})
		require.NoError(t, err)
		assert.Equal(t, expectedGUID, guid)

		expectedGUIDForGUID := "f3c0e9e5-9244-58c1-bc48-f2075a266f3c"
		guid, err = uuidProvider.Generate("gosec", &sarif.Result{
			Rule: &sarif.ReportingDescriptorReference{
				Guid: utils.Ptr("0b432955-8550-52cf-a448-c14b3593734e"),
			},
			Locations: locations,
		})
		require.NoError(t, err)
		assert.Equal(t, expectedGUIDForGUID, guid)
	})

	t.Run("different tool name causes different GUID", func(t *testing.T) {
		locations := []sarif.Location{
			{
				PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{
						Uri: utils.Ptr("main.go"),
					},
					Region: &sarif.Region{
						StartLine:      utils.Ptr(80),
						StartColumn:    utils.Ptr(2),
						EndLine:        utils.Ptr(80),
						EndColumn:      utils.Ptr(2),
						SourceLanguage: utils.Ptr("go"),
						Snippet: &sarif.ArtifactContent{
							Text: utils.Ptr("db.Exec(query)"),
						},
					},
				},
			},
		}

		expectedGUID := "637dda5f-20e1-56a2-b9af-09bf179d2950"
		guid, err := uuidProvider.Generate("gosec", &sarif.Result{
			RuleId:    utils.Ptr("G404"),
			Locations: locations,
		})
		require.NoError(t, err)
		assert.Equal(t, expectedGUID, guid)

		expectedGUID = "9c312108-6db4-5d3d-834d-591b7495e1c8"
		guid, err = uuidProvider.Generate("zap", &sarif.Result{
			RuleId:    utils.Ptr("G404"),
			Locations: locations,
		})
		require.NoError(t, err)
		assert.Equal(t, expectedGUID, guid)
	})

	t.Run("existing guid is not changed by the uuid provider", func(t *testing.T) {
		expectedGUID := "0000000-1111-5222-bbbb-09bf179d2950"
		guid, err := uuidProvider.Generate("gosec", &sarif.Result{
			RuleId: utils.Ptr("G404"),
			Guid:   utils.Ptr(expectedGUID),
			Locations: []sarif.Location{
				{
					PhysicalLocation: &sarif.PhysicalLocation{
						ArtifactLocation: &sarif.ArtifactLocation{
							Uri: utils.Ptr("main.go"),
						},
						Region: &sarif.Region{
							StartLine:      utils.Ptr(80),
							StartColumn:    utils.Ptr(2),
							EndLine:        utils.Ptr(80),
							EndColumn:      utils.Ptr(2),
							SourceLanguage: utils.Ptr("go"),
							Snippet: &sarif.ArtifactContent{
								Text: utils.Ptr("db.Exec(query)"),
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)
		require.Equal(t, expectedGUID, guid)
	})
}
