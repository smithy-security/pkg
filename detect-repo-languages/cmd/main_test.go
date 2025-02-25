package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	repolanguages "github.com/smithy-security/pkg/detect-repo-languages"
)

func TestRepoLanguageDetection(t *testing.T) {
	dir, err := os.Getwd()
	require.NoError(t, err)

	repoRoot := filepath.Join(dir, "../")
	emptyDir := t.TempDir()

	tests := []struct {
		name        string
		codeDir     string
		expectedRes []string
		expectedErr error
	}{
		{
			name:    "happy path",
			codeDir: repoRoot,
			expectedRes: []string{
				"dockerfile",
				"go",
			},
		},
		{
			name:        "no recognisable code",
			codeDir:     emptyDir,
			expectedRes: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := repolanguages.Detect(tt.codeDir)
			require.ErrorIs(t, tt.expectedErr, err)
			require.EqualValues(t, tt.expectedRes, res)
		})
	}
}
