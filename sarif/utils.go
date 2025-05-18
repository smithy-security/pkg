package sarif

import (
	"regexp"
	"strings"

	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/pkg/utils"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

var cweRegex = regexp.MustCompile(`(?i)CWE-\d{3,}`)

func resolveCWE(
	ruleID string,
	taxasByCWEID map[string]sarif.ReportingDescriptor,
	ruleToTools map[string]sarif.ReportingDescriptor,
) *ocsf.Cwe {
	cwe := &ocsf.Cwe{}

	rule, ok := ruleToTools[ruleID]
	if !ok {
		return nil
	}

	for _, rel := range rule.Relationships {
		cwe.Uid = *rel.Target.Id
		taxa, ok := taxasByCWEID[cwe.Uid]
		if !ok {
			continue
		}
		cwe.SrcUrl = taxa.HelpUri
		if taxa.FullDescription != nil && taxa.FullDescription.Text != "" {
			cwe.Caption = utils.Ptr(taxa.FullDescription.Text)
		}
	}
	if cwe.Uid != "" {
		return cwe
	}
	// if all else fails try to match regexp with tags (semgrep, snyk and codeql do that)
	if rule.Properties != nil {
		for _, tag := range rule.Properties.Tags {
			matches := cweRegex.FindAllString(tag, -1)
			for _, match := range matches {
				if match != "" {
					cwe.Uid = strings.ReplaceAll(strings.ToLower(match), "cwe-", "")
					return cwe // we only care about 1, since ocsf only supports one cwe
				}
			}

		}
	}
	return nil // all failed, no cwe
}

func getRuleID(res *sarif.Result) *string {
	if res.RuleId != nil {
		return res.RuleId
	} else if res.Rule != nil {
		if res.Rule.ToolComponent != nil {
			return res.Rule.ToolComponent.Name
		}
	}

	return nil
}
