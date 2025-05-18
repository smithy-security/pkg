package sarif

import (
	"testing"

	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCVEExtraction(t *testing.T) {
	t.Run("cve in rule id - osv-scanner", func(t *testing.T) {
		rule := sarif.ReportingDescriptor{
			Id:   "CVE-2019-20477",
			Name: utils.Ptr("CVE-2019-20477"),
			ShortDescription: &sarif.MultiformatMessageString{
				Text: "CVE-2019-20477: Deserialization of Untrusted Data in PyYAML",
			},
			FullDescription: &sarif.MultiformatMessageString{
				Text:     "PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.",
				Markdown: utils.Ptr("PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342."),
			},
		}
		cve := extractCVE(rule)
		require.NotNil(t, cve)
		assert.Equal(t, "CVE-2019-20477", cve.Uid)
		require.NotNil(t, cve.Desc)
		assert.Equal(t, "PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.", *cve.Desc)
	})

	t.Run("no cve in rule - codeql", func(t *testing.T) {
		rule := sarif.ReportingDescriptor{
			Id:   "go/incomplete-hostname-regexp",
			Name: utils.Ptr("go/incomplete-hostname-regexp"),
			ShortDescription: &sarif.MultiformatMessageString{
				Text: "Incomplete regular expression for hostnames",
			},
			FullDescription: &sarif.MultiformatMessageString{
				Text: "Matching a URL or hostname against a regular expression that contains an unescaped dot as part of the hostname might match more hostnames than expected.",
			},
		}
		assert.Nil(t, extractCVE(rule))
	})

	t.Run("cve in rule's full description - osv-scanner-corner-case", func(t *testing.T) {
		rule := sarif.ReportingDescriptor{
			Id:   "SOME-RULE",
			Name: utils.Ptr("SOME-RULE"),
			ShortDescription: &sarif.MultiformatMessageString{
				Text: "CVE-2019-20477: Deserialization of Untrusted Data in PyYAML",
			},
			FullDescription: &sarif.MultiformatMessageString{
				Text:     "PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.",
				Markdown: utils.Ptr("PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342."),
			},
		}
		cve := extractCVE(rule)
		require.NotNil(t, cve)
		assert.Equal(t, "CVE-2017-18342", cve.Uid)
		require.NotNil(t, cve.Desc)
		assert.Equal(t, "PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.", *cve.Desc)
	})

	t.Run("cve in references of helm markdow - semgrep", func(t *testing.T) {
		rule := sarif.ReportingDescriptor{
			Id:   "java.lang.security.jackson-unsafe-deserialization.jackson-unsafe-deserialization",
			Name: utils.Ptr("java.lang.security.jackson-unsafe-deserialization.jackson-unsafe-deserialization"),
			ShortDescription: &sarif.MultiformatMessageString{
				Text: "Semgrep Finding: java.lang.security.jackson-unsafe-deserialization.jackson-unsafe-deserialization",
			},
			FullDescription: &sarif.MultiformatMessageString{
				Text: "When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious JSON which can be used to exploit unsecure deserialization. In order to prevent this issue, avoid to enable default typing (globally or by using \"Per-class\" annotations) and avoid using `Object` and other dangerous types for member variable declaration which creating classes for Jackson based deserialization.\n Enable cross-file analysis and Pro rules for free at sg.run/pro",
			},
			Help: &sarif.MultiformatMessageString{
				Text:     "When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious JSON which can be used to exploit unsecure deserialization. In order to prevent this issue, avoid to enable default typing (globally or by using \"Per-class\" annotations) and avoid using `Object` and other dangerous types for member variable declaration which creating classes for Jackson based deserialization.\n Enable cross-file analysis and Pro rules for free at sg.run/pro",
				Markdown: utils.Ptr("When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious JSON which can be used to exploit unsecure deserialization. In order to prevent this issue, avoid to enable default typing (globally or by using \"Per-class\" annotations) and avoid using `Object` and other dangerous types for member variable declaration which creating classes for Jackson based deserialization.\n\n#### Enable cross-file analysis and Pro rules for free at <a href='https://sg.run/pro'>sg.run/pro</a>\n\n<b>References:</b>\n - [Semgrep Rule](https://semgrep.dev/r/java.lang.security.jackson-unsafe-deserialization.jackson-unsafe-deserialization)\n - [https://swapneildash.medium.com/understanding-insecure-implementation-of-jackson-deserialization-7b3d409d2038](https://swapneildash.medium.com/understanding-insecure-implementation-of-jackson-deserialization-7b3d409d2038)\n - [https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062)\n - [https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/](https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/)\n"),
			},
		}
		cve := extractCVE(rule)
		require.NotNil(t, cve)
		assert.Equal(t, "CVE-2017-7525", cve.Uid)
		require.NotNil(t, cve.Desc)
		assert.Equal(t, "When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious JSON which can be used to exploit unsecure deserialization. In order to prevent this issue, avoid to enable default typing (globally or by using \"Per-class\" annotations) and avoid using `Object` and other dangerous types for member variable declaration which creating classes for Jackson based deserialization.\n Enable cross-file analysis and Pro rules for free at sg.run/pro", *cve.Desc)
	})
}

func TestCVERegex(t *testing.T) {
	assert.Equal(t, "CVE-1012-23456", cveRegExp.FindString("rule-id-CVE-1012-23456"))
	assert.Equal(t, "cve-1012-23456", cveRegExp.FindString("rule-id-cve-1012-23456"))
	assert.Equal(t, "CVE-1012-23456", cveRegExp.FindString("CVE-1012-23456"))
	assert.Equal(t, "cve-1012-23456", cveRegExp.FindString("cve-1012-23456"))
	assert.Equal(t, "cve-2017-7525", cveRegExp.FindString("- [https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/](https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/)"))
}
