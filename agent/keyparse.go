package main

import (
	"errors"
	"regexp"
	"strings"
)

// The Windows recovery-key script prints one line: "KSKEY {protector-id} 123456-...-123456".
// Anything else in the output (PowerShell warnings, notices) is ignored.
var keyLineRE = regexp.MustCompile(`KSKEY (\{[0-9A-Fa-f-]{36}\}) (\d{6}(?:-\d{6}){7})\b`)

func parseKeyLine(out string) (string, string, error) {
	m := keyLineRE.FindStringSubmatch(out)
	if m == nil {
		return "", "", errors.New("could not read a valid recovery password from BitLocker")
	}
	return strings.ToUpper(m[1]), m[2], nil
}
