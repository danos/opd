// Copyright (c) 2018-2020, AT&T Intellectual Property.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"bytes"
	"fmt"
	"github.com/danos/utils/patherr"
	"testing"
)

var testSchema = `opd:command show {
	opd:help "Show commands";
	opd:command interfaces {
		opd:help "Show interfaces information";

		opd:command switch {
			opd:help "Show switch info";

			opd:command detail {
				opd:help "Show detailed info";
			}

			opd:argument if-name {
				type string {
					opd:pattern-help "<swN|swN.M>";
				}
				opd:help "Show switch";
				opd:allowed "sw1 sw2";
			}
		}
	}
	opd:command ip-filter {
		opd:help "Show ip filter information";
	}
 }`

func checkHelpCompletion(
	t *testing.T,
	schema_text *bytes.Buffer,
	templates string,
	path []string,
	expects map[string]string,
) {
	srv := newTestServer(t, schema_text, "test_templates/")
	comps, err := srv.Help(path, &ucred{})
	if err != nil {
		t.Errorf("Unexpected completion failure:\n  %s\n\n", err.Error())
	}
	// Verify that the expected help text is seen
	if len(comps) != len(expects) {
		t.Errorf("Completions do not match:\n   Expected - %v\n  Got = %v\n", expects, comps)
	}

	for k, v := range expects {
		help, ok := comps[k]
		if !ok {
			t.Errorf("Expected completion not found: %s\n", k)
		} else {
			if help != v {
				t.Errorf("Help for '%s' not as expected:\n Expect - %s\n\n Actual - %s\n", k, v, help)

			}
		}
	}

}

// Verify help derived from both yang and templates works
func TestCompletionCommandHelp(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate, testSchema))

	expects := map[string]string{
		"<swN|swN.M>": "Show switch",
		"detail":      "Show detailed info",
		"sw1":         "",
		"sw2":         "",
	}

	path := []string{"show", "interfaces", "switch"}

	checkHelpCompletion(t, schema_text, "test_templates/", path, expects)
}

// Check help text for a node.tag with allowed script is correct.
func TestCompletionCommandHelpWithAllowedValues(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate, testSchema))

	expects := map[string]string{
		"dp0s3":  "Show interface information",
		"dp0s4":  "Show interface information",
		"sw2":    "Show interface information",
		"sw3":    "Show interface information",
		"switch": "Show switch info",
	}

	path := []string{"show", "interfaces"}

	checkHelpCompletion(t, schema_text, "test_templates/", path, expects)
}

// Check help text for a child of a node.tag is correct and does not include
// parents allowed script derived values.
func TestCompletionCommandHelpWithAllowedValuesChildOfNodeTag(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate, testSchema))

	expects := map[string]string{
		"<Enter>": "Execute the current command",
	}

	path := []string{"show", "interfaces", "dp0s3"}

	checkHelpCompletion(t, schema_text, "test_templates/", path, expects)

}

func checkAmbiguousError(
	t *testing.T,
	schema_text *bytes.Buffer,
	templates string,
	path []string,
	expects []string,
) {
	srv := newTestServer(t, schema_text, "test_templates/")

	_, err := srv.Expand(path, &ucred{})

	if err == nil {
		t.Errorf("Unexpected expand success\n")
		return
	}

	switch e := err.(type) {
	case *patherr.PathAmbig:
		matches := e.Matches
		for _, v := range expects {
			if _, ok := matches[v]; !ok {
				t.Errorf("Expected ambiguous value not found: %s \n\n", v)
			}
		}

	default:
		t.Errorf("Unexpected expand failure: %s\n", err.Error())
	}
}

// TestAmbiguousCompletion
// Check that an ambiguous command error message is correctly
// returned, merging operational commands present in both yang
// and templates.
func TestAmbiguousCompletion(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate, testSchema))

	checkAmbiguousError(t, schema_text, "test_templates/",
		[]string{"show", "i"},
		[]string{"interfaces", "ip-filter", "ip", "ipv6"})

	checkAmbiguousError(t, schema_text, "test_templates/",
		[]string{"show", "i", "switch"},
		[]string{"interfaces", "ip-filter", "ip", "ipv6"})

	checkAmbiguousError(t, schema_text, "test_templates/",
		[]string{"show", "i", "dp0s3"},
		[]string{"interfaces", "ip-filter", "ip", "ipv6"})
}

func checkExpandSuccess(
	t *testing.T,
	schema_text *bytes.Buffer,
	templates string,
	path []string,
	expects []string,
) {
	srv := newTestServer(t, schema_text, "test_templates/")

	exp, err := srv.Expand(path, &ucred{})

	if err != nil {
		t.Errorf("Unexpected expand failure: %s\n", err.Error())
		return
	}

	if len(expects) != len(exp) {
		t.Errorf("Unexpected expand failure\n Got: %s\n Expected %s\n",
			exp, expects)
	}

	for idx, v := range expects {
		if exp[idx] != v {
			t.Errorf("Expand failure:\n  Got %s Expected: %s\n\n", exp[idx], v)
		}
	}
}

func TestExpandSuccess(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate, testSchema))

	// Match a single node due to a complete match, even though
	// there are other prefix matches
	checkExpandSuccess(t, schema_text, "test_templates/",
		[]string{"sh", "ip"},
		[]string{"show", "ip"})

	checkExpandSuccess(t, schema_text, "test_templates/",
		[]string{"sh", "in"},
		[]string{"show", "interfaces"})

	checkExpandSuccess(t, schema_text, "test_templates/",
		[]string{"sh", "ipv"},
		[]string{"show", "ipv6"})

	checkExpandSuccess(t, schema_text, "test_templates/",
		[]string{"sh", "ip-"},
		[]string{"show", "ip-filter"})

	// Match on argument node
	checkExpandSuccess(t, schema_text, "test_templates/",
		[]string{"sh", "in", "dp0s2"},
		[]string{"show", "interfaces", "dp0s2"})

	// Match, by expansion, a non-argument node, which has
	// an alternative argument node
	checkExpandSuccess(t, schema_text, "test_templates/",
		[]string{"sh", "in", "s"},
		[]string{"show", "interfaces", "switch"})

}

func checkInvalidError(
	t *testing.T,
	schema_text *bytes.Buffer,
	templates string,
	path []string,
	failpath []string,
	failval string,
) {
	srv := newTestServer(t, schema_text, "test_templates/")

	_, err := srv.Expand(path, &ucred{})

	if err == nil {
		t.Errorf("Did not see expected invalid error")
	}

	switch e := err.(type) {
	case *patherr.CommandInval:
		if failval != e.Fail {
			t.Errorf("Unexpected fail value\n Got: %s\n Expected %s\n\n", e.Fail, failval)
		}
		if len(failpath) != len(e.Path) {
			t.Errorf("Unexpected fail path\n Got: %s\n Expected %s\n\n", e.Path, failpath)
		}

		for idx, p := range failpath {
			if p != e.Path[idx] {
				t.Errorf("Unexpected fail path element %d\n Got: %s\n Expected %s\n\n", idx, p, e.Path[idx])
			}
		}

	default:
		t.Errorf("Unexpected expand error:\n %s\n\n", err.Error())
	}
}

func TestExpandInvalid(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate, testSchema))

	// Invalid root level command
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"shows"},
		[]string{},
		"shows")

	// Invalid mid-path keyword
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"sh", "iii", "foo"},
		[]string{"show"},
		"iii")

	// Yang sourced commands
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"sh", "ip-", "foo"},
		[]string{"show", "ip-filter"},
		"foo")
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"s", "in", "s", "d", "foo"},
		[]string{"show", "interfaces", "switch", "detail"},
		"foo")
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"s", "in", "s", "sw1", "foo"},
		[]string{"show", "interfaces", "switch", "sw1"},
		"foo")

	// Template sources commands
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"show", "in", "dp0s2", "foo"},
		[]string{"show", "interfaces", "dp0s2"},
		"foo")
	checkInvalidError(t, schema_text, "test_templates/",
		[]string{"sh", "ipv", "foo"},
		[]string{"show", "ipv6"},
		"foo")
}
