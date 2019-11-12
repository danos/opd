// Copyright (c) 2018-2019, AT&T Intellectual Property.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/danos/config/schema"
	"github.com/danos/op/tmpl/tree"
	"github.com/danos/op/yang"
	"github.com/danos/utils/pathutil"
	"github.com/danos/yang/compile"
	"github.com/danos/yang/parse"
)

// Schema Template with '%s' at end for insertion of schema for each test.
const schemaTemplate = `
module test-configd-compile {
        namespace "urn:vyatta.com:test:configd-compile";
        prefix test;
        organization "Brocade Communications Systems, Inc.";
        revision 2014-12-29 {
                description "Test schema for configd";
        }
        %s
}
`

func getTestYang(bufs ...[]byte) (*yang.Yang, error) {
	const name = "schema"
	modules := make(map[string]*parse.Tree)
	for index, b := range bufs {
		t, err := schema.Parse(name+strconv.Itoa(index), string(b))
		if err != nil {
			return nil, err
		}
		mod := t.Root.Argument().String()
		modules[mod] = t
	}
	st, err := schema.CompileModules(modules, "", false, compile.IsOpd, &schema.CompilationExtensions{})
	return yang.NewTestYang(st), err

}

func newTestServer(
	t *testing.T,
	schema_text *bytes.Buffer,
	templates string,
) *Server {

	//Compile the test yang
	if schema_text == nil {
		schema_text = bytes.NewBufferString(fmt.Sprintf(schemaTemplate, ""))
	}

	y, err := getTestYang(schema_text.Bytes())

	if err != nil {
		t.Errorf("Error initialising yang schema:\n  %s\n\n", err.Error())
	}

	// Build the test templates
	tmpltree, err := tree.BuildOpTree(templates)
	if err != nil {
		t.Errorf("Error initialising templates:\n  %s\n\n", err.Error())
	}

	// Set up autheriser, to allow everything, for testing purposes
	achan := make(chan *Auth)
	pchan := make(chan *PermReq)
	acctChan := make(chan *AcctReq)
	asig := make(chan os.Signal)

	go auth("", achan, pchan, acctChan, asig, false)
	srv := NewServer(nil, tmpltree, y, achan, pchan, acctChan, false)

	// Prevent allowed script execution, the contents of the scripts is
	// the allowed values
	srv.testallowed = true

	return srv
}

func checkPathAttrsSecrets(t *testing.T, attrs *pathutil.PathAttrs, secret_elems []bool) {
	for i, v := range attrs.Attrs {
		if v.Secret != secret_elems[i] {
			t.Fatalf("PathElementAttrs Secret mismatch at index %v: expected %v, got %v",
				i, secret_elems[i], v.Secret)
		}
	}
}

func TestAttrsForPathTmpl(t *testing.T) {
	path := []string{"add", "system", "image", "foo", "username", "bar", "password", "baz"}
	secret_elems := []bool{false, false, false, false, false, false, false, true}
	srv := newTestServer(t, nil, "test_templates/")

	checkPathAttrsSecrets(t, srv.AttrsForPath(path), secret_elems)
}

func TestAttrsForPathYang(t *testing.T) {
	schema_text := bytes.NewBufferString(fmt.Sprintf(
		schemaTemplate,
		`opd:command add {
			opd:command system {
				opd:command image {
					opd:argument uri {
						type string;

						opd:command username {
							opd:argument user {
								type string;

								opd:option password {
									type string;
									opd:secret "true";
								}
							}
						}
					}
				}
			}
		 }`))

	path := []string{"add", "system", "image", "foo", "username", "bar", "password", "baz"}
	secret_elems := []bool{false, false, false, false, false, false, false, true}
	srv := newTestServer(t, schema_text, "test_templates/show")

	checkPathAttrsSecrets(t, srv.AttrsForPath(path), secret_elems)
}
