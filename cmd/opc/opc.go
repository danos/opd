// Copyright (c) 2017-2019, AT&T Intellectual Property.
// All rights reserved.
//
// Copyright (c) 2013-2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
Opc is the command line interface to opd operational commands.
It provides all functions needed to implement the Vyatta CLI.

Usage:
	opc [ options ] path
	Options:
	-op=[run|complete|help|expand|tmpl|children|allowed|field|getperms]
		Default: run
		The op flag is the operation to request from opd.
		More details are described below for each operation.

		run: The run operation requests opd run the supplied command
			path.  If the user is allowed to run this command by the
			authorization service, the command will be executed by opd
			and opc will then connect to the sockets attached to that
			exec'd processes pty.

		complete: The complete operation returns a list of possible
			next completions for the supplied path. When used in
			conjunction with the -prefix flag,only the completions
			matching the supplied prefix are printed. This is used by
			the bash completion scripts implementing the Vyatta CLI.

		help: The help operation returns a the pretty printed help
			text for the supplied path.  When used in conjunction with
			the -prefix flag, only the completions matching the
			supplied prefix are shown. This is used by the bash
			completion scripts implmenting the Vyatta CLI.

		expand: The expand operation returns a fully expanded Vyatta
			command path. Paths in the Vyatta CLI may be abbreviated
			such that the shortest un-ambiguous match is accepted as a
			valid command. Expand will return the fully qualified path
			when given an un-ambiguous path, or an error string when
			given an ambiguous path.

		tmpl: The tmpl operation returns a text representation of the
			operational template at the supplied path. This template
			is a pretty printed form of the templates present in the
			template tree.

		children: The children operation returns a list of children
			for the given path.

		allowed: The allowed operation returns a list allowed values
			for the given tag node. If the allowed operation is called
			on a non tag node then it will report an error.

		field: The field operation returns a single field value from a
			template. This is a helper function implemented using the
			tmpl operation. Field requires that the -field flag be
			defined.

		getperms: The getperms operation returns a subset of the
			operational mode ruleset that affects the current user.

	-field=<field> The field flag defines the field to extract from a
		template.

	-prefix=<prefix> The prefix flag is the prefix to filter for the
		help and complete operations.

	-debug Default: false The debug flag enables RPC request/response
		debugging.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/danos/utils/natsort"

	opdclient "github.com/danos/opd/client"
	"github.com/danos/opd/pty"
)

var op string
var field string
var prefix string
var debug bool

func init() {
	flag.StringVar(&op, "op", "run", "Operation to be preformed")
	flag.StringVar(&field, "field", "", "Field to retrieve")
	flag.StringVar(&prefix, "prefix", "", "Current prefix to filter")
	flag.BoolVar(&debug, "debug", false, "Debug RPC")
}

type argData struct {
	Args []string `json:"args"`
}

type tmplmap map[string]string

func (t tmplmap) String() string {
	var outs string
	for k, v := range t {
		outs += fmt.Sprintf("%s: %s\n", k, v)
	}
	return outs
}

func argsToPath(args []string) string {
	escapedArgs := make([]string, len(args))
	for i, v := range args {
		escapedArgs[i] = url.QueryEscape(v)
	}
	s := strings.Join(escapedArgs, "/")
	s = "/" + s
	return s
}

func getOpdPty() bool {
	ptyStr := os.Getenv("OPD_PTY")
	if ptyStr == "" {
		return true //if not set then treat initial as pty
	}
	ispty, err := strconv.ParseBool(ptyStr)
	if err != nil {
		return true
	}
	return ispty
}

func buildArgsEnv(c *opdclient.Client, path string) (string, error) {
	args, err := c.Expand(path)
	if err != nil {
		return "", err
	}

	encArgs, err := json.Marshal(&argData{args})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", encArgs), err
}

func Run(c *opdclient.Client, argv []string) (int, error) {
	var err error
	var infile io.Reader
	paths := argsToPath(argv)
	opdispty := getOpdPty()
	inisatty := pty.IsTerminal(os.Stdin)
	outisatty := pty.IsTerminal(os.Stdout)
	isforeground := pty.IsForeground(os.Stdout)
	if opdispty && outisatty && isforeground {
		st, err := pty.MakeRaw(os.Stdout)
		if err != nil {
			return 1, err
		}
		/*restore terminal on return*/
		defer pty.Restore(os.Stdout, st)
	}
	if opdispty && inisatty && isforeground {
		stin, err := pty.MakeRaw(os.Stdin)
		if err != nil {
			return 1, err
		}
		/*restore terminal on return*/
		defer pty.Restore(os.Stdin, stin)
	}
	infile = os.Stdin
	if !isforeground {
		infile = nil
	}
	osenv := os.Environ()
	env := make([]string, 0, len(osenv))
	for _, v := range osenv {
		ev := strings.Split(v, "=")
		if len(ev) < 2 {
			continue
		}
		switch ev[0] {
		case "LS_COLORS":
			continue
		case "OPC_ARGS":
			/*
			 * Depending upon how opc was called OPC_ARGS may or may not
			 * be present in the environment. For consistency we therefore
			 * ignore any existing value and always build our own OPC_ARGS
			 * from argv - note the call to buildArgsEnv() below.
			 */
			continue
		}
		env = append(env, v)
	}

	aenv, err := buildArgsEnv(c, paths)
	if err != nil {
		return 1, err
	}
	env = append(env, "OPC_ARGS="+aenv)

	ec, err := c.Run(paths, env, (opdispty && outisatty), infile, os.Stdout)
	if err != nil {
		return ec, err
	}

	return ec, nil
}

func RunFromEnv(c *opdclient.Client) (int, error) {
	return Run(c, getArgsFromEnv())
}

func getArgsFromEnv() []string {
	var args argData
	dec := json.NewDecoder(strings.NewReader(os.Getenv("OPC_ARGS")))
	err := dec.Decode(&args)
	if err != nil {
		return []string{}
	}
	return args.Args
}

func Complete(c *opdclient.Client, argv []string) error {
	var result []string
	var err error
	var outs string
	var comps = make([]string, 0)
	var non_comps = make([]string, 0)

	paths := argsToPath(argv)
	result, err = c.Complete(paths)
	if err != nil {
		return err
	}

	var re *regexp.Regexp = regexp.MustCompile("<.*>")
	for _, item := range result {
		if re.MatchString(item) {
			non_comps = append(non_comps, item)
		} else {
			if strings.HasPrefix(item, prefix) {
				comps = append(comps, item)
			}
		}
	}

	natsort.Sort(comps)
	natsort.Sort(non_comps)
	if prefix != "" && len(comps) == 0 && len(non_comps) < 2 {
		path := append(argv, prefix)
		paths := argsToPath(path)
		_, err := c.Expand(paths)
		if err != nil {
			return err
		}
	}

	outs = fmt.Sprintf("_vyatta_op_completions=( ")
	for _, item := range comps {
		outs += "'" + item + "' "
	}
	outs += fmt.Sprintf("); _vyatta_op_noncompletions=( ")
	for _, item := range non_comps {
		if prefix != "" && item == "<Enter>" {
			continue
		}
		outs += "'" + item + "' "
	}
	outs += ");"

	fmt.Printf("%s", outs)

	return nil
}

func CompleteFromEnv(c *opdclient.Client) error {
	return Complete(c, getArgsFromEnv())
}

func Help(c *opdclient.Client, argv []string) error {
	var result map[string]string
	var err error
	const indent = 2
	const gap = 2
	const minOptionWidth = 10

	paths := argsToPath(argv)
	result, err = c.Help(paths)
	if err != nil {
		return err
	}

	var keys []string
	for k, _ := range result {
		keys = append(keys, k)
	}

	natsort.Sort(keys)

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, minOptionWidth+indent, 8, gap, ' ', 0)

	fmt.Fprintf(w, "%s", "\nPossible completions:\n")
	for _, v := range keys {
		if !strings.HasPrefix(v, prefix) {
			continue
		}
		fmt.Fprintf(w, "%*s%s\t%s\n", indent, " ", v, result[v])
	}
	w.Flush()

	return nil
}

func HelpFromEnv(c *opdclient.Client) error {
	return Help(c, getArgsFromEnv())
}

func HelpForField(c *opdclient.Client, argv []string) error {
	var result map[string]string
	var err error

	paths := argsToPath(argv)
	result, err = c.Help(paths)
	if err != nil {
		return err
	}

	if result[field] != "" {
		fmt.Fprintf(os.Stdout, "%s (%s)", field, result[field])
	} else {
		fmt.Fprintf(os.Stdout, "%s", field)
	}

	return nil
}

func Expand(c *opdclient.Client, argv []string) error {
	var result []string
	var err error

	paths := argsToPath(argv)
	result, err = c.Expand(paths)
	if err != nil {
		return err
	}

	var buf string
	for i, v := range result {
		if strings.Index(v, " ") > 0 {
			v = "\"" + v + "\""
		}
		if i == 0 {
			buf = fmt.Sprintf("%s", v)
		} else {
			buf = fmt.Sprintf("%s %s", buf, v)
		}
	}
	fmt.Printf("%s\n", buf)

	return nil
}

func ExpandFromEnv(c *opdclient.Client) error {
	return Expand(c, getArgsFromEnv())
}

func Tmpl(c *opdclient.Client, argv []string) error {
	var result tmplmap
	var err error

	paths := argsToPath(argv)
	result, err = c.Tmpl(paths)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", result)

	return nil
}

func Children(c *opdclient.Client, argv []string) error {
	var result []string
	var err error

	paths := argsToPath(argv)
	result, err = c.Children(paths)
	if err != nil {
		return err
	}
	natsort.Sort(result)
	for _, v := range result {
		fmt.Printf("%s ", v)
	}
	fmt.Printf("\n")
	return nil
}

func Allowed(c *opdclient.Client, argv []string) error {
	var result []string
	var err error

	paths := argsToPath(argv)
	result, err = c.Allowed(paths)
	if err != nil {
		return err
	}
	for _, v := range result {
		fmt.Printf("%s ", v)
	}
	fmt.Printf("\n")
	return nil
}

func Field(c *opdclient.Client, argv []string) error {
	var result tmplmap
	var err error

	if field == "" {
		return fmt.Errorf("Required argument 'field' does not exist")
	}

	paths := argsToPath(argv)
	result, err = c.Tmpl(paths)
	if err != nil {
		return err
	}

	if f, ok := result[field]; ok {
		fmt.Printf("%s\n", f)
	}

	return nil

}

func FieldFromEnv(c *opdclient.Client) error {
	return Field(c, getArgsFromEnv())
}

func GetPerms(c *opdclient.Client, argv []string) error {
	var result map[string]string
	var err error
	result, err = c.GetPerms()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", result)
	return nil
}

func main() {
	var c *opdclient.Client
	var err error
	var exit int

	/*Parse command line flags*/
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  opc [ flags ] path\n")
		fmt.Fprintf(os.Stderr, "    -op=[run|complete|help|expand|tmpl|children|allowed|field|getperms|run-from-env]\n")
		fmt.Fprintf(os.Stderr, "    -debug\n")
		fmt.Fprintf(os.Stderr, "    -field=<field>\n")
		fmt.Fprintf(os.Stderr, "    -prefix=<prefix>\n")
		fmt.Fprintf(os.Stderr, "Flag description and default values:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if prefix == "" {
		prefix = os.Getenv("OPC_PREFIX")
	}

	if field == "" {
		field = os.Getenv("OPC_FIELD")
	}

	/*Setup exit handling magic so defers will be run*/
	defer func() { os.Exit(exit) }()

	/*Connect to opd*/
	c, err = opdclient.Dial("/var/run/vyatta/opd/main.sock", debug)
	defer c.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		exit = 1
		return
	}

	if debug {
		fmt.Printf("op: %s\n", op)
	}

	var comp_context bool
	switch op {
	case "run":
		exit, err = Run(c, flag.Args())
	case "run-from-env":
		exit, err = RunFromEnv(c)
	case "complete":
		comp_context = true
		err = Complete(c, flag.Args())
	case "complete-from-env":
		comp_context = true
		err = CompleteFromEnv(c)
	case "help":
		comp_context = true
		err = Help(c, flag.Args())
	case "help-from-env":
		comp_context = true
		err = HelpFromEnv(c)
	case "helpforfield":
		comp_context = true
		err = HelpForField(c, flag.Args())
	case "expand":
		comp_context = true
		err = Expand(c, flag.Args())
	case "expand-from-env":
		comp_context = true
		err = ExpandFromEnv(c)
	case "tmpl":
		err = Tmpl(c, flag.Args())
	case "children":
		err = Children(c, flag.Args())
	case "allowed":
		err = Allowed(c, flag.Args())
	case "field":
		err = Field(c, flag.Args())
	case "field-from-env":
		err = FieldFromEnv(c)
	case "getperms":
		err = GetPerms(c, flag.Args())
	default:
		err = fmt.Errorf("Invalid operation: %s", op)
	}

	if err != nil {
		if err == io.EOF {
			exit = 1
			return
		}
		if comp_context {
			fmt.Fprintf(os.Stderr, "\n")
		}
		fmt.Fprintf(os.Stderr, "\n  %s", err)
		if !comp_context {
			fmt.Fprintf(os.Stderr, "\n\n")
		}
		exit = 1
		return
	}
}
