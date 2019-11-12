package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"brocade.com/vyatta/cmdclient"
	"github.com/danos/opd/rpc"
)

var ty = flag.String("type", "opc", "type of test: opc, par, rest, or restPar")
var path = flag.String("path", "", "command to run")
var num = flag.Int("num", 2000, "number of iterations")
var host = flag.String("host", "", "host for rest")
var user = flag.String("user", "", "username for rest")
var pass = flag.String("pass", "", "password for rest")
var method = flag.String("method", "GET", "method for rest")
var operation = flag.String("operation", "run", "operation for par")

type chty struct {
	i      int
	res    int
	resstr string
	resmap map[string]string
	err    error
}

func opcTest(num int, path string) {
	ch := make(chan bool)
	dnull, _ := os.OpenFile("/dev/null", os.O_RDWR, 0777)
	for i := 0; i < num; i++ {
		c, e := rpc.Dial("/var/run/vyatta/opd/main.sock", false)
		if e != nil {
			fmt.Fprintf(os.Stderr, "i: %d; e: %s\n", i, e)
			return
		}
		res, e := c.Run(path, os.Environ(), 80, 24, false)
		if e != nil {
			fmt.Fprintf(os.Stderr, "i: %d; e: %s\n", i, e)
			continue
		}
		fmt.Println(res)

		pid := strconv.Itoa(res)
		go func() {
			cmdclient.Connect(pid, dnull, dnull)
			ch <- true
		}()
	}
	for i := 0; i < num; i++ {
		<-ch
	}
	fmt.Println("All done")
}

func opcSeqTest(num int, path string) {
	c, e := rpc.Dial("/var/run/vyatta/opd/main.sock", false)
	if e != nil {
		fmt.Fprintf(os.Stderr, "e: %s\n", e)
		return
	}
	for i := 0; i < num; i++ {
		res, e := c.Tmpl(path)
		if e != nil {
			fmt.Fprintf(os.Stderr, "i: %d; e: %s\n", i, e)
		}
		fmt.Println(res)
	}
}

func opcParTest(num int, path, operation string) {
	ch := make(chan *chty)
	var success int
	var fail int
	dnull, _ := os.OpenFile("/dev/null", os.O_RDWR, 0777)
	defer dnull.Close()
	for i := 0; i < num; i++ {
		go func(i int) {
			c, e := rpc.Dial("/var/run/vyatta/opd/main.sock", false)
			for e != nil {
				if nerr, ok := e.(net.Error); ok {
					if !nerr.Temporary() {
						ch <- &chty{i: i, res: -1, err: e}
						return
					}
				} else {
					ch <- &chty{i: i, res: -1, err: e}
					return
				}
				time.Sleep(10 * time.Millisecond)
				c, e = rpc.Dial("/var/run/vyatta/opd/main.sock", false)
			}
			defer c.Close()
			switch operation {
			case "run":
				res, e := c.Run(path, os.Environ(), 80, 24, false)
				if e != nil {
					ch <- &chty{i: i, res: -1, err: e}
				}
				pid := strconv.Itoa(res)

				_, e = cmdclient.Connect(pid, dnull, dnull)
				ch <- &chty{i: i, res: res, err: e}
			case "tmpl":
				res, e := c.Tmpl(path)
				ch <- &chty{i: i, resmap: res, err: e}
			}
		}(i)
	}
	for i := 0; i < num; i++ {
		var out *chty
		out = <-ch
		if out != nil {
			if out.err != nil {
				fail = fail + 1
				fmt.Fprintf(os.Stderr, "i: %d; e: %s\n", out.i, out.err)
			} else {
				success = success + 1
				fmt.Fprintf(os.Stdout, "i: %d; res: %d\n", out.i, out.res)
			}
		}
		fmt.Printf("Successes: %d, Failures: %d\n", success, fail)
	}
	fmt.Printf("DONE! Successes: %d, Failures: %d\n", success, fail)
}

func restOne(num int, host, user, pass, method, path string, ch chan<- *chty) {
	var c http.Client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c = http.Client{Transport: tr}

	authstring := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))

	urlstring := "https://" + host + path

	var e error
	var req *http.Request
	req, _ = http.NewRequest(strings.ToUpper(method), urlstring, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Vyatta-Specification-Version", "0.1")
	req.Header.Add("Authorization", "Basic "+authstring)

	res, e := c.Do(req)
	if e != nil {
		ch <- &chty{i: num, err: e}
		return
	}
	buf := &bytes.Buffer{}
	buf.ReadFrom(res.Body)
	var jbuf bytes.Buffer
	err := json.Indent(&jbuf, []byte(buf.String()), "", "    ")
	if err != nil {
		jbuf = *buf
	}
	jbuf.WriteByte('\n')
	out := fmt.Sprintf("%s", res.Header) + "\n" + jbuf.String()
	ch <- &chty{i: num, resstr: out}
}

func restTest(num int, host, user, pass, method, path string) {
	ch := make(chan *chty)
	if host == "" {
		fmt.Fprintln(os.Stderr, "No host specified")
		return
	}
	if user == "" {
		fmt.Fprintln(os.Stderr, "No user specified")
		return
	}
	if pass == "" {
		fmt.Fprintln(os.Stderr, "No password specified")
		return
	}

	for i := 0; i < num; i++ {
		go restOne(i, host, user, pass, method, path, ch)
		out := <-ch
		if out != nil {
			if out.err != nil {
				fmt.Fprintf(os.Stderr, "i: %d; e: %s\n", out.i, out.err)
			} else {
				fmt.Printf("i: %d: %s\n", out.i, out.resstr)
			}
		}
	}
}

func restParTest(num int, host, user, pass, method, path string) {
	var success int
	var fail int

	if host == "" {
		fmt.Fprintln(os.Stderr, "No host specified")
		return
	}
	if user == "" {
		fmt.Fprintln(os.Stderr, "No user specified")
		return
	}
	if pass == "" {
		fmt.Fprintln(os.Stderr, "No password specified")
		return
	}

	ch := make(chan *chty)

	for i := 0; i < num; i++ {
		go restOne(i, host, user, pass, method, path, ch)
	}
	for i := 0; i < num; i++ {
		out := <-ch
		if out != nil {
			if out.err != nil {
				fail = fail + 1
				fmt.Fprintf(os.Stderr, "i: %d; e: %s\n", out.i, out.err)
			} else {
				success = success + 1
				fmt.Printf("i: %d: %s\n", out.i, out.resstr)
			}
		}
	}
	fmt.Printf("DONE! successes: %d; failures: %d\n", success, fail)
}

func main() {
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "No path specified")
		return
	}
	switch strings.ToLower(*ty) {
	case "opc":
		opcTest(*num, *path)
	case "seq":
		opcSeqTest(*num, *path)
	case "par":
		opcParTest(*num, *path, *operation)
	case "rest":
		restTest(*num, *host, *user, *pass, *method, *path)
	case "restPar":
		restParTest(*num, *host, *user, *pass, *method, *path)
	default:
		fmt.Fprintln(os.Stderr, "Invalid test type")
	}
}
