package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/term"
)

const version = "0.4.0"

const usageText = `stash — a small secrets store for agents and scripts

Server:
  stash serve [--addr 127.0.0.1:8555] [--data DIR] [--tls-cert F --tls-key F]
  stash reset-admin [--data DIR]     make a new admin token (offline recovery)
  stash reset-password [--data DIR]  remove the owner password (offline recovery)

Secrets (need STASH_TOKEN, and STASH_ADDR if not local):
  stash set NAME [VALUE]             VALUE from stdin when omitted
  stash get NAME                     print a value (asks for the owner password)
  stash list
  stash ui                           browse, search, and edit secrets on one screen
  stash delete NAME
  stash run [--] COMMAND [ARGS...]   run a command with all secrets as env vars,
                                     secret values in its output show as ****

Owner password (need an admin STASH_TOKEN and a terminal):
  stash password set                 set or change the password that guards reads
  stash open                         list secrets any token can read without it
  stash open NAME [--data DIR]       let programs read NAME without the password
  stash close NAME [--data DIR]      lock NAME again
                                     (--data works offline, with the server stopped)

Tokens (need an admin STASH_TOKEN):
  stash token create NAME [--role proxy|ro|rw|admin]
  stash token list
  stash token revoke NAME
  stash audit [--limit N]

Proxy routes (need an admin STASH_TOKEN):
  stash route create NAME --upstream URL --secret SECRET [--header "H: p {value}"]
  stash route list
  stash route delete NAME

Other:
  stash version
`

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".stash"
	}
	return filepath.Join(home, ".stash")
}

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usageText)
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(rest)
	case "reset-admin":
		err = cmdResetAdmin(rest)
	case "set":
		err = cmdSet(rest)
	case "get":
		err = cmdGet(rest)
	case "list":
		err = cmdList(rest)
	case "delete":
		err = cmdDelete(rest)
	case "run":
		err = cmdRun(rest)
	case "password":
		err = cmdPassword(rest)
	case "ui":
		err = cmdUI(rest)
	case "open":
		err = cmdOpen(rest, true)
	case "close":
		err = cmdOpen(rest, false)
	case "reset-password":
		err = cmdResetPassword(rest)
	case "token":
		err = cmdToken(rest)
	case "route":
		err = cmdRoute(rest)
	case "audit":
		err = cmdAudit(rest)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "stash: unknown command %q\n\n", cmd)
		fmt.Print(usageText)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("stash: %v", err)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8555", "listen address")
	data := fs.String("data", defaultDataDir(), "data directory")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (optional)")
	tlsKey := fs.String("tls-key", "", "TLS key file (optional)")
	fs.Parse(args)

	st, err := OpenStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()

	admin, created, err := st.EnsureAdmin()
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("admin token (shown once, save it now): %s\n", admin)
	}
	if *tlsCert == "" || *tlsKey == "" {
		host, _, splitErr := net.SplitHostPort(*addr)
		if splitErr != nil {
			host = *addr
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			log.Printf("WARNING: plaintext HTTP on non-local address %s — tokens and secrets travel unencrypted. Bind to 127.0.0.1 or add --tls-cert and --tls-key.", *addr)
		}
	}
	log.Printf("stash %s listening on %s, data in %s", version, *addr, *data)
	mux := newMux(st)
	if *tlsCert != "" && *tlsKey != "" {
		return http.ListenAndServeTLS(*addr, *tlsCert, *tlsKey, mux)
	}
	return http.ListenAndServe(*addr, mux)
}

func cmdResetAdmin(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data directory")
	fs.Parse(args)

	st, err := OpenStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	plain, err := st.ResetAdmin()
	if err != nil {
		return err
	}
	fmt.Printf("new admin token (shown once, save it now): %s\n", plain)
	return nil
}

func cmdSet(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: stash set NAME [VALUE]")
	}
	name := args[0]
	var value string
	if len(args) == 2 {
		value = args[1]
	} else {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		value = strings.TrimSuffix(string(b), "\n")
	}
	c := newClient()
	return c.do("PUT", "/v1/secrets/"+name, map[string]string{"value": value}, nil)
}

// readPassword prompts on the terminal without echo. It refuses when stdin
// is not a terminal, so a script or agent cannot pipe a password in.
func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("this needs the owner password, typed at a terminal. Agents: use `stash run` or a proxy route instead")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func cmdGet(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: stash get NAME")
	}
	c := newClient()
	var out struct {
		Value string `json:"value"`
	}
	err := c.do("GET", "/v1/secrets/"+args[0], nil, &out)
	if isPasswordErr(err) {
		if c.password, err = readPassword("owner password: "); err != nil {
			return err
		}
		err = c.do("GET", "/v1/secrets/"+args[0], nil, &out)
	}
	if err != nil {
		return err
	}
	fmt.Println(out.Value)
	return nil
}

func cmdList(args []string) error {
	c := newClient()
	var out struct {
		Secrets []string `json:"secrets"`
	}
	if err := c.do("GET", "/v1/secrets", nil, &out); err != nil {
		return err
	}
	for _, n := range out.Secrets {
		fmt.Println(n)
	}
	return nil
}

func cmdDelete(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: stash delete NAME")
	}
	c := newClient()
	return c.do("DELETE", "/v1/secrets/"+args[0], nil, nil)
}

var envUnsafe = regexp.MustCompile(`[^A-Z0-9_]`)

// envName turns a secret name into a safe env var name:
// "openai.key" -> "OPENAI_KEY".
func envName(name string) string {
	return envUnsafe.ReplaceAllString(strings.ToUpper(name), "_")
}

func cmdPassword(args []string) error {
	if len(args) != 1 || args[0] != "set" {
		return errors.New("usage: stash password set")
	}
	c := newClient()
	var status struct {
		Set bool `json:"set"`
	}
	if err := c.do("GET", "/v1/password", nil, &status); err != nil {
		return err
	}
	var old string
	if status.Set {
		var err error
		if old, err = readPassword("current owner password: "); err != nil {
			return err
		}
	}
	pw, err := readPassword("new owner password: ")
	if err != nil {
		return err
	}
	again, err := readPassword("new owner password again: ")
	if err != nil {
		return err
	}
	if pw != again {
		return errors.New("the two passwords do not match")
	}
	c.password = old
	return c.do("PUT", "/v1/password", map[string]string{"password": pw}, nil)
}

func cmdOpen(args []string, open bool) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	data := fs.String("data", "", "data directory, to change it offline")
	var name string
	var flags []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") && len(flags)%2 == 0 {
			name = a
			continue
		}
		flags = append(flags, a)
	}
	fs.Parse(flags)
	if name == "" {
		if !open {
			return errors.New("usage: stash close NAME [--data DIR]")
		}
		var out struct {
			Open []string `json:"open"`
		}
		if err := newClient().do("GET", "/v1/open", nil, &out); err != nil {
			return err
		}
		for _, n := range out.Open {
			fmt.Println(n)
		}
		return nil
	}
	if *data != "" {
		st, err := OpenStore(*data)
		if err != nil {
			return err
		}
		defer st.Close()
		return st.SetOpen(name, open)
	}
	c := newClient()
	method := "PUT"
	if !open {
		method = "DELETE"
	}
	err := c.do(method, "/v1/open/"+name, nil, nil)
	if isPasswordErr(err) {
		if c.password, err = readPassword("owner password: "); err != nil {
			return err
		}
		err = c.do(method, "/v1/open/"+name, nil, nil)
	}
	return err
}

func cmdResetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data directory")
	fs.Parse(args)

	st, err := OpenStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.ClearPassword(); err != nil {
		return err
	}
	fmt.Println("owner password removed. Run `stash password set` to make a new one.")
	return nil
}

func cmdToken(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: stash token create|list|revoke")
	}
	sub, rest := args[0], args[1:]
	c := newClient()
	switch sub {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		role := fs.String("role", "rw", "token role: proxy, ro, rw, or admin")
		// allow "stash token create NAME --role ro" and "--role ro NAME"
		var name string
		var flags []string
		for _, a := range rest {
			if name == "" && !strings.HasPrefix(a, "-") && len(flags) == 0 {
				name = a
				continue
			}
			flags = append(flags, a)
		}
		fs.Parse(flags)
		if name == "" && fs.NArg() > 0 {
			name = fs.Arg(0)
		}
		if name == "" {
			return errors.New("usage: stash token create NAME [--role proxy|ro|rw|admin]")
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := c.do("POST", "/v1/tokens", map[string]string{"name": name, "role": *role}, &out); err != nil {
			return err
		}
		fmt.Println(out.Token)
		return nil
	case "list":
		var out struct {
			Tokens []Token `json:"tokens"`
		}
		if err := c.do("GET", "/v1/tokens", nil, &out); err != nil {
			return err
		}
		for _, t := range out.Tokens {
			fmt.Printf("%s\t%s\t%s\n", t.Name, t.Role, t.Created.Format("2006-01-02 15:04"))
		}
		return nil
	case "revoke":
		if len(rest) != 1 {
			return errors.New("usage: stash token revoke NAME")
		}
		return c.do("DELETE", "/v1/tokens/"+rest[0], nil, nil)
	default:
		return fmt.Errorf("unknown token command %q", sub)
	}
}

func cmdRoute(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: stash route create|list|delete")
	}
	sub, rest := args[0], args[1:]
	c := newClient()
	switch sub {
	case "create":
		if len(rest) < 1 || strings.HasPrefix(rest[0], "-") {
			return errors.New(`usage: stash route create NAME --upstream URL --secret SECRET [--header "H: p {value}"]`)
		}
		name := rest[0]
		fs := flag.NewFlagSet("route create", flag.ExitOnError)
		upstream := fs.String("upstream", "", "upstream base URL, like https://api.openai.com")
		secret := fs.String("secret", "", "name of the secret to inject")
		header := fs.String("header", "", `header template, default "Authorization: Bearer {value}"`)
		fs.Parse(rest[1:])
		if *upstream == "" || *secret == "" {
			return errors.New("--upstream and --secret are required")
		}
		return c.do("POST", "/v1/routes", Route{Name: name, Upstream: *upstream, Secret: *secret, Header: *header}, nil)
	case "list":
		var out struct {
			Routes []Route `json:"routes"`
		}
		if err := c.do("GET", "/v1/routes", nil, &out); err != nil {
			return err
		}
		for _, r := range out.Routes {
			fmt.Printf("%s\t%s\t%s\n", r.Name, r.Upstream, r.Secret)
		}
		return nil
	case "delete":
		if len(rest) != 1 {
			return errors.New("usage: stash route delete NAME")
		}
		return c.do("DELETE", "/v1/routes/"+rest[0], nil, nil)
	default:
		return fmt.Errorf("unknown route command %q", sub)
	}
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	limit := fs.Int("limit", 100, "max entries")
	fs.Parse(args)
	c := newClient()
	var out struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := c.do("GET", fmt.Sprintf("/v1/audit?limit=%d", *limit), nil, &out); err != nil {
		return err
	}
	for _, e := range out.Entries {
		fmt.Printf("%s\t%s\t%s\t%s\n", e.Time.Format("2006-01-02 15:04:05"), e.Token, e.Action, e.Secret)
	}
	return nil
}
