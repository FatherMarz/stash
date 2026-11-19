package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/term"
)

// Legacy tokens are removed without changing secrets, passwords, or routes.
func (s *Store) removeLegacyTokens() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// 0.5 has no open secrets. Clear the old list.
		if err := tx.DeleteBucket(bucketOpen); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		if _, err := tx.CreateBucket(bucketOpen); err != nil {
			return err
		}
		bucket := tx.Bucket(bucketTokens)
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var token Token
			if err := json.Unmarshal(value, &token); err != nil {
				return err
			}
			if token.Role != "owner" && token.Role != "agent" {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func cmdSetup(args []string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("run stash setup in your own terminal; the owner password must not enter logs or chat")
	}
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	data := flags.String("data", defaultDataDir(), "data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	st, err := OpenStore(*data)
	if err != nil {
		return fmt.Errorf("stop the stash server before setup: %w", err)
	}
	defer st.Close()
	if err := st.removeLegacyTokens(); err != nil {
		return err
	}
	if _, err := oneToken(st, *data); err != nil {
		return err
	}
	if err := revokeOwnerTokens(st); err != nil {
		return err
	}
	has, err := st.HasPassword()
	if err != nil {
		return err
	}
	if !has {
		fmt.Println("Choose the owner password. Every owner action asks for it. Keep it out of chat and files.")
		if err := askNewPassword(st); err != nil {
			return err
		}
	}
	rc, cleaned, err := writeShellLine(*data)
	if err != nil {
		return err
	}
	moved := moveAWSProfiles(st)
	if err := printPaths(st, moved); err != nil {
		return err
	}
	fmt.Printf("\nYour stash token is in %s.\n", tokenFile(*data))
	for _, f := range cleaned {
		fmt.Printf("Removed an old STASH_TOKEN line from %s.\n", f)
	}
	if rc != "" {
		fmt.Printf("%s loads it in every new terminal.\n", rc)
	}
	fmt.Println("Agents need nothing else. Owner actions ask for your owner password.")
	fmt.Println("Start stash again to finish.")
	return nil
}

// oneToken keeps the token that setup wrote before, or makes a new one, and
// writes it to the token file.
func oneToken(st *Store, dir string) (string, error) {
	token := readTokenFile(dir)
	if tok, err := st.VerifyToken(token); err != nil || tok.Role != "agent" {
		name := "default-" + time.Now().UTC().Format("20060102-150405")
		if token, err = st.NewToken(name, "agent"); err != nil {
			return "", err
		}
	}
	temp, err := os.CreateTemp(dir, ".token-")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.WriteString(token + "\n"); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temp.Name(), tokenFile(dir)); err != nil {
		return "", err
	}
	os.Remove(filepath.Join(dir, "agent.token"))
	return token, nil
}

// revokeOwnerTokens ends every owner token. The owner password replaces them.
func revokeOwnerTokens(st *Store) error {
	tokens, err := st.ListTokens()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Role == "owner" {
			if err := st.RevokeToken(t.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func askNewPassword(st *Store) error {
	for {
		pw, err := readPassword("owner password: ")
		if err != nil {
			return err
		}
		again, err := readPassword("owner password again: ")
		if err != nil {
			return err
		}
		if pw != again {
			fmt.Println("The two passwords do not match. Try again.")
			continue
		}
		if err := st.SetPassword("", pw); err != nil {
			fmt.Println(err)
			continue
		}
		return nil
	}
}

const shellMark = "# stash token"

// writeShellLine puts one line in the shell start file that loads the token
// file into STASH_TOKEN. Older lines that export a token value are commented
// out, so they cannot win over the file.
func writeShellLine(dir string) (string, []string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil, err
	}
	path := tokenFile(dir)
	if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
		path = "$HOME/" + rel
	}
	line := fmt.Sprintf(`export STASH_TOKEN="$(cat "%s" 2>/dev/null)"  %s`, path, shellMark)
	var rc string
	switch filepath.Base(os.Getenv("SHELL")) {
	case "zsh":
		rc = filepath.Join(home, ".zshrc")
	case "bash":
		rc = filepath.Join(home, ".bashrc")
	}
	var cleaned []string
	for _, name := range []string{".zshenv", ".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"} {
		f := filepath.Join(home, name)
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		changed := false
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "export STASH_TOKEN=") && !strings.Contains(t, shellMark) {
				lines[i] = "# old stash token, removed by stash setup"
				changed = true
			}
		}
		if changed {
			if err := writeKeepMode(f, strings.Join(lines, "\n")); err != nil {
				return "", nil, err
			}
			cleaned = append(cleaned, f)
		}
	}
	if rc == "" {
		fmt.Printf("Add this line to your shell start file:\n  %s\n", line)
		return "", cleaned, nil
	}
	data, _ := os.ReadFile(rc)
	if strings.Contains(string(data), shellMark) {
		return rc, cleaned, nil
	}
	text := string(data)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return rc, cleaned, writeKeepMode(rc, text+line+"\n")
}

func writeKeepMode(path, text string) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(path, []byte(text), mode)
}

// moveAWSProfiles turns every AWS profile that read its keys with stash get
// into an AWS connection. The key pair then never leaves stash.
func moveAWSProfiles(st *Store) []string {
	addr := os.Getenv("STASH_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8555"
	}
	var moved []string
	for _, p := range awsProfilesUsingStash(awsConfigPath()) {
		if _, err := st.Get(p.KeyID); err != nil {
			continue
		}
		if _, err := st.Get(p.Secret); err != nil {
			continue
		}
		if err := st.SetRoute(Route{Name: p.Profile, Kind: "aws", KeyID: p.KeyID, Secret: p.Secret}); err != nil {
			fmt.Printf("AWS profile %s: %v\n", p.Profile, err)
			continue
		}
		if err := writeAWSProfile(awsConfigPath(), p.Profile, addr); err != nil {
			fmt.Printf("AWS profile %s: %v\n", p.Profile, err)
			continue
		}
		moved = append(moved, p.Profile)
	}
	return moved
}

func printPaths(st *Store, moved []string) error {
	names, err := st.List()
	if err != nil {
		return err
	}
	routes, err := st.ListRoutes()
	if err != nil {
		return err
	}
	paths := secretPaths(names, routes)
	count := map[string][]string{}
	for _, name := range names {
		count[paths[name]] = append(count[paths[name]], name)
	}
	fmt.Printf("\n%d secrets sorted:\n", len(names))
	fmt.Printf("  proxy   %3d  the program never holds the key (API keys and AWS keys)\n", len(count["proxy"]))
	fmt.Printf("  direct  %3d  owner-approved real values; captured output is masked\n", len(count["direct"]))
	fmt.Printf("  blocked %3d  no path yet; nothing can use them\n", len(count["blocked"]))
	for _, profile := range moved {
		fmt.Printf("AWS profile %s now goes through stash.\n", profile)
	}
	fmt.Println("To give a blocked secret its path, open stash ui, select it, and press p.")
	fmt.Println("Agents must select each run's secrets: stash run --secret NAME -- COMMAND.")
	return nil
}
