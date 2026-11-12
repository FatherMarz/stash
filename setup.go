package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		return errors.New("run stash setup in your own terminal; owner tokens must not enter logs or chat")
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
	owner, created, err := st.EnsureOwner()
	if err != nil {
		return err
	}
	if !created {
		return errors.New("setup is already complete; use your owner token to create an agent token")
	}
	agentName := "default-agent-" + time.Now().UTC().Format("20060102-150405.000000000")
	agent, err := st.NewToken(agentName, "agent")
	if err != nil {
		st.RevokeToken("owner")
		return err
	}
	target := filepath.Join(*data, "agent.token")
	temp, err := os.CreateTemp(*data, ".agent-token-")
	if err != nil {
		st.RevokeToken(agentName)
		st.RevokeToken("owner")
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err = temp.WriteString(agent + "\n"); err == nil {
		err = temp.Close()
	} else {
		temp.Close()
	}
	if err == nil {
		err = os.Rename(tempPath, target)
	}
	if err != nil {
		st.RevokeToken(agentName)
		st.RevokeToken("owner")
		return err
	}
	moved := moveAWSProfiles(st)
	if err := printPaths(st, moved); err != nil {
		return err
	}
	fmt.Printf("\nOwner token (save it in your password manager, never in a shell file): %s\n", owner)
	fmt.Println("Agents need nothing. They use stash run, and stash finds its own agent token.")
	fmt.Println("Start stash again to finish.")
	return nil
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
	fmt.Printf("  direct  %3d  the program gets the value, printed as ****\n", len(count["direct"]))
	for _, profile := range moved {
		fmt.Printf("AWS profile %s now goes through stash.\n", profile)
	}
	fmt.Println("Run stash list to see each secret's path.")
	return nil
}
