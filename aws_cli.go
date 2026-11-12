package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func cmdAWS(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: stash aws connect PROFILE --key-id SECRET --secret-key SECRET | stash aws creds PROFILE")
	}
	switch args[0] {
	case "connect":
		return cmdAWSConnect(args[1:])
	case "creds":
		return cmdAWSCreds(args[1:])
	}
	return fmt.Errorf("unknown aws command %q", args[0])
}

// cmdAWSConnect stores an AWS connection and points the AWS profile at it.
func cmdAWSConnect(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: stash aws connect PROFILE --key-id SECRET --secret-key SECRET")
	}
	profile := args[0]
	fs := flag.NewFlagSet("aws connect", flag.ContinueOnError)
	keyID := fs.String("key-id", "", "secret that holds the access key ID")
	secret := fs.String("secret-key", "", "secret that holds the secret access key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *keyID == "" || *secret == "" {
		return errors.New("--key-id and --secret-key name the two secrets that hold the AWS key pair")
	}
	c := newClient()
	if err := c.do("POST", "/v1/routes", Route{Name: profile, Kind: "aws", KeyID: *keyID, Secret: *secret}, nil); err != nil {
		return err
	}
	if err := writeAWSProfile(awsConfigPath(), profile, c.addr); err != nil {
		return err
	}
	fmt.Printf("AWS profile %s now sends its calls through stash. The key pair stays in stash.\n", profile)
	return nil
}

// cmdAWSCreds is the profile's credential_process. It prints a placeholder
// key and a one-hour run token. The real key pair never leaves stash.
func cmdAWSCreds(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: stash aws creds PROFILE")
	}
	var out struct {
		Token   string `json:"token"`
		Expires string `json:"expires"`
	}
	if err := newClient().do("POST", "/v1/aws/"+args[0], map[string]string{}, &out); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"Version":         1,
		"AccessKeyId":     "STASHPROXY",
		"SecretAccessKey": "stash-signs-this-call",
		"SessionToken":    out.Token,
		"Expiration":      out.Expires,
	})
}

func awsConfigPath() string {
	if path := os.Getenv("AWS_CONFIG_FILE"); path != "" {
		return path
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aws", "config")
}

var awsManagedKey = regexp.MustCompile(`^\s*(credential_process|endpoint_url|request_checksum_calculation|s3)\s*=`)

// writeAWSProfile sets the stash lines in one profile and keeps the rest,
// like region and output.
func writeAWSProfile(path, profile, addr string) error {
	stashPath, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(stashPath); err == nil {
		stashPath = resolved
	}
	header := "[profile " + profile + "]"
	if profile == "default" {
		header = "[default]"
	}
	managed := []string{
		"credential_process = " + stashPath + " aws creds " + profile,
		"endpoint_url = " + strings.TrimRight(addr, "/") + "/aws/" + profile,
		"request_checksum_calculation = when_required",
		"s3 =",
		"    addressing_style = path",
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(data) == 0 {
		lines = nil
	}
	var out []string
	found, inside, skipNested := false, false, false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inside = trimmed == header
			skipNested = false
			out = append(out, line)
			if inside {
				found = true
				out = append(out, managed...)
			}
			continue
		}
		if inside {
			if skipNested && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && trimmed != "" {
				continue
			}
			skipNested = false
			if awsManagedKey.MatchString(line) {
				skipNested = strings.HasPrefix(trimmed, "s3")
				continue
			}
		}
		out = append(out, line)
	}
	if !found {
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, header)
		out = append(out, managed...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".stash-tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// awsProfilesUsingStash finds profiles whose credential_process script reads
// a key pair with stash get. Setup moves each of them to an AWS connection.
type awsLegacyProfile struct {
	Profile, KeyID, Secret string
}

var stashGetName = regexp.MustCompile(`stash get ([A-Za-z0-9_.\-]+)`)

func awsProfilesUsingStash(path string) []awsLegacyProfile {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var found []awsLegacyProfile
	profile := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			profile = strings.TrimSpace(strings.TrimPrefix(strings.Trim(trimmed, "[]"), "profile "))
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok || strings.TrimSpace(key) != "credential_process" || profile == "" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 || strings.Contains(value, " aws creds ") {
			continue
		}
		script, err := os.ReadFile(fields[0])
		if err != nil {
			continue
		}
		var id, secret string
		for _, m := range stashGetName.FindAllStringSubmatch(string(script), -1) {
			upper := strings.ToUpper(m[1])
			switch {
			case strings.Contains(upper, "SECRET"):
				secret = m[1]
			case strings.Contains(upper, "KEY_ID") || strings.Contains(upper, "ACCESS_KEY"):
				id = m[1]
			}
		}
		if id != "" && secret != "" {
			found = append(found, awsLegacyProfile{profile, id, secret})
		}
	}
	return found
}
