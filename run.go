package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// stash run starts the command with its secrets. An API key with a proxy
// route arrives as a run token plus a matching *_BASE_URL, so the real key
// never enters the command's process. AWS keys never arrive at all: the AWS
// profile sends calls through stash. Every other secret arrives as its real
// value, and stash prints it as **** in the command's output.

type commandExit struct{ code int }

func (e *commandExit) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func cmdRun(args []string) error {
	var selected []string
	for len(args) > 0 {
		switch args[0] {
		case "--":
			args = args[1:]
			goto ready
		case "--secret":
			if len(args) < 2 || args[1] == "" {
				return errors.New("--secret needs a secret name")
			}
			selected = append(selected, args[1])
			args = args[2:]
		default:
			if strings.HasPrefix(args[0], "--") {
				return fmt.Errorf("unknown run option %s", args[0])
			}
			goto ready
		}
	}
ready:
	if len(args) == 0 {
		return errors.New("usage: stash run [--secret NAME ...] [--] COMMAND [ARGS...]")
	}
	return runProxied(args, selected)
}

// The server creates a scoped proxy credential without returning raw values.
func runProxied(args, selected []string) (err error) {
	c := newClient()
	var setup runSetup
	if err := c.do("POST", "/v1/run", map[string]any{"secrets": selected}, &setup); err != nil {
		return err
	}
	cleanup := &client{addr: c.addr, token: setup.Token, http: c.http}
	defer func() {
		if cleanupErr := cleanup.do("DELETE", "/v1/run", nil, nil); cleanupErr != nil {
			fmt.Fprintln(os.Stderr, "stash: could not revoke run token; it expires within one hour")
		}
	}()
	stopRenew := make(chan struct{})
	defer close(stopRenew)
	go func() {
		tick := time.NewTicker(15 * time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-stopRenew:
				return
			case <-tick.C:
				cleanup.do("POST", "/v1/run/renew", nil, nil)
			}
		}
	}()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = proxyEnvironment(os.Environ(), c.addr, setup)
	masked := []string{setup.Token, c.token}
	for _, value := range setup.Values {
		masked = append(masked, value)
	}
	code, err := runCommand(cmd, masked)
	if err != nil {
		return err
	}
	if code != 0 {
		return &commandExit{code}
	}
	return nil
}

// Remove ambient stash authority and every stored secret name, including
// secrets outside the selected scope, before constructing the child env.
func proxyEnvironment(parent []string, addr string, setup runSetup) []string {
	blocked := map[string]bool{"STASH_TOKEN": true, "STASH_ADDR": true, "STASH_MASTER_KEY": true, "DSH_STASH_TOKEN": true, "DSH_STASH_ADDR": true, "OPENAI_BASE_URL": true, "ANTHROPIC_BASE_URL": true}
	for _, name := range setup.SecretNames {
		blocked[envName(name)] = true
		blocked[envName(name)+"_BASE_URL"] = true
	}
	var env []string
	for _, pair := range parent {
		key, _, _ := strings.Cut(pair, "=")
		if !blocked[key] {
			env = append(env, pair)
		}
	}
	for name, value := range setup.Values {
		env = append(env, envName(name)+"="+value)
	}
	for _, rt := range setup.Routes {
		env = append(env, envName(rt.Secret)+"="+setup.Token)
		env = append(env, envName(rt.Secret)+"_BASE_URL="+strings.TrimRight(addr, "/")+"/proxy/"+rt.Name)
		if rt.Secret == "OPENAI_API_KEY" {
			env = append(env, "OPENAI_BASE_URL="+strings.TrimRight(addr, "/")+"/proxy/"+rt.Name)
		}
		if rt.Secret == "ANTHROPIC_API_KEY" {
			env = append(env, "ANTHROPIC_BASE_URL="+strings.TrimRight(addr, "/")+"/proxy/"+rt.Name)
		}
	}
	return env
}

func runCommand(cmd *exec.Cmd, values []string) (int, error) {
	if ptySupported && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		return runOnPTY(cmd, values)
	}
	return runOnPipes(cmd, values)
}

func isPasswordErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "needs the owner password")
}

// forwardSignals passes stop signals on to the command, so a service
// manager that stops `stash run` also stops what it started.
func forwardSignals(cmd *exec.Cmd, sigs ...os.Signal) func() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, sigs...)
	go func() {
		for s := range ch {
			if cmd.Process != nil {
				cmd.Process.Signal(s)
			}
		}
	}()
	return func() { signal.Stop(ch); close(ch) }
}

func exitCode(err error) (int, error) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return 0, err
}

// runOnPipes serves scripts and agents. Stdin passes straight through.
func runOnPipes(cmd *exec.Cmd, values []string) (int, error) {
	cmd.Stdin = os.Stdin
	stdout := newMasker(values, func(b []byte) { os.Stdout.Write(b) })
	stderr := newMasker(values, func(b []byte) { os.Stderr.Write(b) })
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Ctrl-C reaches the command from the terminal already. Forward the rest.
	signal.Ignore(os.Interrupt)
	stop := forwardSignals(cmd, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	err := cmd.Run()
	stop()
	stdout.Flush()
	stderr.Flush()
	return exitCode(err)
}

// runOnPTY serves a person at a terminal. The command gets its own terminal,
// so colors, prompts, and keys work as before, and its screen output still
// passes through the masker.
func runOnPTY(cmd *exec.Cmd, values []string) (int, error) {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return 0, err
	}
	defer ptmx.Close()

	defer watchResize(ptmx)()

	old, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return 0, err
	}
	defer term.Restore(int(os.Stdin.Fd()), old)

	stop := forwardSignals(cmd, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	go io.Copy(ptmx, os.Stdin)
	out := newMasker(values, func(b []byte) { os.Stdout.Write(b) })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(out, ptmx) // ends with an error when the command exits
	}()
	err = cmd.Wait()
	wg.Wait()
	out.Flush()
	return exitCode(err)
}
