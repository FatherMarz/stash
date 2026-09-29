package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// stash run starts the command in the caller's own shell, as it always did,
// so the command keeps its directory, terminal, and permissions. The one
// change is its output: every secret value in it shows as ****.

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: stash run [--] COMMAND [ARGS...]")
	}
	c := newClient()
	var secrets map[string]string
	err := c.do("GET", "/v1/env", nil, &secrets)
	if isPasswordErr(err) {
		if c.password, err = readPassword("owner password: "); err != nil {
			return err
		}
		err = c.do("GET", "/v1/env", nil, &secrets)
	}
	if err != nil {
		return err
	}
	env := os.Environ()
	values := make([]string, 0, len(secrets))
	for name, value := range secrets {
		env = append(env, envName(name)+"="+value)
		values = append(values, value)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env

	var code int
	if ptySupported && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		code, err = runOnPTY(cmd, values)
	} else {
		code, err = runOnPipes(cmd, values)
	}
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
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
