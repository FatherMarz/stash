//go:build !darwin

package main

import "net/http"

func localCallerIsStash(r *http.Request) (bool, bool)                    { return false, false }
func startLocalControl(dir string, handler http.Handler) (func(), error) { return func() {}, nil }
func configureLocalHTTP(hc *http.Client, addr, dir string)               {}
