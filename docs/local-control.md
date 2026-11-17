# Private macOS control transport

The normal local Stash CLI uses `~/.stash/control/control.sock` when available.
The server starts this alongside the existing plaintext loopback listener on
port 8555. TLS, remote and explicit custom-port clients keep their existing
transport. Other operating systems keep their existing transport.

The data directory must belong to the current user and be unwritable by other
users. Its existing permissions are preserved. The new `control` directory is
mode 0700 and the socket is mode 0600. Symlinks, ordinary files, unsafe directories
and active sockets are never replaced. An owned socket that refuses connections
can be replaced after a crash or restart.

The complete socket path must fit the macOS Unix-socket path limit. A long custom
data path can prevent the default listener from starting. Use a shorter data
path or an explicit custom port for that installation.

The kernel supplies the peer PID through macOS LOCAL_PEERPID. Stash verifies that
PID's executable with its existing sameProgram check. No PID from an HTTP header
is accepted. The CLI also verifies the server executable before it transmits its
authentication token. A present socket that fails verification does not silently
fall back to TCP. The client sends one request per local control connection.

Owner/agent roles, owner-password protection, connection bindings, scoped run
leases and all AWS read restrictions are unchanged. The new transport changes no
stored tokens, keys, routes, AWS profiles or IAM policy. SDK AWS/proxy traffic
continues to use its scoped run tokens over the existing HTTP endpoints.

This avoids a system-wide lsof scan for local CLI control requests. Such scans
can hang on unrelated macOS processes. The existing TCP agent verification path
remains in place for older clients; the underlying OS process-inspection issue
is not repaired by this change.

Regression tests verify kernel/executable identity, foreign-client rejection,
forged PID-header rejection, server-impostor rejection before token transmission,
role boundaries, private paths, active-socket protection, stale-socket recovery,
and streaming control requests. Tests use temporary fixture stores only.

Activation: replace the installed binary and restart the known Stash service.
Then restart programs launched through `stash run` so they obtain new run leases.
A server restart invalidates existing leases. Renewal cannot restore them.
AWS credential-process clients need fresh sessions. Restart affected clients if
they cache a previous session.

Rollback: restore the previous binary and restart the same service. Then restart
affected clients so they obtain new leases. No database restore or token reset
is required.
