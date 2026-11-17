# Owner-approved read-only API Gateway connections

An AWS connection can optionally select one exact API Gateway hostname and an
explicit list of GET paths. Existing connections keep rejecting execute-api until
the owner approves that metadata. AWS keys remain inside Stash.

Paths are exact, or use a trailing /* prefix. Different regions, non-GET methods,
request bodies, arbitrary destinations and encoded traversal are denied. Stash
signs only after checking this route, removes the caller run token upstream and
keeps response redaction. Existing leases keep their captured connection policy.

The restriction covers the HTTP method and path. Query parameters and ordinary
headers pass through. The upstream GET endpoints must themselves be read-only.
The connection still supports its other AWS services under the key pair's IAM
permissions. This grant does not make the whole AWS connection read-only.

The owner can use `--read-api-host` and repeated `--read-api-path` flags with
`stash aws connect`, preserving the connection's existing key and secret names.
In the owner's terminal, activate the owner token as described in the
[migration guide](safer-defaults.md#owner-commands). Then run:

```sh
stash aws connect my-profile --key-id MY_KEY_ID --secret-key MY_SECRET_KEY \
  --read-api-host a1b2c3d4e5.execute-api.us-east-1.amazonaws.com \
  --read-api-path /ops/review --read-api-path '/ops/evidence/*'
```

The hostname above is synthetic. Replace it and the paths with the API's real
details. Set the client's signing region to match the approved hostname.
Owner authorization is required. These settings do not add AWS IAM permission.
Run `unset STASH_TOKEN` after the owner command.

Clients must send their placeholder signature and scoped run token only to the
loopback /aws/PROFILE connection. The configured owner route supplies the real
API destination. The proxy returns redirects to the client without following
them. Configure the client to reject redirects and never send its run token to
an upstream URL directly.

When removing a grant, existing leases can retain their earlier captured policy.
Restarting Stash invalidates all leases. Reconnect affected clients afterward.
Do not reset tokens or restore the whole database to change one connection.
