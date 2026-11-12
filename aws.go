package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// AWS connections keep the key pair inside stash. The AWS profile points the
// CLI or SDK at http://127.0.0.1:8555/aws/NAME with a placeholder key and a
// run token as its session token. stash checks the run token, drops the
// placeholder signature, and signs the call again with the real key pair.
// The host is always an amazonaws.com name built from the service and region.

const maxSignedBody = 256 << 20

// awsURL builds the outgoing URL. Tests point it at a local server.
var awsURL = func(host, path string) string { return "https://" + host + path }

var awsLabel = regexp.MustCompile(`^[a-z0-9-]{2,40}$`)

// awsCredential reads the region and service from a SigV4 Authorization
// header: "AWS4-HMAC-SHA256 Credential=KEY/DATE/REGION/SERVICE/aws4_request, ...".
func awsCredential(header string) (region, service string, err error) {
	_, rest, ok := strings.Cut(header, "Credential=")
	if !ok {
		return "", "", errors.New("the call is not signed with AWS SigV4")
	}
	scope, _, _ := strings.Cut(rest, ",")
	parts := strings.Split(strings.TrimSpace(scope), "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return "", "", errors.New("bad AWS credential scope")
	}
	region, service = parts[2], parts[3]
	if !awsLabel.MatchString(region) || !awsLabel.MatchString(service) {
		return "", "", errors.New("bad AWS region or service name")
	}
	return region, service, nil
}

// awsHost maps a signing service and region to the real AWS host.
func awsHost(service, region, path string) (string, error) {
	switch service {
	case "iam", "route53", "cloudfront", "budgets":
		return service + ".amazonaws.com", nil
	case "ce", "organizations":
		return service + ".us-east-1.amazonaws.com", nil
	case "aws-marketplace":
		return "catalog.marketplace.us-east-1.amazonaws.com", nil
	case "ses":
		return "email." + region + ".amazonaws.com", nil
	case "ecr":
		return "api.ecr." + region + ".amazonaws.com", nil
	case "bedrock":
		if strings.HasPrefix(path, "/model/") {
			return "bedrock-runtime." + region + ".amazonaws.com", nil
		}
		return "bedrock." + region + ".amazonaws.com", nil
	case "execute-api":
		return "", errors.New("API Gateway calls cannot go through stash")
	}
	return service + "." + region + ".amazonaws.com", nil
}

// awsSession gives a program a run token for one AWS connection. It lasts an
// hour. The AWS CLI asks again when it runs out.
func (s *server) awsSession(w http.ResponseWriter, r *http.Request, tok *Token) {
	rt, err := s.st.GetRoute(r.PathValue("route"))
	if err != nil || rt.Kind != "aws" {
		writeErr(w, http.StatusNotFound, "no AWS connection named "+r.PathValue("route"))
		return
	}
	token, err := newRunToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create run token")
		return
	}
	expires := time.Now().Add(time.Hour)
	s.addLease(token, r, map[string]Route{rt.Name: *rt}, time.Hour)
	s.st.Audit(tok.Name, "aws-session", rt.Name)
	writeJSON(w, http.StatusCreated, map[string]string{"token": token, "expires": expires.UTC().Format(time.RFC3339)})
}

func (s *server) awsRequest(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("route")
	plain := requestToken(r)
	if !s.runAllows(plain, name) {
		writeErr(w, http.StatusForbidden, "this AWS connection is outside the token's scope")
		return
	}
	rt, err := s.routeForRequest(plain, name)
	if err != nil || rt.Kind != "aws" {
		writeErr(w, http.StatusNotFound, "no AWS connection named "+name)
		return
	}
	if r.URL.Query().Get("X-Amz-Signature") != "" {
		writeErr(w, http.StatusBadRequest, "presigned AWS URLs cannot go through stash")
		return
	}
	region, service, err := awsCredential(r.Header.Get("Authorization"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/aws/"+name)
	if path == "" {
		path = "/"
	}
	host, err := awsHost(service, region, path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	keyID, err := s.st.Get(rt.KeyID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "the AWS key ID secret is missing")
		return
	}
	secret, err := s.st.Get(rt.Secret)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "the AWS secret key secret is missing")
		return
	}

	payload := r.Header.Get("X-Amz-Content-Sha256")
	var body io.Reader = r.Body
	length := r.ContentLength
	switch {
	case payload == "UNSIGNED-PAYLOAD" || payload == "STREAMING-UNSIGNED-PAYLOAD-TRAILER":
		// The body is not part of the signature. Pass it through as it is.
	case strings.HasPrefix(payload, "STREAMING-"):
		writeErr(w, http.StatusBadRequest, "signed chunk uploads cannot go through stash. Set payload_signing_enabled = false")
		return
	default:
		data, err := io.ReadAll(io.LimitReader(r.Body, maxSignedBody+1))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "cannot read the request body")
			return
		}
		if len(data) > maxSignedBody {
			writeErr(w, http.StatusRequestEntityTooLarge, "signed AWS bodies over 256 MB cannot go through stash")
			return
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		if payload != "" && payload != hash {
			writeErr(w, http.StatusBadRequest, "the body does not match its x-amz-content-sha256")
			return
		}
		payload, body, length = hash, bytes.NewReader(data), int64(len(data))
	}

	target, err := url.Parse(awsURL(host, path))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad AWS path")
		return
	}
	target.RawQuery = r.URL.RawQuery
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad AWS request")
		return
	}
	out.ContentLength = length
	for key, values := range r.Header {
		switch http.CanonicalHeaderKey(key) {
		case "Authorization", "X-Amz-Security-Token", "X-Amz-Date", "Host", "Connection", "Keep-Alive",
			"Proxy-Authorization", "Proxy-Connection", "Te", "Trailer", "Upgrade", "Content-Length", "X-Amz-Content-Sha256":
			continue
		}
		out.Header[key] = values
	}
	if service == "s3" || r.Header.Get("X-Amz-Content-Sha256") != "" {
		out.Header.Set("X-Amz-Content-Sha256", payload)
	}
	creds := aws.Credentials{AccessKeyID: keyID, SecretAccessKey: secret}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = service == "s3" })
	if err := signer.SignHTTP(r.Context(), creds, out, payload, service, region, time.Now()); err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot sign the AWS call")
		return
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out = out.WithContext(pr.In.Context())
		},
		ModifyResponse: func(response *http.Response) error {
			return protectProxyResponse(response, []string{secret, keyID, plain})
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeErr(w, http.StatusBadGateway, "AWS request failed")
		},
	}
	s.st.Audit(tok.Name, "aws", rt.Name+" "+service)
	proxy.ServeHTTP(w, r)
}
