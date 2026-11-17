package main

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var gatewayHost = regexp.MustCompile(`^[a-z0-9]{10}\.execute-api\.([a-z0-9-]{2,40})\.amazonaws\.com$`)
var safeAPIPath = regexp.MustCompile(`^/[A-Za-z0-9._~@/+!-]+$`)

func canonicalAPIPath(value string) bool {
	return safeAPIPath.MatchString(value) && path.Clean(value) == value && !strings.HasSuffix(value, "/")
}

func validateAWSReadAPI(api *AWSReadAPI) error {
	if api == nil || !gatewayHost.MatchString(api.Host) || len(api.Paths) == 0 || len(api.Paths) > 32 {
		return errors.New("read-only API needs one exact API Gateway hostname and 1 to 32 paths")
	}
	for _, pattern := range api.Paths {
		base := strings.TrimSuffix(pattern, "/*")
		if !canonicalAPIPath(base) || strings.Contains(base, "*") {
			return errors.New("read-only API paths must be exact paths or end in /*")
		}
	}
	return nil
}

// The destination comes only from the owner-approved route. The caller can
// neither select a hostname nor use this connection for API mutations.
func awsReadAPIHost(route *Route, region, method, escapedPath string) (string, error) {
	denied := errors.New("API Gateway read is outside the owner-approved connection")
	if route.Kind != "aws" || validateAWSReadAPI(route.AWSReadAPI) != nil || method != http.MethodGet {
		return "", denied
	}
	api := route.AWSReadAPI
	if gatewayHost.FindStringSubmatch(api.Host)[1] != region {
		return "", denied
	}
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil || !canonicalAPIPath(decoded) {
		return "", denied
	}
	for _, pattern := range api.Paths {
		if pattern == decoded {
			return api.Host, nil
		}
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(decoded, strings.TrimSuffix(pattern, "*")) {
			return api.Host, nil
		}
	}
	return "", denied
}
