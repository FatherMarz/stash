package main

import (
	"fmt"
	"net/url"
	"strings"
)

// Path editing in stash ui. A path says how a program can use a secret:
// through a site (stash adds the key on the way out), as an AWS key pair that
// stash signs with, or as the real value (direct). A secret with no path is
// blocked.

const defaultHeader = "Authorization: Bearer {value}"

func (m *uiModel) blockedCount() int {
	n := 0
	for _, name := range m.names {
		if m.paths[name] == "blocked" {
			n++
		}
	}
	return n
}

// routeFor returns the saved path of a secret, if it has one.
func (m *uiModel) routeFor(name string) (Route, bool) {
	for _, rt := range m.routes {
		if rt.Secret == name || (rt.Kind == "aws" && rt.KeyID == name) {
			return rt, true
		}
	}
	return Route{}, false
}

func siteHost(upstream string) string {
	if u, err := url.Parse(upstream); err == nil && u.Host != "" {
		return u.Host
	}
	return upstream
}

// pathText is the short path line shown beside each secret.
func (m *uiModel) pathText(name string) string {
	switch m.paths[name] {
	case "blocked":
		return "blocked"
	case "direct":
		return "direct: the program gets the real value"
	}
	if rt, ok := m.routeFor(name); ok {
		if rt.Kind == "aws" {
			return "AWS profile " + rt.Name
		}
		if rt.Upstream != "" {
			return "→ " + siteHost(rt.Upstream)
		}
	}
	if rt, ok := builtinRoute(name); ok {
		return "→ " + siteHost(rt.Upstream) + " (built in)"
	}
	return m.paths[name]
}

func (m *uiModel) pathMenu(name string) {
	choices := map[string]func(m *uiModel){
		"s": func(m *uiModel) { m.askSite(name) },
		"d": func(m *uiModel) { m.askDirect(name) },
		"a": func(m *uiModel) { m.askAWS(name) },
	}
	prompt := "path for " + name + ":  s site  d direct  a AWS"
	if _, ok := m.routeFor(name); ok {
		choices["x"] = func(m *uiModel) { m.removePath(name) }
		prompt += "  x remove"
	}
	m.choose(prompt+"  esc cancel", choices)
}

// routeName keeps the current path's name, so an edit replaces it.
func (m *uiModel) routeName(name string) string {
	if rt, ok := m.routeFor(name); ok {
		return rt.Name
	}
	return name
}

func (m *uiModel) askSite(name string) {
	current, _ := m.routeFor(name)
	if current.Upstream == "" {
		if rt, ok := builtinRoute(name); ok {
			current = rt
		}
	}
	m.ask("site address for "+name+" (like https://api.example.com): ", current.Upstream, false, func(m *uiModel, site string) {
		site = strings.TrimSpace(site)
		if site == "" {
			m.say("cancelled")
			return
		}
		header := current.Header
		if header == "" {
			header = defaultHeader
		}
		m.ask("key header ({value} is the key): ", header, false, func(m *uiModel, header string) {
			header = strings.TrimSpace(header)
			if header == "" {
				header = defaultHeader
			}
			rt := Route{Name: m.routeName(name), Secret: name, Upstream: site, Header: header}
			m.confirm(fmt.Sprintf("send %s only to %s? y/n", name, siteHost(site)), func(m *uiModel) {
				m.savePath(name, rt, false, fmt.Sprintf("%s now goes only to %s", name, siteHost(site)))
			})
		})
	})
}

func (m *uiModel) askDirect(name string) {
	rt := Route{Name: m.routeName(name), Secret: name, Kind: "direct"}
	m.confirm(fmt.Sprintf("give programs the real value of %s? Use this only for a database password or a signing secret. y/n", name), func(m *uiModel) {
		m.savePath(name, rt, true, name+" now goes to programs as its real value")
	})
}

func (m *uiModel) askAWS(name string) {
	m.ask("AWS profile name: ", m.routeName(name), false, func(m *uiModel, profile string) {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			m.say("cancelled")
			return
		}
		m.ask(name+" is the secret access key. Secret that holds the access key ID (tab completes): ", "", false, func(m *uiModel, keyID string) {
			keyID = strings.TrimSpace(keyID)
			if keyID == "" {
				m.say("cancelled")
				return
			}
			rt := Route{Name: profile, Kind: "aws", KeyID: keyID, Secret: name}
			m.confirm(fmt.Sprintf("connect AWS profile %s with key ID %s and secret key %s? y/n", profile, keyID, name), func(m *uiModel) {
				m.savePath(name, rt, true, "AWS profile "+profile+" now goes through stash")
				if !m.errState {
					if err := writeAWSProfile(awsConfigPath(), profile, m.c.addr); err != nil {
						m.fail(err)
					}
				}
			})
		})
		m.complete = m.names
	})
	m.complete = nil
}

// savePath stores a path. If the kind changes, the old path goes first, and
// it comes back if the new one fails.
func (m *uiModel) savePath(name string, rt Route, replace bool, done string) {
	old, had := m.routeFor(name)
	if had && (replace || old.Kind != rt.Kind || old.Name != rt.Name) {
		if err := m.c.do("DELETE", "/v1/routes/"+old.Name, nil, nil); err != nil {
			m.fail(err)
			return
		}
	}
	if err := m.c.do("POST", "/v1/routes", rt, nil); err != nil {
		if had {
			m.c.do("POST", "/v1/routes", old, nil)
		}
		m.fail(err)
		return
	}
	m.after("%s", done)
	m.jumpTo(name)
}

func (m *uiModel) removePath(name string) {
	rt, ok := m.routeFor(name)
	if !ok {
		return
	}
	m.confirm(fmt.Sprintf("remove the path for %s? Nothing can use it until it gets a new one. y/n", name), func(m *uiModel) {
		if err := m.c.do("DELETE", "/v1/routes/"+rt.Name, nil, nil); err != nil {
			m.fail(err)
			return
		}
		m.after("%s is blocked now", name)
		m.jumpTo(name)
	})
}
