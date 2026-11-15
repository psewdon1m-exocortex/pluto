// Package network contains the shared daemon/legacy proxy policy. Proxy secrets
// are never included in errors and are never sent as Saturn Authorization.
package network

import (
	"errors"
	"net/http"
	"net/url"
)

type ProxyConfig struct {
	Mode string `json:"mode,omitempty"` // environment (default), direct, explicit
	URL  string `json:"url,omitempty"`
}

func Proxy(config ProxyConfig) (func(*http.Request) (*url.URL, error), error) {
	switch config.Mode {
	case "", "environment":
		if config.URL != "" {
			return nil, errors.New("proxy URL requires explicit mode")
		}
		return http.ProxyFromEnvironment, nil
	case "direct":
		if config.URL != "" {
			return nil, errors.New("direct mode cannot specify a proxy")
		}
		return nil, nil
	case "explicit":
		u, err := url.Parse(config.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("invalid HTTP proxy configuration")
		}
		return http.ProxyURL(u), nil
	default:
		return nil, errors.New("unknown proxy mode")
	}
}

type ProxyError struct{ Status int }

func (e *ProxyError) Error() string {
	if e.Status == http.StatusProxyAuthRequired {
		return "proxy authorization required (407)"
	}
	return "proxy CONNECT failed"
}
