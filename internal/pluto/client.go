package pluto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("remote request rejected (HTTP %d)", e.Status)
}

type Remote struct {
	HTTP          *http.Client
	Origin, Token string
}

func NewHTTPClient() *http.Client {
	// Saturn can spend up to a minute waiting for a storage lease, then another
	// minute performing the operation. Keep response headers within that bounded
	// window rather than abandoning a valid queued copy after 30 seconds.
	return &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 2 * time.Minute}}
}
func (r Remote) request(ctx context.Context, method, path string, body io.Reader, size int64, headers map[string]string, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(r.Origin, "/")+path, body)
	if err != nil {
		return errors.New("remote URL is invalid")
	}
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	if size >= 0 {
		req.ContentLength = size
		if size == 0 {
			req.Body = http.NoBody
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return errors.New("remote request timed out; copying will retry")
		}
		return errors.New("remote service is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		message := ""
		if r.Origin == "http://localhost" {
			message = strings.TrimSpace(string(body))
		}
		return &HTTPError{Status: resp.StatusCode, Message: message}
	}
	if result == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return errors.New("remote response exceeds limit")
	}
	if json.Unmarshal(raw, result) != nil {
		return errors.New("remote response is invalid")
	}
	return nil
}
func (r Remote) json(ctx context.Context, method, path string, value any, result any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.request(ctx, method, path, bytes.NewReader(raw), int64(len(raw)), map[string]string{"Content-Type": "application/json"}, result)
}

type Discovery struct{ SaturnURL, Repository string }

func Discover(ctx context.Context, client *http.Client, origin, token string) (Discovery, error) {
	var out struct {
		Values map[string]struct {
			Value  string `json:"value"`
			Secret bool   `json:"secret"`
		} `json:"values"`
	}
	keys := []string{"services.saturn.sni", "services.saturn.port", "repositories.pluto.url"}
	err := (Remote{client, origin, token}).json(ctx, "POST", "/api/v1/register/resolve", map[string]any{"keys": keys}, &out)
	if err != nil {
		return Discovery{}, err
	}
	for _, key := range keys {
		value, ok := out.Values[key]
		if !ok || value.Secret || value.Value == "" {
			return Discovery{}, errors.New("Kernel discovery is incomplete or contains secret values")
		}
	}
	host := out.Values[keys[0]].Value
	port := out.Values[keys[1]].Value
	if strings.ContainsAny(host, "/@?# ") || strings.ContainsAny(port, "/@?# :") {
		return Discovery{}, errors.New("Saturn coordinates are invalid")
	}
	if port != "443" {
		host = net.JoinHostPort(host, port)
	}
	saturn, err := HTTPSOrigin("https://" + host)
	if err != nil {
		return Discovery{}, err
	}
	repo := out.Values[keys[2]].Value
	u, err := url.Parse(repo)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(strings.Split(strings.Trim(u.Path, "/"), "/")) != 2 {
		return Discovery{}, errors.New("Pluto repository must be an HTTPS GitHub repository")
	}
	return Discovery{saturn, repo}, nil
}

type Metadata struct {
	Type, SHA256, ETag string
	SizeBytes          int64
}
type Binding struct {
	Token  string                                            `json:"token"`
	Device struct{ Name, DeviceKind, SyncFolderName string } `json:"device"`
}

func Bind(ctx context.Context, r Remote, code, version string) (Binding, error) {
	var b Binding
	err := r.json(ctx, "POST", "/api/v1/pluto/enrollments/redeem", map[string]string{"code": strings.TrimSpace(code), "version": version}, &b)
	if err != nil {
		return b, err
	}
	if b.Token == "" || b.Device.DeviceKind != "pluto" || b.Device.SyncFolderName == "" {
		return b, errors.New("Saturn returned an invalid Pluto binding")
	}
	return b, nil
}
