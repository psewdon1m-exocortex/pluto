package syncstate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"pluto/internal/network"
	"time"
)

type guardedResolver func(context.Context, string) ([]net.IPAddr, error)
type guardedDialer func(context.Context, string, string) (net.Conn, error)

// CONNECT addresses an already approved IP; TLS still verifies the original
// Saturn hostname in http.Transport. Letting the proxy resolve that hostname
// would bypass AllowedAddresses. A proxy failure never falls back to direct.
func guardedDial(origin *url.URL, allowed map[string]bool, daemon bool, proxy network.ProxyConfig,
	lookup guardedResolver, dial guardedDialer) (guardedDialer, error) {
	chooseProxy, err := network.Proxy(proxy)
	if err != nil {
		return nil, err
	}
	if !daemon {
		if proxy.Mode != "" && proxy.Mode != "direct" || proxy.URL != "" {
			return nil, ErrRemoteUnqualified
		}
		chooseProxy = nil
	}
	return func(parent context.Context, protocol, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != origin.Hostname() {
			return nil, ErrRemoteUnqualified
		}
		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		var candidates []net.IPAddr
		for _, candidate := range ips {
			if allowed[candidate.IP.String()] || daemon && len(allowed) == 0 {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) == 0 {
			return nil, ErrRemoteUnqualified
		}
		var proxyURL *url.URL
		if chooseProxy != nil {
			proxyURL, err = chooseProxy(&http.Request{URL: origin})
			if err != nil {
				return nil, errors.New("proxy configuration unavailable")
			}
		}
		var failures []error
		for i, candidate := range candidates {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			deadline, _ := ctx.Deadline()
			attempt, done := context.WithTimeout(ctx, min(3*time.Second, time.Until(deadline)/time.Duration(len(candidates)-i)))
			target := net.JoinHostPort(candidate.String(), port)
			var connection net.Conn
			if proxyURL == nil {
				connection, err = dial(attempt, protocol, target)
			} else {
				connection, err = dialTunnel(attempt, protocol, target, proxyURL, dial)
			}
			done()
			if err == nil {
				return connection, nil
			}
			var proxyFailure *network.ProxyError
			if errors.As(err, &proxyFailure) && proxyFailure.Status == http.StatusProxyAuthRequired {
				return nil, err
			}
			failures = append(failures, err)
		}
		return nil, errors.Join(failures...)
	}, nil
}

func dialTunnel(ctx context.Context, protocol, target string, proxy *url.URL, dial guardedDialer) (connection net.Conn, resultErr error) {
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, errors.New("unsupported proxy scheme")
	}
	port := proxy.Port()
	if port == "" {
		if proxy.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	connection, resultErr = dial(ctx, protocol, net.JoinHostPort(proxy.Hostname(), port))
	if resultErr != nil {
		return nil, resultErr
	}
	raw := connection
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
			if resultErr == nil {
				resultErr = ctx.Err()
				connection = nil
			}
		}
		if resultErr != nil {
			raw.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		raw.SetDeadline(deadline)
	}
	if proxy.Scheme == "https" {
		secure := tls.Client(raw, &tls.Config{ServerName: proxy.Hostname(), MinVersion: tls.VersionTLS12})
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		connection = secure
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+password)))
	}
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: connection, N: 32 * 1024}
	reader := bufio.NewReaderSize(limited, 4096)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, &network.ProxyError{Status: response.StatusCode}
	}
	limited.N = math.MaxInt64
	// Successful CONNECT has no HTTP body. Preserve any already buffered tunnel bytes.
	if err = raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &tunnelConn{Conn: connection, reader: reader}, nil
}

type tunnelConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *tunnelConn) Read(bytes []byte) (int, error) { return c.reader.Read(bytes) }
