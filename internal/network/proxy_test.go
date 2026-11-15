package network

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProxyModesShareEnvironmentAndExplicitPolicy(t *testing.T) {
	runProxyChild(t, "", "http://proxy.test:3128")
	request, _ := http.NewRequest("GET", "https://saturn.test/", nil)
	explicit, err := Proxy(ProxyConfig{Mode: "explicit", URL: "https://user:secret@proxy.test:8443"})
	if err != nil {
		t.Fatal(err)
	}
	chosen, err := explicit(request)
	if err != nil || chosen.String() != "https://user:secret@proxy.test:8443" {
		t.Fatal("explicit proxy changed")
	}
	direct, err := Proxy(ProxyConfig{Mode: "direct"})
	if err != nil || direct != nil {
		t.Fatal("direct policy used environment")
	}
}

func runProxyChild(t *testing.T, bypass, expected string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestNetworkAcceptanceN12EnvironmentChild$")
	for _, value := range os.Environ() {
		key := strings.ToUpper(strings.SplitN(value, "=", 2)[0])
		if strings.Contains(key, "PROXY") || key == "REQUEST_METHOD" {
			continue
		}
		command.Env = append(command.Env, value)
	}
	command.Env = append(command.Env, "NETWORK_PROXY_CHILD=1", "HTTPS_PROXY=http://proxy.test:3128", "NO_PROXY="+bypass, "NETWORK_PROXY_EXPECT="+expected)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("child proxy policy failed: %v %s", err, output)
	}
}

func TestNetworkAcceptanceN12EnvironmentChild(t *testing.T) {
	if os.Getenv("NETWORK_PROXY_CHILD") != "1" {
		runProxyChild(t, "", "http://proxy.test:3128")
		runProxyChild(t, "saturn.test", "")
		return
	}
	choose, err := Proxy(ProxyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest("GET", "https://saturn.test/", nil)
	proxy, err := choose(request)
	if err != nil {
		t.Fatal("proxy policy error")
	}
	actual := ""
	if proxy != nil {
		actual = proxy.String()
	}
	if actual != os.Getenv("NETWORK_PROXY_EXPECT") {
		t.Fatal("environment/NO_PROXY policy mismatch")
	}
}

func TestInvalidProxyPolicyFailsClosed(t *testing.T) {
	for _, config := range []ProxyConfig{{Mode: "unknown"}, {Mode: "direct", URL: "http://proxy.test"}, {Mode: "explicit", URL: "socks5://proxy.test"}, {Mode: "explicit", URL: "http://proxy.test/path"}} {
		if _, err := Proxy(config); err == nil {
			t.Fatal("invalid proxy accepted")
		}
	}
}
