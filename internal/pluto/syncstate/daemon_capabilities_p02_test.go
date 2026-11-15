package syncstate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestP02DaemonNegotiatesScaledServerWithExplicitTransportRequest(t *testing.T) {
	for _, kind := range []string{"legacy", "scaled", "explicit-v2", "v2-without-stream", "missing-advertisement", "wrong-scaled-bound", "wrong-chunk-size", "missing-scaled-extensions", "missing-file-limit", "numeric-file-limit", "zero-file-limit", "smaller-file-limit", "larger-file-limit"} {
		t.Run(kind, func(t *testing.T) {
			_, _, _, session, _, _ := actualHTTPFixture(t, 0)
			caps := stage3Capabilities(session)
			caps["limits"] = map[string]any{"maximum_file_bytes": "2147483648"}
			switch kind {
			case "missing-file-limit":
				delete(caps, "limits")
			case "numeric-file-limit":
				caps["limits"] = map[string]any{"maximum_file_bytes": 2147483648}
			case "zero-file-limit":
				caps["limits"] = map[string]any{"maximum_file_bytes": "0"}
			case "smaller-file-limit":
				caps["limits"] = map[string]any{"maximum_file_bytes": "1073741824"}
			case "larger-file-limit":
				caps["limits"] = map[string]any{"maximum_file_bytes": "4294967296"}
			}
			limits := caps["extensions"].(map[string]any)["limits"].(map[string]int)
			if kind != "legacy" {
				limits["stream_maximum_chunks"] = 2147483648
			}
			if kind != "legacy" && kind != "missing-advertisement" {
				caps["features"] = append(caps["features"].([]string), "scale-transfer-v2")
			}
			if kind == "wrong-scaled-bound" {
				limits["stream_maximum_chunks"] = 256
			}
			if kind == "wrong-chunk-size" {
				limits["stream_chunk_bytes"] = 8388608
			}
			if kind == "missing-scaled-extensions" {
				delete(caps, "extensions")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(caps)
			}))
			defer server.Close()
			session.origin = server.URL
			session.requested.Features = []string{"stream-upload-v1"}
			explicit := kind == "explicit-v2" || kind == "missing-file-limit" || kind == "numeric-file-limit" || kind == "zero-file-limit" || kind == "smaller-file-limit" || kind == "larger-file-limit"
			if explicit {
				session.requested.Features = append(session.requested.Features, "scale-transfer-v2")
			}
			if kind == "v2-without-stream" {
				session.requested.Features = []string{"scale-transfer-v2"}
			}
			if kind == "missing-scaled-extensions" {
				session.requested.Features = nil
			}
			err := session.Negotiate(testContext)
			if kind != "legacy" && kind != "scaled" && kind != "explicit-v2" && kind != "smaller-file-limit" && kind != "larger-file-limit" {
				if err == nil {
					t.Fatal("inconsistent server bounds accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !session.Features()["stream-upload-v1"] || session.Features()["scale-transfer-v2"] != explicit {
				t.Fatal("server advertisement changed the client's implemented transport", session.Features())
			}
			want := int64(MaxFileBytes)
			if explicit {
				want = streamV2MaximumFileBytes
			}
			if kind == "smaller-file-limit" {
				want = 1 << 30
			}
			if session.streamFileLimit() != want {
				t.Fatal("negotiated file limit", session.streamFileLimit(), want)
			}
		})
	}
}
