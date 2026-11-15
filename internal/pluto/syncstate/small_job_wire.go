package syncstate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"pluto/internal/syncproto"
)

// The wire schema remains the server's ordinary manifest+inputs. Only the
// local durable envelope records which protocol owns this immutable job.
func (p *smallBatchPlan) asExecutionJob() (*smallBatchPlan, error) {
	if p == nil || len(p.entries) < 1 || len(p.entries) > 16 || p.dataBytes > 4194304 {
		return nil, ErrRemoteUnqualified
	}
	parent := ""
	for _, e := range p.entries {
		intent := e.input.body["intent"].(map[string]any)
		condition, ok := intent["condition"].(map[string]any)
		if !ok || condition["kind"] != "absent" || intent["requireAbsent"] != true || intent["targetId"] != nil || intent["expectedVersionId"] != nil || e.original.SizeBytes <= 0 {
			return nil, ErrRemoteUnqualified
		}
		current := intent["parentId"].(string)
		if parent != "" && parent != current {
			return nil, ErrRemoteUnqualified
		}
		parent = current
	}
	wire, err := p.prepareBytes()
	if err != nil || len(wire) > 1048576 {
		return nil, ErrSourceQuota
	}
	job := *p
	job.executionJob, job.jobWire = true, bytes.Clone(wire)
	return &job, nil
}

func (p *smallBatchPlan) persistedBytes() []byte {
	if !p.executionJob {
		return p.manifestBytes()
	}
	// These two strings always encode; no untrusted marshaler is involved.
	raw, _ := json.Marshal(map[string]string{"schema": "pluto.small-execution-job/v1", "plan_base64": base64.StdEncoding.EncodeToString(p.jobWire)})
	return raw
}

func restoreSmallJobPlan(top map[string]any, originals []Operation) (*smallBatchPlan, error) {
	if _, err := strictHTTPObject(top, "schema", "plan_base64"); err != nil {
		return nil, err
	}
	encoded, ok := top["plan_base64"].(string)
	if !ok || len(encoded) > 1398104 {
		return nil, syncproto.ErrLimit
	}
	wire, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(wire) > 1048576 || base64.StdEncoding.EncodeToString(wire) != encoded {
		return nil, syncproto.ErrContract
	}
	parsed, err := syncproto.Parse(wire)
	if err != nil {
		return nil, err
	}
	plan, err := strictHTTPObject(parsed, "manifest", "inputs")
	if err != nil {
		return nil, err
	}
	// Only the original manifest schema is allowed here; never recursive wrappers.
	m, ok := plan["manifest"].(map[string]any)
	if !ok || m["schema"] != smallBatchSchema {
		return nil, syncproto.ErrContract
	}
	p, err := restoreSmallBatchValue(plan["manifest"], originals)
	if err != nil {
		return nil, err
	}
	job, err := p.asExecutionJob()
	if err != nil {
		return nil, err
	}
	// Canonical encoding compares the entire strictly parsed value, including
	// every input and unknown field. The exact received wire remains retained.
	canonical, err := httpJSON(parsed)
	if err != nil || !bytes.Equal(canonical, job.jobWire) {
		return nil, ErrIdentityConflict
	}
	job.jobWire = bytes.Clone(wire)
	return job, nil
}
