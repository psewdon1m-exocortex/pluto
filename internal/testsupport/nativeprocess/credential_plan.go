package nativefixture

import "errors"

type CredentialRecord struct {
	Kind     string
	PID      int
	UID, GID uint32
	FDs      []int
}
type CredentialPlan struct {
	PID      int
	UID, GID uint32
	CloseFDs []int
	Error    error
}

// Pure plan used by the real receiver. It inventories ALL delivered rights
// before deciding refusal, so even a second rights cmsg cannot leak its fds.
func PlanCredentials(records []CredentialRecord) CredentialPlan {
	var p CredentialPlan
	count := 0
	seen := map[int]bool{}
	bad := false
	for _, r := range records {
		switch r.Kind {
		case "rights":
			bad = true
			for _, fd := range r.FDs {
				if fd >= 0 && !seen[fd] {
					seen[fd] = true
					p.CloseFDs = append(p.CloseFDs, fd)
				}
			}
		case "credentials":
			count++
			p.PID, p.UID, p.GID = r.PID, r.UID, r.GID
		default:
			bad = true
		}
	}
	if bad || count != 1 || p.PID <= 0 || p.UID != 10001 || p.GID != 10001 {
		p.Error = errors.New("one exact kernel credential; no received rights authority")
	}
	return p
}
