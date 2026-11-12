package licensing

import "time"

// State of a licence with a valid signature at a point in time (ADR-004 D3).
type State int

const (
	StateActive State = iota
	StateGrace
	StateExpired
	StateInvalid
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateGrace:
		return "grace"
	case StateExpired:
		return "expired"
	default:
		return "invalid"
	}
}

// GraceEndsAt is the Unix time the grace period ends.
func (l License) GraceEndsAt() int64 {
	return l.ExpiresAt + int64(l.GraceDays())*24*3600
}

// StateAt is active until ExpiresAt, grace until GraceEndsAt, then expired.
func (l License) StateAt(now time.Time) State {
	t := now.Unix()
	switch {
	case t <= l.ExpiresAt:
		return StateActive
	case t <= l.GraceEndsAt():
		return StateGrace
	default:
		return StateExpired
	}
}

// AllowWrite: new tokenisation, updates and configuration changes. Active and
// grace only.
func (s State) AllowWrite() bool { return s == StateActive || s == StateGrace }

// AllowRead: detokenisation and export. Every state with a valid signature: a
// customer is never locked out of their own data.
func (s State) AllowRead() bool { return s != StateInvalid }

// DaysLeft until ExpiresAt, negative once passed (whole days, rounded down).
func (l License) DaysLeft(now time.Time) int {
	d := l.ExpiresAt - now.Unix()
	if d >= 0 {
		return int(d / 86400)
	}
	return -int((-d + 86399) / 86400)
}

// ValidateForDeployment checks a requested deployment against the licence.
func (l License) ValidateForDeployment(nodeCount int, tier string) error {
	if NormalizeTier(l.Tier) != NormalizeTier(tier) {
		return errTier(l.Tier, tier)
	}
	if nodeCount > l.NodeCount {
		return errNodes(l.NodeCount, nodeCount)
	}
	return nil
}
