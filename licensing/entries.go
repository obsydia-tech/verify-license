package licensing

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Entries in Features (ADR-004 D1): an entry without a colon is a module; an
// entry "key:value" is a setting. Unknown entries are ignored, so new settings
// never break older readers.

const (
	FormatV1 = 1
	FormatV2 = 2

	DefaultGraceDays = 14

	ChannelStable = "stable"
	ChannelLTS    = "lts"

	TelemetryBasic = "basic"
	TelemetryOff   = "off"

	settingFormat    = "lv"
	settingGrace     = "grace"
	settingEULA      = "eula"
	settingChannel   = "channel"
	settingTelemetry = "telemetry"
	moduleOffline    = "offline"

	maxGraceDays = 365
)

// Canonical tiers (ADR-004 D4).
const (
	TierCommunity  = "community"
	TierStarter    = "starter"
	TierPro        = "pro"
	TierEnterprise = "enterprise"
)

// NormalizeTier maps legacy names (access token: core, professional) to the
// canonical tier. Unknown names are returned lower-cased.
func NormalizeTier(t string) string {
	switch t = strings.ToLower(strings.TrimSpace(t)); t {
	case "core":
		return TierStarter
	case "professional":
		return TierPro
	}
	return t
}

// FeaturesForTier is the module set every licence of a tier carries. It is
// the list the licence CLI has issued since 2026.
func FeaturesForTier(tier string) []string {
	switch NormalizeTier(tier) {
	case TierCommunity:
		return []string{"pii", "keys", "bridge", "audit", "export"}
	case TierStarter:
		return []string{"pii", "keys", "bridge", "audit", "export", "monitoring"}
	case TierPro:
		return []string{"pii", "keys", "bridge", "audit", "export", "monitoring", "file_storage"}
	case TierEnterprise:
		return []string{"pii", "keys", "bridge", "audit", "export", "monitoring", "file_storage", "ha"}
	default:
		return []string{"pii", "keys", "bridge", "audit", "export"}
	}
}

func (l License) setting(key string) (string, bool) {
	prefix := key + ":"
	for _, f := range l.Features {
		if strings.HasPrefix(f, prefix) {
			return f[len(prefix):], true
		}
	}
	return "", false
}

// Modules lists the module entries (no colon), in licence order.
func (l License) Modules() []string {
	out := []string{}
	for _, f := range l.Features {
		if f != "" && !strings.Contains(f, ":") {
			out = append(out, f)
		}
	}
	return out
}

// HasModule reports whether a module is licensed.
func (l License) HasModule(m string) bool {
	for _, f := range l.Modules() {
		if f == m {
			return true
		}
	}
	return false
}

func (l License) FormatVersion() int {
	if v, ok := l.setting(settingFormat); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return FormatV1
}

// GraceDays is the grace period after ExpiresAt, 14 days unless the licence
// says otherwise.
func (l License) GraceDays() int {
	if v, ok := l.setting(settingGrace); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= maxGraceDays {
			return n
		}
	}
	return DefaultGraceDays
}

func (l License) EULA() string {
	v, _ := l.setting(settingEULA)
	return v
}

func (l License) Channel() string {
	if v, ok := l.setting(settingChannel); ok && (v == ChannelStable || v == ChannelLTS) {
		return v
	}
	return ChannelStable
}

// Offline licences are air-gapped: no phone-home, no reports.
func (l License) Offline() bool { return l.HasModule(moduleOffline) }

// Telemetry is the scope of node reports: off for offline licences.
func (l License) Telemetry() string {
	if l.Offline() {
		return TelemetryOff
	}
	if v, ok := l.setting(settingTelemetry); ok && v == TelemetryOff {
		return TelemetryOff
	}
	return TelemetryBasic
}

// Options are the v2 settings and extra modules for a new licence.
type Options struct {
	Modules   []string // added to the tier's modules
	GraceDays int      // 0 = default
	EULA      string
	Channel   string
	Telemetry string
	Offline   bool
}

var entryPattern = func(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// BuildFeatures returns the Features for a v2 licence: the tier's modules,
// the extra modules, then the settings. It validates every value.
func BuildFeatures(tier string, o Options) ([]string, error) {
	out := append([]string{}, FeaturesForTier(tier)...)
	seen := map[string]bool{}
	for _, m := range out {
		seen[m] = true
	}
	extra := []string{}
	for _, m := range o.Modules {
		extra = append(extra, strings.ToLower(strings.TrimSpace(m)))
	}
	if o.Offline {
		extra = append(extra, moduleOffline)
	}
	sort.Strings(extra)
	for _, m := range extra {
		if m == "" {
			continue
		}
		if !entryPattern(m) {
			return nil, fmt.Errorf("invalid module %q", m)
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	out = append(out, fmt.Sprintf("%s:%d", settingFormat, FormatV2))
	if o.GraceDays < 0 || o.GraceDays > maxGraceDays {
		return nil, fmt.Errorf("grace must be 0..%d days", maxGraceDays)
	}
	if o.GraceDays > 0 && o.GraceDays != DefaultGraceDays {
		out = append(out, fmt.Sprintf("%s:%d", settingGrace, o.GraceDays))
	}
	if o.EULA != "" {
		if !entryPattern(o.EULA) {
			return nil, fmt.Errorf("invalid eula version %q", o.EULA)
		}
		out = append(out, settingEULA+":"+o.EULA)
	}
	switch o.Channel {
	case "", ChannelStable:
	case ChannelLTS:
		out = append(out, settingChannel+":"+ChannelLTS)
	default:
		return nil, fmt.Errorf("invalid channel %q", o.Channel)
	}
	switch o.Telemetry {
	case "", TelemetryBasic:
	case TelemetryOff:
		out = append(out, settingTelemetry+":"+TelemetryOff)
	default:
		return nil, fmt.Errorf("invalid telemetry %q", o.Telemetry)
	}
	return out, nil
}
