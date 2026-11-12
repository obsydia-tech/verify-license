package licensing

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := MarshalPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pub
}

func TestV2LicenceVerifiesWithLegacyCode(t *testing.T) {
	key, _ := mustKey(t)
	feats, err := BuildFeatures("pro", Options{Modules: []string{"federation"}, GraceDays: 30, EULA: "1.0", Channel: "lts", Telemetry: "off"})
	if err != nil {
		t.Fatal(err)
	}
	sl, err := Issue(key, License{TenantID: "acme", Tier: "pro", NodeCount: 6, ExpiresAt: time.Now().Add(time.Hour).Unix(), Features: feats, Mode: ModeSelfhosted}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	file, _ := json.MarshalIndent(sl, "", "  ")
	var old legacySignedLicense
	if err := json.Unmarshal(file, &old); err != nil {
		t.Fatal(err)
	}
	if err := legacyVerify(&key.PublicKey, &old); err != nil {
		t.Fatalf("a v2 licence must verify in binaries built before v2: %v", err)
	}
	for _, m := range []string{"pii", "file_storage", "federation"} {
		found := false
		for _, f := range old.Features {
			found = found || f == m
		}
		if !found {
			t.Errorf("legacy reader does not see module %s", m)
		}
	}
}

func TestLegacyLicenceVerifiesWithPackage(t *testing.T) {
	key, _ := mustKey(t)
	old, err := legacyIssue(key, legacyLicense{TenantID: "acme", Tier: "enterprise", NodeCount: 10, ExpiresAt: time.Now().Add(time.Hour).Unix(), Features: FeaturesForTier("enterprise"), Mode: "selfhosted"})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := json.MarshalIndent(old, "", "  ")
	pub := &key.PublicKey
	sl, st, err := Load(pub, file, time.Now())
	if err != nil || st != StateActive {
		t.Fatalf("legacy licence: %v %v", st, err)
	}
	if sl.FormatVersion() != FormatV1 || sl.GraceDays() != 14 || sl.Channel() != "stable" || sl.Telemetry() != "basic" || sl.Offline() || sl.EULA() != "" {
		t.Fatalf("v1 defaults: %+v", sl)
	}
	// Nil features and empty mode survive a round trip byte for byte.
	old2, _ := legacyIssue(key, legacyLicense{TenantID: "x", Tier: "pro", NodeCount: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	f2, _ := json.Marshal(old2)
	if _, _, err := Load(pub, f2, time.Now()); err != nil {
		t.Fatalf("nil features / empty mode: %v", err)
	}
}

// TestGoldenFromProductionCLI verifies licences made by the licence CLI that
// was in production before this package (testdata written at repository
// creation with a throwaway key).
func TestGoldenFromProductionCLI(t *testing.T) {
	files, _ := filepath.Glob("testdata/golden-*.json")
	if len(files) == 0 {
		t.Skip("no golden licences in testdata")
	}
	pubPEM, err := os.ReadFile("testdata/golden.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		sl, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := VerifySignature(pub, sl); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		var old legacySignedLicense
		json.Unmarshal(data, &old)
		if !reflect.DeepEqual(old.Features, sl.Features) || old.TenantID != sl.TenantID || old.ExpiresAt != sl.ExpiresAt {
			t.Errorf("%s: package and legacy readers disagree", f)
		}
		tampered := *sl
		tampered.NodeCount++
		if VerifySignature(pub, &tampered) == nil {
			t.Errorf("%s: tampered licence verified", f)
		}
	}
	t.Logf("%d golden licence(s) verified", len(files))
}

func TestEntries(t *testing.T) {
	f, err := BuildFeatures("professional", Options{Modules: []string{"Memory", "federation", "federation", "pii"}, GraceDays: 30, EULA: "1.2", Channel: "lts", Telemetry: "off"})
	if err != nil {
		t.Fatal(err)
	}
	want := "pii,keys,bridge,audit,export,monitoring,file_storage,federation,memory,lv:2,grace:30,eula:1.2,channel:lts,telemetry:off"
	if strings.Join(f, ",") != want {
		t.Fatalf("features:\n got %s\nwant %s", strings.Join(f, ","), want)
	}
	l := License{Features: f}
	if l.FormatVersion() != 2 || l.GraceDays() != 30 || l.EULA() != "1.2" || l.Channel() != "lts" || l.Telemetry() != "off" || l.Offline() {
		t.Fatalf("accessors: %+v", l)
	}
	if !l.HasModule("memory") || l.HasModule("lv") || l.HasModule("grace:30") {
		t.Fatal("modules")
	}
	d, _ := BuildFeatures("community", Options{})
	if strings.Join(d, ",") != "pii,keys,bridge,audit,export,lv:2" {
		t.Fatalf("defaults add only the format marker: %v", d)
	}
	off, _ := BuildFeatures("starter", Options{Offline: true})
	lo := License{Features: off}
	if !lo.Offline() || lo.Telemetry() != "off" {
		t.Fatal("offline implies telemetry off")
	}
	for _, bad := range []Options{{Modules: []string{"bad module"}}, {Modules: []string{"a:b"}}, {GraceDays: -1}, {GraceDays: 400}, {EULA: "1 0"}, {Channel: "beta"}, {Telemetry: "full"}} {
		if _, err := BuildFeatures("pro", bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	junk := License{Features: []string{"grace:abc", "grace:-3", "channel:beta", "lv:x", "unknown:1"}}
	if junk.GraceDays() != 14 || junk.Channel() != "stable" || junk.FormatVersion() != 1 || len(junk.Modules()) != 0 {
		t.Fatal("malformed settings must fall back to defaults")
	}
	if NormalizeTier("Core") != "starter" || NormalizeTier("professional") != "pro" || NormalizeTier("enterprise") != "enterprise" {
		t.Fatal("tier mapping")
	}
}

func TestStates(t *testing.T) {
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	l := License{ExpiresAt: exp.Unix()}
	cases := []struct {
		at    time.Time
		state State
		write bool
	}{
		{exp.Add(-time.Hour), StateActive, true},
		{exp, StateActive, true},
		{exp.Add(time.Second), StateGrace, true},
		{exp.Add(14 * 24 * time.Hour), StateGrace, true},
		{exp.Add(14*24*time.Hour + time.Second), StateExpired, false},
	}
	for _, c := range cases {
		st := l.StateAt(c.at)
		if st != c.state || st.AllowWrite() != c.write || !st.AllowRead() {
			t.Errorf("%s: %v write=%v read=%v", c.at, st, st.AllowWrite(), st.AllowRead())
		}
	}
	if StateInvalid.AllowRead() || StateInvalid.AllowWrite() {
		t.Fatal("invalid allows nothing")
	}
	g := License{ExpiresAt: exp.Unix(), Features: []string{"grace:0"}}
	if g.StateAt(exp.Add(time.Second)) != StateExpired {
		t.Fatal("grace:0 means no grace")
	}
	if l.DaysLeft(exp.Add(-36*time.Hour)) != 1 || l.DaysLeft(exp.Add(36*time.Hour)) != -2 {
		t.Fatalf("days left: %d %d", l.DaysLeft(exp.Add(-36*time.Hour)), l.DaysLeft(exp.Add(36*time.Hour)))
	}
}

func TestInvalid(t *testing.T) {
	key, _ := mustKey(t)
	other, _ := mustKey(t)
	sl, _ := Issue(key, License{TenantID: "a", Tier: "pro", NodeCount: 1, ExpiresAt: time.Now().Add(-100 * 24 * time.Hour).Unix()}, time.Now())
	data, _ := json.Marshal(sl)
	if _, st, err := Load(&other.PublicKey, data, time.Now()); err == nil || st != StateInvalid {
		t.Fatal("wrong key must be invalid")
	}
	if _, st, err := Load(&key.PublicKey, data, time.Now()); err != nil || st != StateExpired || !st.AllowRead() {
		t.Fatalf("expired licence with a good signature is readable: %v %v", st, err)
	}
	for _, bad := range []string{`{`, `{"tenant_id":"a"}`, `{"tenant_id":"a","tier":"pro","expires_at":1,"signature":"AAAA"}`} {
		if _, st, err := Load(&key.PublicKey, []byte(bad), time.Now()); err == nil || st != StateInvalid {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := (License{Tier: "professional", NodeCount: 3}).ValidateForDeployment(3, "pro"); err != nil {
		t.Fatal(err)
	}
	if (License{Tier: "pro", NodeCount: 3}).ValidateForDeployment(4, "pro") == nil {
		t.Fatal("node limit")
	}
}
