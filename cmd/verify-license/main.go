package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/obsydia-tech/verify-license/licensing"
)

//go:embed obsydia_license.pub
var obsydiaPublicKey []byte

const (
	exitActive  = 0
	exitInvalid = 1
	exitUsage   = 2
	exitExpired = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fl := flag.NewFlagSet("verify-license", flag.ContinueOnError)
	pubPath := fl.String("pubkey", "", "public key (PEM) to verify against instead of the embedded Obsydia key")
	at := fl.String("at", "", "check the state at this date (YYYY-MM-DD or RFC 3339) instead of now")
	showKey := fl.Bool("show-key", false, "print the embedded Obsydia public key and its fingerprints, then exit")
	fl.Usage = func() {
		fmt.Fprintln(fl.Output(), "usage: verify-license [-pubkey <PEM>] [-at <date>] <licence.json>")
		fmt.Fprintln(fl.Output(), "       verify-license -show-key")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return exitUsage
	}
	if *showKey {
		fmt.Print(string(obsydiaPublicKey))
		pub, err := licensing.ParsePublicKey(obsydiaPublicKey)
		if err != nil {
			fmt.Println("ERROR:", err)
			return exitUsage
		}
		fmt.Println("pem sha256: ", sha256Hex(obsydiaPublicKey))
		fmt.Println("spki sha256:", spkiFingerprint(pub))
		return exitActive
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return exitUsage
	}

	pemData := obsydiaPublicKey
	keySource := "embedded Obsydia key"
	if *pubPath != "" {
		b, err := os.ReadFile(*pubPath)
		if err != nil {
			fmt.Println("ERROR:", err)
			return exitUsage
		}
		pemData = b
		keySource = *pubPath
	}
	pub, err := licensing.ParsePublicKey(pemData)
	if err != nil {
		fmt.Println("ERROR: public key:", err)
		return exitUsage
	}

	now := time.Now()
	if *at != "" {
		t, err := parseDate(*at)
		if err != nil {
			fmt.Println("ERROR: -at:", err)
			return exitUsage
		}
		now = t
	}

	data, err := os.ReadFile(fl.Arg(0))
	if err != nil {
		fmt.Println("ERROR:", err)
		return exitUsage
	}
	sl, err := licensing.Parse(data)
	if err != nil {
		fmt.Println("ERROR:", err)
		fmt.Println("LICENSE INVALID")
		return exitInvalid
	}

	l := sl.License
	fmt.Printf("tenant:      %s\n", l.TenantID)
	fmt.Printf("tier:        %s\n", l.Tier)
	fmt.Printf("nodes:       %d\n", l.NodeCount)
	if l.Mode != "" {
		fmt.Printf("mode:        %s\n", l.Mode)
	}
	fmt.Printf("issued:      %s\n", day(l.IssuedAt))
	fmt.Printf("expires:     %s (%d days left)\n", day(l.ExpiresAt), l.DaysLeft(now))
	fmt.Printf("grace until: %s (%d days)\n", day(l.GraceEndsAt()), l.GraceDays())
	fmt.Printf("format:      v%d\n", l.FormatVersion())
	fmt.Printf("modules:     %s\n", strings.Join(l.Modules(), ", "))
	if v := l.EULA(); v != "" {
		fmt.Printf("eula:        %s\n", v)
	}
	if l.FormatVersion() >= licensing.FormatV2 {
		fmt.Printf("channel:     %s\n", l.Channel())
		fmt.Printf("telemetry:   %s\n", l.Telemetry())
		fmt.Printf("offline:     %t\n", l.Offline())
	}
	fmt.Printf("key:         %s (spki sha256 %s)\n", keySource, spkiFingerprint(pub))

	if err := licensing.VerifySignature(pub, sl); err != nil {
		fmt.Println("signature:  ", err)
		fmt.Println("LICENSE INVALID")
		return exitInvalid
	}
	fmt.Println("signature:   valid")

	switch st := l.StateAt(now); st {
	case licensing.StateActive:
		fmt.Println("LICENSE VALID")
		return exitActive
	case licensing.StateGrace:
		fmt.Printf("LICENSE VALID, EXPIRED, IN GRACE until %s\n", day(l.GraceEndsAt()))
		return exitExpired
	default:
		fmt.Println("LICENSE VALID, EXPIRED, GRACE OVER")
		return exitExpired
	}
}

func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

func day(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func spkiFingerprint(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unknown"
	}
	return sha256Hex(der)
}
