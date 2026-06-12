package msf

import (
	"testing"
)

// TestDefaultConfig_VerifiesTLSByDefault covers M-05: TLS certificate
// verification must be ON by default (InsecureSkipVerify == false) unless the
// operator explicitly opts in via MSF_INSECURE_TLS=1.
func TestDefaultConfig_VerifiesTLSByDefault(t *testing.T) {
	t.Setenv("MSF_INSECURE_TLS", "")
	if DefaultConfig().InsecureSkipVerify {
		t.Fatal("DefaultConfig should verify TLS by default (InsecureSkipVerify=false)")
	}
}

func TestDefaultConfig_OptInInsecureTLS(t *testing.T) {
	t.Setenv("MSF_INSECURE_TLS", "1")
	if !DefaultConfig().InsecureSkipVerify {
		t.Fatal("MSF_INSECURE_TLS=1 should enable InsecureSkipVerify")
	}
}

func TestHostIsLocalOrPrivate(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":   true,
		"localhost":   true,
		"10.0.0.5":    true,
		"192.168.1.1": true,
		"8.8.8.8":     false,
		"example.com": false,
	}
	for host, want := range cases {
		if got := hostIsLocalOrPrivate(host); got != want {
			t.Errorf("hostIsLocalOrPrivate(%q) = %v, want %v", host, got, want)
		}
	}
}
