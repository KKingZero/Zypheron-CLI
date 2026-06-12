package licensing

import "testing"

// TestProviderGatesAreNoOps documents that RequireProviderAccess and
// CheckProviderAndTokens enforce NOTHING (M-08). They always return nil for any
// input. This test exists so the no-op behaviour is explicit and cannot be
// silently relied upon as a security control: if someone implements real
// enforcement later, this test will fail and force a deliberate decision.
func TestProviderGatesAreNoOps(t *testing.T) {
	providers := []string{"", "claude", "ollama", "custom-provider", "openai"}

	for _, p := range providers {
		if err := RequireProviderAccess(p); err != nil {
			t.Errorf("RequireProviderAccess(%q) is documented as a no-op; got error: %v", p, err)
		}
		if err := CheckProviderAndTokens(p, 1_000_000); err != nil {
			t.Errorf("CheckProviderAndTokens(%q) is documented as a no-op; got error: %v", p, err)
		}
	}
}
