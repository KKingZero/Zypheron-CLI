package commands

import (
	"strings"
	"testing"
)

func TestAutoPentCmdRequiresExplicitFeatureFlag(t *testing.T) {
	t.Setenv("ZYPHERON_ENABLE_AUTOPENT", "")

	cmd := AutoPentCmd()
	cmd.SetArgs([]string{"127.0.0.1", "--objective", "test objective"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("AutoPentCmd() succeeded without ZYPHERON_ENABLE_AUTOPENT=1")
	}
	if !strings.Contains(err.Error(), "ZYPHERON_ENABLE_AUTOPENT=1") {
		t.Fatalf("error does not explain enablement flag: %v", err)
	}
}

func TestAutoPentCmdDocumentsFeatureFlag(t *testing.T) {
	cmd := AutoPentCmd()
	if !strings.Contains(cmd.Long, "ZYPHERON_ENABLE_AUTOPENT=1") {
		t.Fatalf("autopent long help does not document feature flag: %q", cmd.Long)
	}
}
