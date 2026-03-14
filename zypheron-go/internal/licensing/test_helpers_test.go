package licensing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "licensing-test-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	overrideDBPath = filepath.Join(tmpDir, "test.db")
	code := m.Run()
	os.RemoveAll(tmpDir)
	os.Exit(code)
}
