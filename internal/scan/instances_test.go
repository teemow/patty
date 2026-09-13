package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect/grafana"
)

// TestDirBindsObservedInstances checks that a credential bound to an
// instance it does not name is handed the instances the scanned tree
// names: the ones in its own file first, the rest of the tree after.
func TestDirBindsObservedInstances(t *testing.T) {
	root := t.TempDir()
	secret := "ScanScanScanScanScanScanScan0123"
	tok := "glsa_" + secret + "_" + grafana.Checksum(secret)
	if err := os.MkdirAll(filepath.Join(root, "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "deploy", ".env"), "GRAFANA_URL=https://grafana.near.example.com\nGRAFANA_TOKEN="+tok+"\n")
	write(t, filepath.Join(root, "README.md"), "Dashboards live at https://grafana.far.example.com/dashboards and https://acme.grafana.net\n")
	write(t, filepath.Join(root, "docs.md"), "See https://grafana.com/docs for the API.\n")

	res, err := Dir(context.Background(), "tree", root, Options{Providers: defaultProviders, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != grafana.KindServiceAccountToken {
		t.Fatalf("findings: %+v", res.Findings)
	}
	got := strings.Split(res.Findings[0].Secret, "\n")
	want := []string{"https://grafana.near.example.com", "https://acme.grafana.net", "https://grafana.far.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("bound instances %v, want %v (own file first, then the tree, vendor sites left out)", got, want)
	}

	// With nothing named anywhere, the token stays unbound and --verify
	// says so without contacting anyone.
	bare := t.TempDir()
	write(t, filepath.Join(bare, ".env"), "GRAFANA_TOKEN="+tok+"\n")
	res, err = Dir(context.Background(), "bare", bare, Options{Providers: defaultProviders, Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Secret != "" || !res.Findings[0].Unverifiable() || !strings.Contains(res.Findings[0].Verification.Detail, grafana.URLFlag) {
		t.Fatalf("unbound: %+v", res.Findings)
	}
}
