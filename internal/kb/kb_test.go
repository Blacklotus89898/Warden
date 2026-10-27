package kb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSearchRanksTheMatchingRunbook(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("runbooks/crashloop.md", "# CrashLoopBackOff triage\nRead the previous container log. OOMKilled means raise the limit.\n")
	write("solutions/virtiofs-xattr-dind-buildkit.md", "# virtiofs xattr breaks buildkit in dind\ndind failed to create hash: operation not supported\n")
	write("guides/onboarding.md", "# Onboarding a service\nGolden path.\n")
	write(".git/HEAD", "ref: refs/heads/main\n")

	x := &Index{Roots: []Root{{Label: "homelab", Dir: dir}}}
	hits := x.Search([]string{"KubePodCrashLooping", "dind: CrashLoopBackOff", "petal"}, 3)
	if len(hits) == 0 || hits[0].Path != "homelab/runbooks/crashloop.md" || hits[0].Heading != "CrashLoopBackOff triage" {
		t.Fatalf("hits = %+v", hits)
	}
	if h := x.Search([]string{"dind", "operation not supported"}, 1); len(h) != 1 || h[0].Path != "homelab/solutions/virtiofs-xattr-dind-buildkit.md" {
		t.Errorf("hits = %+v", h)
	}
	if h := x.Search([]string{"zz"}, 3); len(h) != 0 {
		t.Errorf("short terms must not match everything: %+v", h)
	}
}
