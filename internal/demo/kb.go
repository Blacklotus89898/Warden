package demo

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

// kbFiles are short stand-ins for the DaVinci knowledge base, at the same
// paths, so the demo's KB hits link to the real documents.
//
//go:embed kb
var kbFiles embed.FS

// WriteKB copies the demo knowledge base under dir and returns the root to
// index (label "davinci", as in production).
func WriteKB(dir string) (string, error) {
	root := filepath.Join(dir, "kb")
	err := fs.WalkDir(kbFiles, "kb", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out := filepath.Join(dir, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := kbFiles.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
	return root, err
}
