package assets

import (
	"html/template"
	"io/fs"
	"testing"
)

func TestEmbedAssets_ContainsExpectedFiles(t *testing.T) {
	assets := &EmbedAssets{}
	expected := []string{"sign_in.html", "sign_up.html"}
	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			f, err := assets.GetTemplates().Open(name)
			if err != nil {
				t.Fatalf("expected %s to be embedded: %v", name, err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("stat %s: %v", name, err)
			}
			if info.Size() == 0 {
				t.Errorf("%s is empty", name)
			}
		})
	}
}

func TestEmbedAssets_OnlyHTMLFilesEmbedded(t *testing.T) {
	assets := &EmbedAssets{}
	entries, err := fs.ReadDir(assets.GetTemplates(), ".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("unexpected directory in embedded FS: %s", e.Name())
		}
	}
}

func TestEmbedAssets_ParsesAsGinTemplates(t *testing.T) {
	assets := &EmbedAssets{}
	tmpl, err := template.ParseFS(assets.GetTemplates(), "*.html")
	if err != nil {
		t.Fatalf("template.ParseFS failed: %v", err)
	}

	required := []string{"sign_in.html", "sign_up.html"}
	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			if tmpl.Lookup(name) == nil {
				t.Errorf("template %q not found after ParseFS", name)
			}
		})
	}
}
