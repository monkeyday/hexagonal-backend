package assets

import (
	"embed"
	"io/fs"
)

//go:embed *.html
var htmlFS embed.FS

type EmbedAssets struct{}

func (a *EmbedAssets) GetTemplates() fs.FS {
	return htmlFS
}
