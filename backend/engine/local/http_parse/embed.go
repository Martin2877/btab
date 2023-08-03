package httpparse

import "embed"

//go:embed resource/static_page_suffix.csv
//go:embed resource/dynamic_page_suffix.csv
//go:embed resource/http_content_type.csv
//go:embed resource/file_type_magic_offset.csv
var resource embed.FS
