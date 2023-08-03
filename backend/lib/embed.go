package lib

import "embed"

//go:embed java_src/SerializationDumper.jar
var libResource embed.FS
