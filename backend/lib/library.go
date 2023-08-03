package lib

import (
	"github.com/kluctl/go-embed-python/embed_util"
	"log"
	"path"
)

const (
	SerializationDumperJar = "SerializationDumper.jar"
)

type Library struct {
	librarySrc *embed_util.EmbeddedFiles
}

func (ins *Library) GetSerializationDumperJar() (_path string, err error) {
	ins.librarySrc, err = embed_util.NewEmbeddedFiles(libResource, SerializationDumperJar)
	if err != nil {
		return
	}
	_path = path.Join(ins.librarySrc.GetExtractedPath(), "java_src", SerializationDumperJar)
	return
}

func (ins *Library) Cleanup() {
	err := ins.librarySrc.Cleanup()
	if err != nil {
		log.Fatalln("清理缓存失败")
		return
	}
}
