package routers

import (
	"net/http"
	"strings"

	"github.com/Martin2877/blue-team-box/web"
)

type binaryFileSystem struct {
	fs http.FileSystem
}

func (b *binaryFileSystem) Open(name string) (http.File, error) {
	return b.fs.Open(name)
}

func (b *binaryFileSystem) Exists(prefix, filepath string) bool {
	if p := strings.TrimPrefix(filepath, prefix); len(p) > len(filepath) {
		if _, err := b.fs.Open(p); err != nil {
			return false
		}
		return true
	}
	return false
}

// spaFileSystem 未命中文件时回退到 index.html，兼容前端 history 路由
type spaFileSystem struct {
	fs http.FileSystem
}

func (s *spaFileSystem) Open(name string) (http.File, error) {
	f, err := s.fs.Open(name)
	if err != nil {
		return s.fs.Open("/index.html")
	}
	return f, nil
}

// BinaryFileSystem 返回 embed 的 web/dist 静态资源（随 go build 自动更新，无需 go-bindata）
func BinaryFileSystem() *binaryFileSystem {
	return &binaryFileSystem{
		fs: &spaFileSystem{fs: web.NewFileSystem()},
	}
}
