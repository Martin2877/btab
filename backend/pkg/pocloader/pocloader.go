package pocloader

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

func NewPocLoader(customTemplatePath string) (*PocLoader, error) {
	pl := PocLoader{}
	err := pl.Load(customTemplatePath)
	if err != nil {
		return nil, err
	}
	return &pl, nil
}

// NewPocLoaderFromFiles 从内存中的模板内容加载（模板内容存数据库时使用）：
// 物化到临时目录供 nuclei 加载，Close 时自动清理。
func NewPocLoaderFromFiles(templates map[string][]byte) (*PocLoader, error) {
	if len(templates) == 0 {
		return nil, errors.New("no nuclei templates")
	}
	tmpDir, err := os.MkdirTemp("", "btab-nuclei-*")
	if err != nil {
		return nil, err
	}
	pl := &PocLoader{tmpDir: tmpDir}
	for name, content := range templates {
		safe := filepath.Base(name)
		if safe == "" || safe == "." || safe == ".." {
			continue
		}
		if werr := os.WriteFile(filepath.Join(tmpDir, safe), content, 0o600); werr != nil {
			log.Println("pocloader: write temp template failed:", name, werr)
		}
	}
	if err := pl.Load(tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return nil, err
	}
	return pl, nil
}

type PocLoader struct {
	NucleiEngine *nuclei.NucleiEngine

	// tmpDir 内存物化的临时模板目录，Close 时清理
	tmpDir string
}

func (ins *PocLoader) Load(customTemplatePath string) error {
	if customTemplatePath == "" {
		return errors.New("customTemplatePath not found")
	}
	templateSources := nuclei.TemplateSources{Templates: []string{customTemplatePath}}
	ne, err := nuclei.NewNucleiEngineCtx(context.Background(), nuclei.WithTemplatesOrWorkflows(templateSources))
	if err != nil {
		return err
	}
	err = ne.LoadAllTemplates()
	if err != nil {
		// 部分模板加载失败不终止，只要存在可用模板即可继续
		log.Printf("pocloader: 部分模板加载失败: %v", err)
	}
	if len(ne.GetTemplates()) == 0 {
		ne.Close()
		return errors.New("没有可用的 nuclei 模板")
	}
	ins.NucleiEngine = ne
	return nil
}

// Close 释放 nuclei 引擎资源，并清理物化的临时模板目录
func (ins *PocLoader) Close() {
	if ins.NucleiEngine != nil {
		ins.NucleiEngine.Close()
	}
	if ins.tmpDir != "" {
		os.RemoveAll(ins.tmpDir)
		ins.tmpDir = ""
	}
}

func (ins *PocLoader) Http() error {
	for _, tp := range ins.NucleiEngine.GetTemplates() {
		log.Println(tp.Info.Name)
		log.Printf("tp.Variables >>> %+v\n", tp.Variables)
		log.Printf("tp.RequestsCode >>> %+v\n", tp.RequestsCode)
		log.Printf("tp.RequestsHTTP >>> %+v\n", tp.RequestsHTTP)

		for _, req := range tp.RequestsHTTP {
			log.Printf("req >>> %+v\n", req)
		}
		break
	}
	return nil
}
