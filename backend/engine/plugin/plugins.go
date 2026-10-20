package plugin

import (
	"context"
	"errors"
)

type Plugins struct {
	Plugin Plugin `json:"plugin"`
}

func NewPlugin(name string) (*Plugins, error) {
	pgs := new(Plugins)
	factory, ok := MapPluginGlb[name]
	if ok {
		pgs.Plugin = factory()
		return pgs, nil
	}
	return nil, errors.New("找不到相应插件")
}

func (ins *Plugins) Init(plugin string) error {
	factory, ok := MapPluginGlb[plugin]
	if ok {
		ins.Plugin = factory()
		return nil
	}
	return errors.New("找不到相应插件")
}

func (ins *Plugins) Run(ctx context.Context, payloads map[string]string) error {
	// 先重置插件状态，再设置参数
	ins.Plugin.Init()
	for k, v := range payloads {
		ins.Plugin.Set(k, v)
	}
	if err := ins.Plugin.Check(); err != nil {
		return err
	}
	// 在独立 goroutine 中执行，使 ctx 超时真正生效
	done := make(chan error, 1)
	go func() {
		done <- ins.Plugin.Exec()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errors.New("plugin process timed out")
	}
}
