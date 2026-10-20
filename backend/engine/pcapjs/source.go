package pcapjs

import (
	"sort"
	"strings"
	"sync"

	"github.com/Martin2877/blue-team-box/pkg/pcap"
	"github.com/tidwall/gjson"
)

// TsharkSource 基于 tshark 的数据源
type TsharkSource struct {
	File string
}

func (t *TsharkSource) Query(filter string, fields []string) ([]map[string][]string, error) {
	p := pcap.CreatePcaper()
	if err := p.Load(t.File); err != nil {
		return nil, err
	}
	p.SetFields(fields)
	raw, _, err := p.Query(filter)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var rows []map[string][]string
	for _, layer := range gjson.GetBytes(raw, "#._source.layers").Array() {
		row := map[string][]string{}
		layer.ForEach(func(k, v gjson.Result) bool {
			if v.IsArray() {
				for _, e := range v.Array() {
					row[k.String()] = append(row[k.String()], e.String())
				}
			} else {
				row[k.String()] = []string{v.String()}
			}
			return true
		})
		rows = append(rows, row)
	}
	return rows, nil
}

type cachedEntry struct {
	once sync.Once
	rows []map[string][]string
	err  error
}

// cachedSource 同一次检测内相同查询只执行一次（多策略共享）
type cachedSource struct {
	src Source
	mu  sync.Mutex
	m   map[string]*cachedEntry
}

func newCachedSource(src Source) *cachedSource {
	return &cachedSource{src: src, m: map[string]*cachedEntry{}}
}

func (c *cachedSource) Query(filter string, fields []string) ([]map[string][]string, error) {
	f := append([]string{}, fields...)
	sort.Strings(f)
	key := filter + "\x00" + strings.Join(f, ",")
	c.mu.Lock()
	e, ok := c.m[key]
	if !ok {
		e = &cachedEntry{}
		c.m[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.rows, e.err = c.src.Query(filter, fields) })
	return e.rows, e.err
}
