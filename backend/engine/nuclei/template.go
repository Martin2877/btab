// Package nuclei 实现 nuclei 模板的解析器以及基于模板的流量包检测引擎。
//
// 与 nuclei 本身“主动发包”不同，这里是“被动匹配”：
// 对 tshark 解析出的 HTTP 请求/响应（Exchange），先判断请求是否符合模板中的请求定义
// （method / path / raw / headers / body），再用模板中的 matchers 校验响应，
// 两者同时满足即认为 pcap 中存在该模板对应的攻击或漏洞暴露。
package nuclei

import (
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// StrList 兼容 yaml 中“单个字符串”与“字符串列表”两种写法
type StrList []string

func (s *StrList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = StrList{n.Value}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			*s = append(*s, c.Value)
		}
	default:
		return fmt.Errorf("line %d: expect string or list", n.Line)
	}
	return nil
}

// IntList 兼容单个整数与整数列表
type IntList []int

func (s *IntList) UnmarshalYAML(n *yaml.Node) error {
	var one int
	if n.Kind == yaml.ScalarNode {
		if err := n.Decode(&one); err != nil {
			return err
		}
		*s = IntList{one}
		return nil
	}
	var many []int
	if err := n.Decode(&many); err != nil {
		return err
	}
	*s = many
	return nil
}

type Info struct {
	Name           string                 `yaml:"name" json:"name"`
	Author         StrList                `yaml:"author" json:"author,omitempty"`
	Severity       string                 `yaml:"severity" json:"severity"`
	Description    string                 `yaml:"description" json:"description,omitempty"`
	Reference      StrList                `yaml:"reference" json:"reference,omitempty"`
	Tags           StrList                `yaml:"tags" json:"tags,omitempty"`
	Classification map[string]interface{} `yaml:"classification" json:"classification,omitempty"`
	Metadata       map[string]interface{} `yaml:"metadata" json:"metadata,omitempty"`
}

// Matcher 对应 nuclei 的 matchers 条目
type Matcher struct {
	Type            string  `yaml:"type"`
	Part            string  `yaml:"part"`
	Name            string  `yaml:"name"`
	Condition       string  `yaml:"condition"`
	Negative        bool    `yaml:"negative"`
	Internal        bool    `yaml:"internal"`
	CaseInsensitive bool    `yaml:"case-insensitive"`
	Words           StrList `yaml:"words"`
	Regex           StrList `yaml:"regex"`
	Xpath           StrList `yaml:"xpath"`
	Attribute       string  `yaml:"attribute"`
	Status          IntList `yaml:"status"`
	Size            IntList `yaml:"size"`
	Binary          StrList `yaml:"binary"`
	DSL             StrList `yaml:"dsl"`
	Encoding        string  `yaml:"encoding"`

	compiled *compiledMatcher
}

// Extractor 对应 nuclei 的 extractors 条目
type Extractor struct {
	Type      string  `yaml:"type"`
	Part      string  `yaml:"part"`
	Name      string  `yaml:"name"`
	Group     int     `yaml:"group"`
	Regex     StrList `yaml:"regex"`
	Xpath     StrList `yaml:"xpath"`
	Attribute string  `yaml:"attribute"`
	KVal      StrList `yaml:"kval"`
	JSON      StrList `yaml:"json"`
	Internal  bool    `yaml:"internal"`

	compiled *compiledExtractor
}

// HTTPRequest 对应模板 http（旧版 requests）下的一个请求块
type HTTPRequest struct {
	ID                string            `yaml:"id"`
	Method            string            `yaml:"method"`
	Path              StrList           `yaml:"path"`
	Raw               StrList           `yaml:"raw"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []*Matcher        `yaml:"matchers"`
	Extractors        []*Extractor      `yaml:"extractors"`
	StopAtFirstMatch  bool              `yaml:"stop-at-first-match"`
	// Payloads 变量名 -> 取值列表（内联）或字典文件路径（字符串）
	Payloads map[string]interface{} `yaml:"payloads"`
	// Attack batteringram | pitchfork | clusterbomb（默认）
	Attack string `yaml:"attack"`

	specs []*reqSpec
}

// Template nuclei 模板
type Template struct {
	ID   string        `yaml:"id" json:"id"`
	Info Info          `yaml:"info" json:"info"`
	HTTP []HTTPRequest `yaml:"http"`
	// 旧版写法
	Requests []HTTPRequest `yaml:"requests"`
	// Variables 模板级变量
	Variables map[string]interface{} `yaml:"variables"`

	// File 来源文件名
	File string `json:"file,omitempty"`
	// Refs 模板引用的外部字典文件；MissingRefs 为其中无法解析的部分
	Refs        []string `json:"refs,omitempty"`
	MissingRefs []string `json:"missing_refs,omitempty"`
	// Unsupported 模板中存在但本引擎不处理的协议块（dns/tcp/file/headless/...）
	Unsupported []string `json:"unsupported,omitempty"`
}

var otherProtocols = []string{"dns", "tcp", "network", "file", "ssl", "websocket", "whois", "code", "javascript", "headless", "workflows", "flow"}

// ParseTemplate 解析单个 nuclei 模板，并编译其中的请求/匹配规则
func ParseTemplate(name string, data []byte) (*Template, error) {
	return ParseTemplateOpts(name, data, nil)
}

// ParseTemplateOpts 解析并编译模板；opts 可提供字典读取与 payload 展开配置
func ParseTemplateOpts(name string, data []byte, opts *ParseOptions) (*Template, error) {
	if opts == nil {
		opts = &ParseOptions{}
	}
	t := &Template{File: name}
	if err := yaml.Unmarshal(data, t); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var top map[string]interface{}
	_ = yaml.Unmarshal(data, &top)
	for _, k := range otherProtocols {
		if _, ok := top[k]; ok {
			t.Unsupported = append(t.Unsupported, k)
		}
	}
	if t.ID == "" {
		t.ID = strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
	}
	if t.Info.Name == "" {
		t.Info.Name = t.ID
	}
	t.Info.Severity = strings.ToLower(t.Info.Severity)
	if t.Info.Severity == "" {
		t.Info.Severity = "info"
	}
	var tags StrList
	for _, tg := range t.Info.Tags {
		for _, p := range strings.Split(tg, ",") {
			if p = strings.TrimSpace(p); p != "" {
				tags = append(tags, p)
			}
		}
	}
	t.Info.Tags = tags
	t.HTTP = append(t.HTTP, t.Requests...)
	t.Requests = nil
	if len(t.HTTP) == 0 {
		return nil, fmt.Errorf("%s: 模板不包含 http 请求块（不支持的协议: %v）", name, t.Unsupported)
	}
	for i := range t.HTTP {
		if err := t.HTTP[i].compile(t, opts); err != nil {
			return nil, fmt.Errorf("%s: http[%d]: %w", name, i, err)
		}
	}
	return t, nil
}

func (r *HTTPRequest) compile(t *Template, opts *ParseOptions) error {
	for _, m := range r.Matchers {
		c, err := compileMatcher(m)
		if err != nil {
			return err
		}
		m.compiled = c
	}
	for _, e := range r.Extractors {
		c, err := compileExtractor(e)
		if err != nil {
			return err
		}
		e.compiled = c
	}
	specs, err := buildSpecs(r, r.combos(t, opts))
	if err != nil {
		return err
	}
	r.specs = specs
	return nil
}
