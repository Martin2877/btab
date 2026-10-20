package sqli

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/libinjection-go"
)

// sqlSig 危险 SQL 结构签名：libinjection 词法指纹覆盖引号/注释逃逸类载荷，
// 对无引号的危险语句（xp_cmdshell、waitfor delay、benchmark、堆叠 DDL 等）
// 覆盖不足，由签名按结构特征补充。规则均为 SQL 特有结构，控制误报。
type sqlSig struct {
	name string
	re   *regexp.Regexp
}

var sqlSignatures = []sqlSig{
	{"联合查询", regexp.MustCompile(`(?i)\bunion\b[\s(/*]*\b(?:all[\s(/*]+)?select\b`)},
	{"恒真条件", regexp.MustCompile(`(?i)\b(?:or|and|having)\s+[\w.'"]+\s*(?:[<>]=?|!?=|between|like)\s*[\w.'"%]+|\b(?:or|and|having)\s+[\w.'"]+\s+is\s+(?:not\s+)?null\b|['"]\s*(?:or|and)\s*\(|\b(?:or|and)\s+\(|\)\s*(?:or|and)\s*\(|\b(?:or|and)\s+[\w.'"]+\s*(?:/\*|--|#)`)},
	{"引号逃逸堆叠", regexp.MustCompile(`(?i)['"]\s*(?:union|select\s+\w+\s+from|insert\s+into|update\s+\w+|delete\s+from|drop\s+table|create\s+\w+|alter\s+table|grant|exec(?:ute)?|declare)\b`)},
	{"子查询", regexp.MustCompile(`(?i)\bselect\s+(?:\*|top\s+\d+|count\s*\([^)]*\)|[\w.@$#]+)\s+from\b|\bselect\s+top\s+\d+\b`)},
	{"分号堆叠语句", regexp.MustCompile(`(?i);\s*(?:select\s+(?:\S+\s+from\b|\*)|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b|drop\s+(?:table|database)\b|create\s+(?:table|user|view|procedure|function|index|or\s+replace)\b|alter\s+table\b|grant\b|revoke\b|exec(?:ute)?\b|backup\b|truncate\b|declare\b|shutdown\b)`)},
	{"扩展存储过程", regexp.MustCompile(`(?i)\b(?:xp_cmdshell|xp_regread|xp_dirtree|xp_fileexist|xp_enumgroups|sp_addlogin|sp_addsrvrolemember|sp_oacreate|sp_makewebtask|openrowset|opendatasource)\b`)},
	{"延时注入", regexp.MustCompile(`(?i)\b(?:waitfor\s+delay|benchmark\s*\(|pg_sleep\s*\(|dbms_pipe\.receive_message\s*\(|sleep\s*\(\s*[\w.]+)`)},
	{"报错注入函数", regexp.MustCompile(`(?i)\b(?:updatexml|extractvalue|floor\s*\(\s*rand|exp\s*\(\s*~|elt\s*\(|gtid_subset|name_const|make_set|json_keys|polygon\s*\(|linestring\s*\()\s*\(`)},
	{"库信息探测", regexp.MustCompile(`(?i)(?:@@\w+|\bversion\s*\(\s*\)|\bdatabase\s*\(\s*\)|\bschema\s*\(\s*\)|\buser\s*\(\s*\)|\bcurrent_user\b|\bsystem_user\b|\bsession_user\b|\binformation_schema\b|\bsys(?:objects|databases|users|tables)\b)`)},
	{"带外通道", regexp.MustCompile(`(?i)\b(?:utl_http|utl_inaddr|utl_file|utl_smtp|dbms_ldap|dbms_lock|ctxsys)\b`)},
	{"文件读写", regexp.MustCompile(`(?i)\b(?:load_file\s*\(|into\s+(?:out|dump)file|bulk\s+insert)\b`)},
	{"数据库备份", regexp.MustCompile(`(?i)\bbackup\s+(?:database|log)\b`)},
	{"动态SQL", regexp.MustCompile(`(?i)\b(?:exec(?:ute)?\s+immediate|declare\s+@\w+|prepare\s+\w+\s+from|execute\s+\w+\s+using|exec(?:ute)?\s*\(\s*@\w+\s*\))`)},
	{"MSSQL主库执行", regexp.MustCompile(`(?i)\bexec(?:ute)?\s+(?:master\s*\.\s*\.\s*|dbo\s*\.\s*)?(?:xp_|sp_)`)},
	{"DDL语句", regexp.MustCompile(`(?i)\b(?:create|drop|alter|truncate)\s+(?:table|database|login|or\s+replace\s+(?:view|procedure|function))\b`)},
	{"Oracle授权", regexp.MustCompile(`(?i)\bidentified\s+by\b|\bgrant\s+\w+\s+to\b`)},
	{"连接符注入", regexp.MustCompile(`\|\|\s*'?[\w(]`)},
	{"引号探测", regexp.MustCompile(`^['"]+$|\d'[^'\s]|'\s*(?:or|and)\s+\d|[\w)]'\s*$|^['"][\w]+$`)},
}

var hexTokenRe = regexp.MustCompile(`0x[0-9a-fA-F]{8,}`)

func clipSig(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// candidates 归一化候选：原文、URL 解码（最多两层）、去 /**/ 注释混淆、
// 0x hex 解码（含 UTF-16 的 \0 清理）、\xHH 转义还原
func candidates(content string) []string {
	set := map[string]struct{}{content: {}}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = struct{}{}
		}
	}
	for c := content; ; {
		d, err := url.QueryUnescape(c)
		if err != nil || d == c {
			break
		}
		add(d)
		c = d
	}
	for _, m := range hexTokenRe.FindAllString(content, 4) {
		if b, err := hex.DecodeString(m[2:]); err == nil {
			add(string(b))
			add(strings.ReplaceAll(string(b), "\x00", ""))
		}
	}
	if strings.Contains(content, `\x`) {
		add(hexEscRe.ReplaceAllStringFunc(content, func(m string) string {
			if v, err := strconv.ParseUint(m[2:], 16, 8); err == nil {
				return string(rune(v))
			}
			return m
		}))
	}
	base := make([]string, 0, len(set))
	for s := range set {
		base = append(base, s)
	}
	for _, s := range base {
		if t := strings.ReplaceAll(s, "/**/", ""); t != s {
			add(t)
		}
		if t := strings.ReplaceAll(s, "/**/", " "); t != s {
			add(t)
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}

var hexEscRe = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

// Check 单值 SQL 注入检测：先走 libinjection 词法指纹，未命中再按危险 SQL 结构签名补充；
// 对 URL 编码、/**/ 注释混淆、0x hex、\xHH 编码做归一化后复测。
// 返回是否命中及命中说明（词法指纹或签名名+命中片段）。
func Check(content string) (bool, string) {
	for _, cand := range candidates(content) {
		decoded := cand != content
		if found, fp := libinjection.IsSQLi(cand); found {
			return true, fmt.Sprintf("词法指纹【%s】%s", fp, decodedTag(decoded))
		}
		for _, s := range sqlSignatures {
			if m := s.re.FindString(cand); m != "" {
				return true, fmt.Sprintf("特征【%s】命中【%s】%s", s.name, clipSig(m, 60), decodedTag(decoded))
			}
		}
	}
	return false, ""
}

func decodedTag(b bool) string {
	if b {
		return "（解码归一后命中）"
	}
	return ""
}
