package bash

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// 常见 bash 混淆的静态还原：引号拼接、变量截断、转义、内嵌编码、命令替换展开
var (
	reAnsiCQuote   = regexp.MustCompile(`\$'((?:[^'\\]|\\.)*)'`)
	reHexEsc       = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reOctalEsc     = regexp.MustCompile(`\\([0-7]{1,3})`)
	reSimpleEsc    = regexp.MustCompile(`\\([^x0-7\\'"$\s])`)
	reQuoteJoin    = regexp.MustCompile(`'([^']*)'|"([^"]*)"|'('|"")`)
	reConcatEmpty  = regexp.MustCompile(`''|""`)
	reVarIFS       = regexp.MustCompile(`\$\{?(?:IFS|IFS[0-9]+|PS[0-9]+|HOME|PATH|PWD|OLDPWD|SHELL|TERM|HOSTNAME|LANG|UID|EUID|RANDOM|SECONDS|LINENO|SHLVL|_)\}?`)
	reVarSub       = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-=+?#]?\d*:?\d*|#+|%+|/+[^}]*|,+\^*\^*)?\}`)
	reVarPlain     = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*|\$[@#?!*$-]|\$[0-9]`)
	reSubshell     = regexp.MustCompile("`[^`]*`")
	reCmdSubst     = regexp.MustCompile(`\$\(([^()]*)\)`)
	reBrace        = regexp.MustCompile(`\{[^{}]*,[^{}]*\}`)
	reLongBase64   = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	reEchoB64Pipe  = regexp.MustCompile(`(?i)echo\s+["']?([A-Za-z0-9+/=]{16,})["']?\s*\|\s*(?:base64|openssl\s+enc|busybox\s+base64)\s+(?:-[dD]|--decode)`)
	rePrintfHex    = regexp.MustCompile(`(?i)printf\s+['"]([^'"]*(?:\\x[0-9a-fA-F]{2})+[^'"]*)['"]`)
	reHexString    = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}[\s:]+){6,}`)
	reB64PipeShell = regexp.MustCompile(`(?i)base64\s+(?:-[dD]|--decode)[^|]*\|\s*(?:ba)?sh`)
)

// deobfuscate 对一条命令做静态还原，返回还原后的文本 + 还原步骤
func deobfuscate(input string) (string, []string) {
	var steps []string
	s := strings.TrimSpace(input)

	apply := func(name string, f func(string) string) {
		if ns := f(s); ns != s {
			s = ns
			steps = append(steps, name)
		}
	}

	apply("ansi-c-quote", func(v string) string {
		return reAnsiCQuote.ReplaceAllStringFunc(v, func(m string) string {
			inner := m[2 : len(m)-1]
			inner = reHexEsc.ReplaceAllStringFunc(inner, func(h string) string {
				var b int
				fmt.Sscanf(h[2:], "%x", &b)
				return string([]byte{byte(b)})
			})
			inner = reOctalEsc.ReplaceAllStringFunc(inner, func(o string) string {
				var b int
				fmt.Sscanf(o[1:], "%o", &b)
				return string([]byte{byte(b)})
			})
			return inner
		})
	})
	apply("hex-escape", func(v string) string {
		return reHexEsc.ReplaceAllStringFunc(v, func(h string) string {
			var b int
			fmt.Sscanf(h[2:], "%x", &b)
			return string([]byte{byte(b)})
		})
	})
	apply("escape-remove", func(v string) string {
		// 去掉单词内部的转义反斜杠与续行反斜杠
		v = strings.ReplaceAll(v, "\\\n", "")
		return reSimpleEsc.ReplaceAllString(v, "$1")
	})
	apply("empty-quote", func(v string) string {
		return reConcatEmpty.ReplaceAllString(v, "")
	})
	apply("quote-remove", func(v string) string {
		return reQuoteJoin.ReplaceAllStringFunc(v, func(m string) string {
			if g := reQuoteJoin.FindStringSubmatch(m); len(g) > 2 && (g[1] != "" || g[2] != "") {
				if g[1] != "" {
					return g[1]
				}
				return g[2]
			}
			return ""
		})
	})
	apply("var-subst", func(v string) string {
		v = reVarIFS.ReplaceAllString(v, " ")
		v = reVarSub.ReplaceAllStringFunc(v, func(m string) string {
			// ${var:...} 等复杂展开无法静态求值，置空格防粘连
			return " "
		})
		return reVarPlain.ReplaceAllString(v, " ")
	})
	apply("cmd-subst", func(v string) string {
		// `cmd` 与 $(cmd) 保留内部命令内容继续检测
		v = reSubshell.ReplaceAllStringFunc(v, func(m string) string {
			return " " + m[1:len(m)-1] + " "
		})
		prev := ""
		for prev != v {
			prev = v
			v = reCmdSubst.ReplaceAllString(v, " $1 ")
		}
		return v
	})
	apply("brace-expand", func(v string) string {
		return reBrace.ReplaceAllStringFunc(v, func(m string) string {
			inner := strings.Split(strings.Trim(m, "{}"), ",")
			return " " + strings.Join(inner, " ") + " "
		})
	})
	apply("echo-b64-pipe", func(v string) string {
		return reEchoB64Pipe.ReplaceAllStringFunc(v, func(m string) string {
			g := reEchoB64Pipe.FindStringSubmatch(m)
			if len(g) < 2 {
				return m
			}
			if raw, err := base64DecodeLoose(g[1]); err == nil {
				steps = append(steps, "base64:"+preview(string(raw), 40))
				return " " + string(raw) + " "
			}
			return m
		})
	})
	apply("long-base64", func(v string) string {
		return reLongBase64.ReplaceAllStringFunc(v, func(m string) string {
			if raw, err := base64DecodeLoose(m); err == nil && looksLikeCmd(raw) {
				steps = append(steps, "base64:"+preview(string(raw), 40))
				return " " + string(raw) + " "
			}
			return m
		})
	})
	apply("hex-string", func(v string) string {
		return reHexString.ReplaceAllStringFunc(v, func(m string) string {
			h := strings.NewReplacer(`\x`, "", "0x", "", ":", "", " ", "").Replace(m)
			if raw, err := hex.DecodeString(h); err == nil && looksLikeCmd(raw) {
				return " " + string(raw) + " "
			}
			return m
		})
	})
	apply("printf-hex", func(v string) string {
		return rePrintfHex.ReplaceAllStringFunc(v, func(m string) string {
			g := rePrintfHex.FindStringSubmatch(m)
			if len(g) < 2 {
				return m
			}
			out := reHexEsc.ReplaceAllStringFunc(g[1], func(h string) string {
				var b int
				fmt.Sscanf(h[2:], "%x", &b)
				return string([]byte{byte(b)})
			})
			return " " + out + " "
		})
	})

	return s, steps
}

// base64DecodeLoose 宽松 base64 解码（忽略空白）
func base64DecodeLoose(s string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(compact); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not base64")
}

// looksLikeCmd 判断解码结果是否像一条命令
func looksLikeCmd(b []byte) bool {
	if len(b) == 0 || len(b) > 4096 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	if float64(printable)/float64(len(b)) < 0.9 {
		return false
	}
	s := string(b)
	for _, kw := range []string{
		" ", "/", "|", ";", "sh", "bash", "curl", "wget", "nc", "echo", "cat", "chmod",
		"python", "perl", "eval", "exec", "sudo", "cd", "ls", "rm", "mk", ">",
	} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func preview(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
