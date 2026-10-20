package webshell

import (
	"regexp"
	"strings"
)

// rule 一条特征规则：正则命中即加 weight 分
type rule struct {
	Name    string
	Lang    string // jsp/php/asp/all
	Pattern *regexp.Regexp
	Weight  int
}

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

var rules = []rule{
	// ====== 高置信度特征（命中即高度可疑）======
	{"php.eval", "php", re(`(?i)\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|pack|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|chr\s*\()`), 6},
	{"php.eval.req", "php", re(`(?i)\beval\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)`), 6},
	{"php.assert", "php", re(`(?i)\bassert\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)`), 6},
	{"php.sys.req", "php", re(`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)`), 6},
	{"php.dyncall", "php", re(`\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(`), 6},
	{"php.dyncall2", "php", re(`\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)`), 6},
	{"php.create_func", "php", re(`(?i)create_function\s*\(`), 4},
	{"php.preg_e", "php", re(`(?i)preg_replace\s*\(\s*['"].*/e['"]`), 4},
	{"php.callreq", "php", re(`(?i)(?:call_user_func(?:_array)?|array_map|array_filter|usort|register_shutdown_function|register_tick_function)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)`), 5},
	{"php.include.req", "php", re(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)`), 5},
	{"php.filewrite.req", "php", re(`(?i)(?:file_put_contents|fwrite|fputs)\s*\([^)]*\$_(?:GET|POST|REQUEST)`), 4},

	{"jsp.runtime.exec", "jsp", re(`(?i)Runtime\s*\.\s*get(?:Runtime|DeclaredMethod)|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder`), 6},
	{"jsp.defineClass", "jsp", re(`(?i)defineClass\s*\(|defineAnonymousClass|Unsafe\.|Unsafe\.theUnsafe`), 6},
	{"jsp.reflect.invoke", "jsp", re(`(?i)(?:Method|method)\s*\.\s*invoke\s*\(|getMethod\s*\([^)]*request`), 4},
	{"jsp.classloader", "jsp", re(`(?i)(?:extends\s+ClassLoader|newInstance\s*\(\s*\)\s*\.\s*equals|loadClass\s*\()`), 4},
	{"jsp.script.eval", "jsp", re(`(?i)javax\.script|ScriptEngine.*eval|new\s+java\.util\.Scanner\s*\(\s*[^)]*(?:exec|Process)`), 5},
	{"jsp.process.scanner", "jsp", re(`(?i)new\s+Scanner\s*\([^)]*(?:getInputStream|Process)`), 5},
	{"jsp.upload.echo", "jsp", re(`(?i)request\.getParameter[^;]{0,80}(?:getWriter|FileOutputStream|exec)`), 4},

	{"asp.execute", "asp", re(`(?i)\b(?:eval|execute|ExecuteGlobal|ExecScript)\s*\(?\s*request`), 6},
	{"asp.wscript", "asp", re(`(?i)WScript\.(?:Shell|Network)|CreateObject\s*\(\s*"WScript`), 5},
	{"asp.fso.shell", "asp", re(`(?i)Scripting\.FileSystemObject|Shell\.Application|ADODB\.Stream`), 3},
	{"aspx.process", "aspx", re(`(?i)Process\s*\.\s*Start|System\.Diagnostics\.Process`), 6},
	{"aspx.eval", "aspx", re(`(?i)eval\s*\(\s*Request|Request\.(?:Item|Params|Form|QueryString)[^)]{0,40}(?:eval|Execute|Process)`), 6},

	// ====== 冰蝎/哥斯拉/常见 webshell 指纹 ======
	{"fp.behinder", "all", re(`rebeyond|u\.equals\s*\(|class\s+U\s+extends\s+ClassLoader|javax\.crypto\.Cipher.*getInstance.*AES`), 6},
	{"fp.godzilla", "all", re(`(?i)xc\s*=\s*['"][0-9a-f]{16}|String\s+xc|pass.{0,20}key.{0,20}md5|payload.{0,20}changeMethod`), 5},
	{"fp.jspcode", "all", re(`(?i)<%\s*if\s*\(\s*request\.getParameter.*equals|request\.getSession\s*\(\s*\)\s*\.setAttribute`), 4},

	// ====== 中低置信度特征 ======
	{"cmd.shell", "all", re(`(?i)(/bin/(?:ba)?sh|cmd\.exe|powershell|whoami|ipconfig|ifconfig|uname\s+-a)`), 3},
	{"decode.func", "all", re(`(?i)(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|pack\s*\(\s*['"]H\*|javax\.xml\.bind\.DatatypeConverter|sun\.misc\.BASE64|Cipher\.getInstance|SecretKeySpec)`), 3},
	{"net.func", "all", re(`(?i)(fsockopen|pfsockopen|curl_exec|curl_init|new\s+Socket|Socket\s*\(|URLConnection|HttpURLConnection|openConnection)`), 3},
	{"file.func", "all", re(`(?i)(file_put_contents|file_get_contents|fopen|fwrite|move_uploaded_file|FileOutputStream|FileInputStream|RandomAccessFile|Files\.write)`), 2},
	{"req.input", "all", re(`\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|request\.getParameter|Request\.(?:Form|QueryString|Params|Item)`), 2},
	{"pass.auth", "all", re(`(?i)(md5\s*\([^)]*(?:pass|pwd|\$_)|password.*equals|\.equals\s*\(\s*(?:md5|pass))`), 2},
	{"php.errctrl", "php", re(`@(?:error_reporting|set_time_limit|ini_set|eval|assert|system|exec|shell_exec)\s*\(`), 3},
	{"php.superglobal", "php", re(`\$GLOBALS|global\s+\$|extract\s*\(\s*\$_`), 2},
	{"jsp.stream", "jsp", re(`(?i)(getReader|getInputStream|getOutputStream|getWriter|ServletInputStream)`), 1},
	{"jsp.page", "jsp", re(`<%@\s*page|pageContext\.`), 1},
	{"asp.req", "asp", re(`(?i)Request\.(?:Form|QueryString|Cookies|Item)\b|Response\.(?:Write|BinaryWrite)`), 1},
	{"php.tag", "php", re(`<\?(?:php|=)?`), 1},
	{"jsp.tag", "jsp", re(`<%[^@=]`), 1},
}

// jspHintRe <% 包裹的 Java 代码特征（Servlet API、Java 语法），
// 区分同为 <% 包裹的 ASP/VBScript 页面；<%! 声明块是 JSP 专属标记
var jspHintRe = re(`(?i)HttpServlet|Runtime\s*\.\s*getRuntime|javax\.servlet|pageContext|JspWriter|ProcessBuilder|Class\.forName|ServletRequest|out\.print|throws\s+\w*Exception`)

// detectLang 依据内容粗判脚本语言
func detectLang(content []byte) string {
	s := string(content)
	switch {
	case strings.Contains(s, "<?php") || strings.Contains(s, "<?=") || regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE)\b`).MatchString(s):
		return "php"
	case strings.Contains(s, "<%@") || strings.Contains(s, "pageContext") || strings.Contains(s, "jsp:root"):
		if regexp.MustCompile(`(?i)Language\s*=\s*["']?C#|Language\s*=\s*["']?VB|runat\s*=\s*"?server`).MatchString(s) {
			return "aspx"
		}
		return "jsp"
	case strings.Contains(s, "System.Diagnostics") || strings.Contains(s, "runat=\"server\""):
		return "aspx"
	case strings.Contains(s, "<%"):
		if strings.Contains(s, "<%!") || jspHintRe.MatchString(s) {
			return "jsp"
		}
		return "asp"
	default:
		return "all"
	}
}

// scoreResult 对一段内容按语言匹配规则打分，返回总分与命中规则名
func scoreResult(content []byte, lang string) (int, []string) {
	if lang == "" {
		lang = detectLang(content)
	}
	score := 0
	var hits []string
	for _, r := range rules {
		if r.Lang != "all" && lang != "all" && r.Lang != lang {
			continue
		}
		if r.Pattern.Match(content) {
			score += r.Weight
			hits = append(hits, r.Name)
		}
	}
	return score, hits
}
