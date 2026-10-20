package bash

import "regexp"

// rule 危险命令规则：正则命中即加 weight 分
type rule struct {
	Name    string
	Pattern *regexp.Regexp
	Weight  int
}

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

var rules = []rule{
	// ====== 反弹 shell / 命令执行 ======
	{"rev.devtcp", re(`/dev/(?:tcp|udp)/`), 8},
	{"rev.nc.exec", re(`(?i)\bnc(?:at)?\b[^|;&\n]*\s-(?:e|c)\b|\bnc\b[^|;&\n]*-e\b`), 8},
	{"rev.bash_i", re(`\b(?:ba|z|k)?sh\b\s+-i\b|\bbash\s+-i\b`), 8},
	{"rev.mkfifo", re(`mkfifo[^|;&\n]*\|[^|;&\n]*nc|nc[^|;&\n]*\|[^|;&\n]*(?:ba)?sh`), 8},
	{"rev.socat", re(`(?i)\bsocat\b[^|;&\n]*(?:exec|pty|tcp)`), 7},
	{"rev.telnet", re(`\btelnet\b[^|;&\n]*\|[^|;&\n]*(?:ba)?sh`), 7},
	{"rev.fd", re(`(?:>&|0<|2>&)\s*/dev/(?:tcp|udp)`), 8},
	{"rev.awk", re(`(?i)awk\s+'[^']*(?:system|inet|/inet/)`), 6},
	{"rev.python", re(`(?i)python[23]?\s+-c\s+["'][^"']*(?:socket|subprocess|pty|os\.dup2)`), 8},
	{"rev.perl", re(`(?i)perl\s+-e\s+["'][^"']*(?:socket|IO::Socket)`), 8},
	{"rev.php", re(`(?i)php\s+-r\s+["'][^"']*(?:fsockopen|exec|system|shell_exec)`), 8},
	{"rev.ruby", re(`(?i)ruby\s+-r?socket\s+-e`), 7},
	{"rev.xterm", re(`(?i)xterm\s+-display|xterm.*-e\s+(?:ba)?sh`), 6},

	// ====== 下载并执行 ======
	{"dl.pipe.sh", re(`(?i)(?:curl|wget|fetch|lwp-download|GET)\b[^|;&\n]*\|\s*(?:ba|z|k)?sh\b`), 8},
	{"dl.pipe.sh2", re(`(?i)(?:curl|wget)\b[^|;&\n]*(?:-O|-o)\s+\S*[^|;&\n]*(?:&&|;|\|)[^|;&\n]*(?:chmod\s+\+?x|(?:ba)?sh|exec)`), 5},
	{"dl.b64pipe", re(`(?i)base64\s+(?:-[dD]|--decode)[^|;&\n]*\|\s*(?:ba|z|k)?sh`), 8},
	{"dl.evalsubst", re(`\beval\s+["']?\$\(`), 7},

	// ====== 高危操作 ======
	{"op.rmrf", re(`\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/`), 7},
	{"op.shadow", re(`/etc/(?:passwd|shadow|sudoers|crontab)|authorized_keys`), 6},
	{"op.suid", re(`chmod\s+(?:u\+s|[0-7]*[467][0-7]{3})\b`), 6},
	{"op.chmod777", re(`chmod\s+(?:777|a\+rwx|\+x)\b`), 4},
	{"op.useradd", re(`\b(?:useradd|adduser|usermod|passwd\b|chpasswd)\b`), 5},
	{"op.iptables", re(`\biptables\s+-F|\biptables\s+-P\s+\w+\s+ACCEPT|\b(?:ufw|firewall-cmd)\s+(?:disable|off)`), 5},
	{"op.service", re(`\b(?:systemctl|service)\s+(?:stop|disable|mask)\b|\bkillall\b|\bpkill\b`), 4},
	{"op.disk", re(`\b(?:dd\s+if|mkfs\.|fdisk|shred|wipefs|>\s*/dev/sd[a-z])`), 7},
	{"op.history", re(`\b(?:history\s+-c|unset\s+HISTFILE|export\s+HISTFILE|export\s+HISTSIZE=0|ln\s+-sf\s+/dev/null\s+~?/?\.bash_history)`), 5},
	{"op.cron", re(`\bcrontab\b|/etc/cron\.|/var/spool/cron`), 5},
	{"op.logclear", re(`>\s*/var/log/|rm\s+[^|;&\n]*/var/log/|\.bash_history|wtmp|btmp|lastlog`), 5},
	{"op.proc", re(`/proc/(?:self|\d+)/(?:maps|mem|exe)|ptrace`), 5},
	{"op.chattr", re(`\bchattr\s+[+-]?i`), 5},
	{"op.mount", re(`\bmount\s+(?:-o\s+remount|/dev/)`), 4},
	{"op.insmod", re(`\b(?:insmod|modprobe|rmmod|sysctl\s+-w)\b`), 6},

	// ====== 信息探测（低权重）======
	{"recon.id", re(`\b(?:whoami|id|hostname|uname|ifconfig|ip\s+addr|netstat|ss\s+-|ps\s+aux|w\b|last\b|env\b|printenv|pwd\b|lscpu|free\b|df\s+-h|arp\b|route\b|cat\s+/proc/version|lsb_release)\b`), 2},
	{"recon.find", re(`\bfind\s+[^|;&\n]*(?:-perm|-name\s+[^|;&\n]*key|/etc/)`), 3},
	{"recon.ssh", re(`\.ssh/|id_rsa|known_hosts|/etc/hosts\.|resolv\.conf`), 3},
	{"recon.sudo", re(`\bsudo\s+-l|\bsudo\s+\S+`), 2},

	// ====== 通用执行特征 ======
	{"exec.eval", re(`\beval\b|\bexec\b`), 3},
	{"exec.source", re(`(?i)(?:^|\s)(?:source|\.)\s+/?\S*\.sh`), 3},
	{"exec.python_c", re(`(?i)\b(?:python[23]?|perl|ruby|php|node|ruby)\s+-[ce]\s`), 4},
	{"exec.encoded_cmd", re(`(?i)\b(?:base64|openssl\s+enc)\b`), 2},
	{"exec.nohup", re(`\b(?:nohup|setsid|disown|screen\s+-|tmux\s+new)\b`), 3},
}

// 判为危险的分数阈值
const bashScoreThreshold = 5

func scoreCmd(s string) (int, []string) {
	score := 0
	var hits []string
	for _, r := range rules {
		if r.Pattern.MatchString(s) {
			score += r.Weight
			hits = append(hits, r.Name)
		}
	}
	return score, hits
}
