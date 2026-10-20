// 日志行为策略：敏感文件/配置探测
// 访问 .git/.env/备份压缩包/数据库导出/源码泄露 等敏感路径。
var INFO = {
  name: "敏感文件探测",
  desc: "请求 .git/.env/.svn/备份压缩包/SQL 导出等敏感路径",
  type: "attack",
  phase: "信息探测",
  author: "btab",
  input: "log",
};

var SENSITIVE = /\/\.git(\/|$)|\/\.svn|\/\.hg|\/\.env|\/\.htpasswd|\/\.DS_Store|\/web\.config|\/wp-config|\.(sql|bak|old|swp|swo|tar|tar\.gz|tgz|zip|rar|7z|dump|backup|log|ini|conf|config|yml|yaml|pem|key)(\?|$)|phpinfo|info\.php|test\.php|install\.php|setup\.php|composer\.(json|lock)|package\.json|docker-compose|id_rsa|\.ssh|server-status|nginx_status|actuator|swagger|api-docs|\.well-known\/(?!acme-challenge)/i;

function process(log, util) {
  var events = [];
  var rows = log.query("", ["no", "ip", "method", "url", "path", "status", "time"]);
  var hits = {};
  rows.forEach(function (r) {
    var p = r.path || r.url || "";
    if (!SENSITIVE.test(p)) return;
    var ip = r.ip || "";
    var e = hits[ip] || (hits[ip] = { cnt: 0, ok: 0, examples: [] });
    e.cnt++;
    var st = +r.status || 0;
    if (st >= 200 && st < 400) e.ok++;
    if (e.examples.length < 5) e.examples.push((r.method || "GET") + " " + (r.url || p) + " -> " + (r.status || ""));
  });
  Object.keys(hits).forEach(function (ip) {
    var e = hits[ip];
    var sev = e.ok > 0 ? "high" : "medium";
    events.push({
      name: "敏感文件/路径探测",
      desc: "IP " + ip + " 请求敏感路径 " + e.cnt + " 次，其中 " + e.ok + " 次成功返回，示例：" + e.examples.join(" ; "),
      severity: sev,
      status: true,
      src: [ip],
      dst: [],
    });
  });
  return events;
}
