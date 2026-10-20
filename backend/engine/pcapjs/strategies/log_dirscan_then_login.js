// 日志行为策略：目录爆破 -> 后台登录
// 同一来源先产生大量 4xx/重定向的路径探测（>=30 个不同路径），随后成功（2xx/3xx）
// 访问登录/后台路径 —— 典型打点：先跑目录扫描器、拿到后台入口后登录。
var INFO = {
  name: "目录爆破后登录后台",
  desc: "同一 IP 先大量探测不存在/被拒绝的路径，随后成功访问登录或后台页面",
  type: "attack",
  phase: "探测->登录",
  author: "btab",
  input: "log",
};

var LOGIN_PATH = /login|admin|signin|manager|console|dashboard|wp-login|user_login|auth|backend|cpanel/i;

function process(log, util) {
  var events = [];
  var rows = log.query("", ["no", "ip", "method", "url", "path", "status", "time"]);
  var byIp = {};
  rows.forEach(function (r) {
    var ip = r.ip || "";
    (byIp[ip] = byIp[ip] || []).push(r);
  });
  Object.keys(byIp).forEach(function (ip) {
    var rs = byIp[ip].sort(function (a, b) { return (+a.no || 0) - (+b.no || 0); });
    var paths = {}, bruteCnt = 0, firstBrute = null, lastBruteNo = 0;
    rs.forEach(function (r) {
      var st = +r.status || 0;
      if (st === 404 || st === 403 || st === 301) {
        var p = (r.path || r.url || "").split("?")[0];
        if (p && !paths[p]) { paths[p] = true; bruteCnt++; }
        if (!firstBrute) firstBrute = r;
        lastBruteNo = +r.no || 0;
      }
    });
    if (bruteCnt < 30) return;
    var login = null;
    rs.forEach(function (r) {
      var st = +r.status || 0, no = +r.no || 0;
      if (no <= lastBruteNo || st < 200 || st >= 400) return;
      var p = (r.path || r.url || "");
      if (LOGIN_PATH.test(p) && (!login || no < (+login.no || 0))) login = r;
    });
    if (!login) return;
    events.push({
      name: "疑似目录爆破后成功进入后台",
      desc: "IP " + ip + " 探测了 " + bruteCnt + " 个不存在/被拒绝的路径（自 " + (firstBrute.time || "") + " 起），随后于 " + (login.time || "") + " 成功访问 " + (login.method || "") + " " + (login.url || login.path || "") + "（状态 " + (login.status || "") + "）",
      severity: "critical",
      status: true,
      src: [ip],
      dst: [login.url || login.path || ""],
    });
  });
  return events;
}
