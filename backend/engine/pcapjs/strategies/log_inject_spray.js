// 日志行为策略：注入/XSS 载荷喷洒
// 同一 IP 的多个 URI 经解码后命中 libinjection SQLi 指纹或 XSS 特征，
// 达到阈值即认为该 IP 在做注入探测（而非偶发单条）。
var INFO = {
  name: "注入载荷喷洒",
  desc: "同一 IP 在多个 URI 中投放 SQL 注入/XSS 载荷",
  type: "attack",
  phase: "注入探测",
  author: "btab",
  input: "log",
};

var XSS_RE = /<\s*script|javascript:|on\w+\s*=|<\s*(img|svg|iframe)|%3c|%253c/i;
var SQLI_RE = /('|%27|"|%22|--|%2d%2d|\/\*|%2f%2a|union|%20or%20|%20and%20|sleep\(|benchmark\(|waitfor|select%20|%20select)/i;

function process(log, util) {
  var events = [];
  var rows = log.query("url~.|*", ["no", "ip", "url", "status", "time"]);
  var byIp = {};
  rows.forEach(function (r) {
    var raw = r.url || "";
    var dec = util.urlDecode(raw);
    var isSqli = util.sqli(dec) !== "" || SQLI_RE.test(raw);
    var isXss = XSS_RE.test(raw) || XSS_RE.test(dec);
    if (!isSqli && !isXss) return;
    var ip = r.ip || "";
    var e = byIp[ip] || (byIp[ip] = { sqli: 0, xss: 0, examples: [] });
    if (isSqli) e.sqli++;
    if (isXss) e.xss++;
    if (e.examples.length < 3) e.examples.push((r.method || "GET") + " " + raw);
    byIp[ip] = e;
  });
  Object.keys(byIp).forEach(function (ip) {
    var e = byIp[ip];
    if (e.sqli + e.xss < 5) return;
    var kinds = [];
    if (e.sqli >= 5) kinds.push("SQL注入 " + e.sqli + " 次");
    if (e.xss >= 5) kinds.push("XSS " + e.xss + " 次");
    events.push({
      name: "疑似注入载荷喷洒",
      desc: "IP " + ip + " 在 URI 中投放 " + kinds.join("、") + "，示例：" + e.examples.join(" ; "),
      severity: "high",
      status: true,
      src: [ip],
      dst: [],
    });
  });
  return events;
}
