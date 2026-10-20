// 日志行为策略：目录/路径爆破
// 同一 IP 命中 >=30 个返回 404/403/301 的不同路径，或 >=100 次请求中 4xx 占比过半。
var INFO = {
  name: "目录爆破",
  desc: "同一 IP 在短时间内探测大量不存在的路径（4xx 密集）",
  type: "attack",
  phase: "目录探测",
  author: "btab",
  input: "log",
};

function process(log, util) {
  var events = [];
  var rows = log.query("", ["no", "ip", "path", "url", "status", "time", "ua"]);
  var byIp = {};
  rows.forEach(function (r) {
    var ip = r.ip || "";
    var e = byIp[ip] || (byIp[ip] = { total: 0, err: 0, paths: {}, first: r, ua: r.ua || "" });
    e.total++;
    var st = +r.status || 0;
    if (st >= 400 && st < 500) {
      e.err++;
      var p = (r.path || r.url || "").split("?")[0];
      if (p) e.paths[p] = true;
    }
  });
  Object.keys(byIp).forEach(function (ip) {
    var e = byIp[ip];
    var distinct = Object.keys(e.paths).length;
    var hit = distinct >= 30 || (e.total >= 100 && e.err / e.total >= 0.5);
    if (!hit) return;
    var uaDesc = e.ua ? "，UA " + e.ua : "";
    events.push({
      name: "疑似目录爆破/路径扫描",
      desc: "IP " + ip + " 共 " + e.total + " 次请求，其中 " + e.err + " 次返回 4xx，命中 " + distinct + " 个不同路径" + uaDesc,
      severity: e.err / Math.max(e.total, 1) >= 0.5 ? "high" : "medium",
      status: true,
      src: [ip],
      dst: [],
    });
  });
  return events;
}
