// 日志行为策略：可疑脚本/webshell 访问
// 1) 对可疑文件名（shell/cmd/eval/upload/常见 webshell 命名）的脚本扩展名请求成功返回；
// 2) 任意 IP 对冷门动态脚本（全日志仅被访问 <=2 次）做 POST 且返回成功。
var INFO = {
  name: "可疑脚本访问",
  desc: "访问疑似 webshell 命名或对冷门动态脚本发起 POST",
  type: "attack",
  phase: "webshell访问",
  author: "btab",
  input: "log",
};

var SCRIPT_EXT = /\.(jsp|jspx|php\d*|phtml|asp|aspx|cer|asa|ashx|shtml|war|cfm)(\?|$)/i;
var SUS_NAME = /shell|cmd|eval|exec|upload|upfile|ma_|xiao|dao|hack|pass|spy|c99|r57|b374k|wso|angel|ant|behinder|godzilla|weevely|404|123|aaa|test\d|tmp|kk|dama/i;

function process(log, util) {
  var events = [];
  var rows = log.query("", ["no", "ip", "method", "url", "path", "status", "time"]);
  // 路径访问频次统计（识别冷门脚本）
  var freq = {}, scripts = [];
  rows.forEach(function (r) {
    var p = (r.path || (r.url || "").split("?")[0] || "");
    freq[p] = (freq[p] || 0) + 1;
    if (SCRIPT_EXT.test(p)) scripts.push(r);
  });
  var coldPost = {}, susHit = {};
  scripts.forEach(function (r) {
    var p = (r.path || (r.url || "").split("?")[0] || "");
    var st = +r.status || 0, m = (r.method || "").toUpperCase();
    var ip = r.ip || "";
    if (st >= 400) return;
    if (SUS_NAME.test(p)) {
      var k1 = ip + "|" + p;
      if (!susHit[k1]) susHit[k1] = { ip: ip, p: p, r: r };
    } else if (m === "POST" && (freq[p] || 0) <= 2) {
      var k2 = ip + "|" + p;
      if (!coldPost[k2]) coldPost[k2] = { ip: ip, p: p, r: r };
    }
  });
  Object.keys(susHit).forEach(function (k) {
    var h = susHit[k], r = h.r;
    events.push({
      name: "疑似 webshell 脚本访问",
      desc: "IP " + h.ip + " 访问可疑脚本 " + (r.method || "") + " " + (r.url || h.p) + " 返回 " + (r.status || "") + "（行 " + (r.no || "") + "，" + (r.time || "") + "）",
      severity: "high",
      status: true,
      src: [h.ip],
      dst: [h.p],
    });
  });
  Object.keys(coldPost).forEach(function (k) {
    var h = coldPost[k], r = h.r;
    events.push({
      name: "冷门脚本收到 POST",
      desc: "IP " + h.ip + " 对全日志仅访问 " + (freq[h.p] || 0) + " 次的脚本 " + h.p + " 发起 POST 并返回 " + (r.status || "") + "（行 " + (r.no || "") + "）",
      severity: "medium",
      status: true,
      src: [h.ip],
      dst: [h.p],
    });
  });
  return events;
}
