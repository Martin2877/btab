var INFO = {
  name: "shiro550检测",
  desc: "Shiro rememberMe 反序列化：默认密钥解密 Cookie、恶意回显头、deleteMe 探测响应",
  type: "attack", phase: "Exploitation", author: "r0n1n"
};

var DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA==";
var ECHO_HEADERS = ["techo", "cmd", "path", "pass", "c", "p", "Accept-Header", "Testcmd", "Testecho", "bstr", "pwd"];

function process(pcap, util) {
  var events = [];
  var reqs = pcap.queryMulti("http.request", ["ip.src", "ip.dst", "http.cookie", "http.request.line"]);
  reqs.forEach(function (r) {
    var base = { src: [r["ip.src"][0]], dst: [r["ip.dst"][0]] };
    var cookie = (r["http.cookie"] || [])[0] || "";
    var m = /rememberMe=([^;]*)/.exec(cookie);
    if (m && m[1].length >= 100) {
      var plain = util.aesCbcDecrypt(m[1], DEFAULT_KEY);
      if (/java\/lang\/Class|java\/util\/Map|org\.apache\.shiro\.subject\.SimplePrincipalCollection|aced0005/.test(plain)
        || plain.indexOf("\xac\xed\x00\x05") === 0) {
        events.push({ name: "检测到 Shiro rememberMe 恶意代码", desc: "默认密钥解密后为 Java 序列化数据: " + cookie.substring(0, 80) + "...", src: base.src, dst: base.dst });
      }
    }
    (r["http.request.line"] || []).some(function (line) {
      var hit = ECHO_HEADERS.some(function (h) { return line.indexOf(h + ": ") === 0; });
      if (hit) events.push({ name: "检测到 Shiro 恶意请求头", desc: line.replace(/[\r\n]+/g, ""), src: base.src, dst: base.dst });
      return hit;
    });
  });
  var resps = pcap.queryMulti("http.response", ["ip.src", "ip.dst", "http.set_cookie"]);
  var seen = {};
  resps.forEach(function (r) {
    if ((r["http.set_cookie"] || []).join(";").indexOf("rememberMe=deleteMe") >= 0 && !seen[r["ip.src"][0]]) {
      seen[r["ip.src"][0]] = true;
      events.push({ name: "检测到 Shiro 响应特征(rememberMe=deleteMe)", desc: "目标 " + r["ip.src"][0] + " 使用 Shiro，可能存在漏洞", src: [r["ip.src"][0]], dst: [r["ip.dst"][0]] });
    }
  });
  return events;
}
