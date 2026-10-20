var INFO = {
  name: "CVE-2020-1957",
  desc: "Shiro 权限绕过：URI 路径中以分号拼接后续路由",
  type: "attack", phase: "Exploitation", author: "cjh"
};

function process(pcap, util) {
  var rows = pcap.query("http.request", ["ip.src", "ip.dst", "http.request.uri"]);
  var events = [];
  rows.forEach(function (r) {
    var uri = r["http.request.uri"] || "";
    var q = uri.indexOf("?");
    if (q !== -1) uri = uri.substring(0, q);
    var parts = uri.split(";");
    if (parts.length > 1 && parts[0].indexOf("/") >= 0) {
      var rest = parts.slice(1).join(";");
      if (/\/[a-zA-Z0-9]+/.test(rest) && rest.indexOf("=") < 0) {
        events.push({
          name: "检测到shiro权限绕过(CVE-2020-1957)",
          desc: r["ip.src"] + " 请求 " + r["http.request.uri"],
          src: [r["ip.src"]], dst: [r["ip.dst"]]
        });
      }
    }
  });
  return events;
}
