var INFO = {
  name: "SQL注入检测",
  desc: "使用 libinjection 对 HTTP 请求的 URI 参数与 body 检测 SQL 注入",
  type: "attack", phase: "Exploitation", author: "Ali0th"
};

function check(util, text) {
  var t = util.urlDecode(text);
  var fp = util.sqli(t);
  if (fp) return fp;
  var parts = t.replace(/^[^?]*\?/, "").split("&");
  for (var i = 0; i < parts.length; i++) {
    var v = parts[i].substring(parts[i].indexOf("=") + 1);
    if (v && (fp = util.sqli(v))) return fp;
  }
  return "";
}

function process(pcap, util) {
  var rows = pcap.query("http.request", ["ip.src", "ip.dst", "http.request.uri", "http.file_data"]);
  var events = [];
  rows.forEach(function (r) {
    var uri = r["http.request.uri"] || "";
    var q = uri.indexOf("?");
    var target = q >= 0 ? uri.substring(q + 1) : "";
    var where = "", fp = "";
    if (target && (fp = check(util, target))) where = "URI参数";
    else if (r["http.file_data"] && (fp = check(util, util.body(r["http.file_data"])))) where = "请求体";
    if (where) {
      events.push({
        name: "SQL注入攻击",
        desc: r["ip.src"] + " 请求 " + r["ip.dst"] + uri.substring(0, 150) + " " + where + "命中 libinjection 指纹 " + fp,
        src: [r["ip.src"]], dst: [r["ip.dst"]]
      });
    }
  });
  return events;
}
