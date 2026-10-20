var INFO = {
  name: "CORS配置不当",
  desc: "响应头 Access-Control-Allow-Origin 为 * 或 null",
  type: "vulnerability", phase: "Discovery", author: "cjh"
};

function process(pcap, util) {
  var rows = pcap.queryMulti("http.response", ["ip.src", "ip.dst", "http.response.line"]);
  var seen = {}, events = [];
  rows.forEach(function (r) {
    (r["http.response.line"] || []).forEach(function (line) {
      var m = /^Access-Control-Allow-Origin:\s*(.*?)\s*$/i.exec(line.replace(/[\r\n]+$/, ""));
      if (m && (m[1] === "*" || m[1] === "null") && !seen[r["ip.src"][0]]) {
        seen[r["ip.src"][0]] = true;
        events.push({ name: "CORS配置不当", desc: "目标主机 " + r["ip.src"][0] + " 的 Access-Control-Allow-Origin 为 " + m[1], src: [r["ip.dst"][0]], dst: [r["ip.src"][0]] });
      }
    });
  });
  return events;
}
