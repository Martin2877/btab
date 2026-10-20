var INFO = {
  name: "目录暴破检测",
  desc: "同一源向同一目标请求大量不同 URI（HEAD 为主，或 GET 请求 URI 数量极多）",
  type: "attack", phase: "Reconnaissance", author: "Ali0th"
};

function process(pcap, util) {
  var rows = pcap.query("http.request", ["ip.src", "ip.dst", "http.request.method", "http.request.uri"]);
  var groups = {};
  rows.forEach(function (r) {
    if (!r["http.request.uri"]) return;
    var k = r["ip.src"] + ">" + r["ip.dst"];
    var g = groups[k] || (groups[k] = { src: r["ip.src"], dst: r["ip.dst"], uris: {}, head: 0, total: 0 });
    g.uris[r["http.request.uri"]] = true;
    g.total++;
    if (r["http.request.method"] === "HEAD") g.head++;
  });
  var events = [];
  Object.keys(groups).forEach(function (k) {
    var g = groups[k], n = Object.keys(g.uris).length;
    var headMode = n >= 30 && g.head > g.total / 2;
    var getMode = n >= 100;
    if (headMode || getMode) {
      events.push({
        name: "目录暴破",
        desc: g.src + " 向 " + g.dst + " 请求了 " + n + " 个不同 URI（HEAD " + g.head + "/" + g.total + " 次）",
        src: [g.src], dst: [g.dst]
      });
    }
  });
  return events;
}
