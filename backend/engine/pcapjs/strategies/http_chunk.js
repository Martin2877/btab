var INFO = {
  name: "http分块传输",
  desc: "请求使用 Transfer-Encoding: chunked 分块传输（常用于绕过 WAF）",
  type: "technique", phase: "Defense Evasion", author: "cjh"
};

function process(pcap, util) {
  var rows = pcap.queryMulti("http.request", ["ip.src", "ip.dst", "http.host", "http.transfer_encoding", "http.chunk_size"]);
  var events = [];
  rows.forEach(function (r) {
    var te = (r["http.transfer_encoding"] || [])[0];
    var chunks = r["http.chunk_size"] || [];
    if (te === "chunked" && chunks.length > 1 && chunks[chunks.length - 1] === "0") {
      events.push({
        name: "检测到http分块传输",
        desc: r["ip.src"] + " 对 " + (r["http.host"] || [r["ip.dst"]])[0] + " 的请求使用分块传输(" + chunks.length + " 块)",
        src: [r["ip.src"]], dst: [r["ip.dst"]]
      });
    }
  });
  return events;
}
