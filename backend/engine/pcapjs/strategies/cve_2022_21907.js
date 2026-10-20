var INFO = {
  name: "CVE-2022-21907",
  desc: "http.sys 远程代码执行：Accept-Encoding 异常超长",
  type: "attack", phase: "Exploitation", author: "Yjs"
};

function process(pcap, util) {
  var rows = pcap.query("http.accept_encoding", ["ip.src", "ip.dst", "http.accept_encoding"]);
  var events = [];
  rows.forEach(function (r) {
    if ((r["http.accept_encoding"] || "").length > 100) {
      events.push({
        name: "检测到利用CVE-2022-21907漏洞的流量",
        desc: r["ip.src"] + " -> " + r["ip.dst"] + " 的 Accept-Encoding 长度异常(" + r["http.accept_encoding"].length + ")",
        src: [r["ip.src"]], dst: [r["ip.dst"]]
      });
    }
  });
  return events;
}
