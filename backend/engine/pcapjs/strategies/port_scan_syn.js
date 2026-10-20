var INFO = {
  name: "SYN端口扫描",
  desc: "同一源向同一目标的大量不同端口发送 SYN",
  type: "attack", phase: "Reconnaissance", author: "Yjs"
};

function process(pcap, util) {
  var rows = pcap.query("tcp.flags.syn==1 && tcp.flags.ack==0", ["ip.src", "ip.dst", "tcp.dstport"]);
  var g = {};
  rows.forEach(function (r) {
    var k = r["ip.src"] + ">" + r["ip.dst"];
    var e = g[k] || (g[k] = { src: r["ip.src"], dst: r["ip.dst"], ports: {} });
    e.ports[r["tcp.dstport"]] = true;
  });
  var events = [];
  Object.keys(g).forEach(function (k) {
    var e = g[k], n = Object.keys(e.ports).length;
    if (n > 20) {
      events.push({
        name: "SYN端口扫描",
        desc: "源IP:" + e.src + " 连接目标IP:" + e.dst + " 不同端口数量多达 " + n + " 个",
        src: [e.src], dst: [e.dst]
      });
    }
  });
  return events;
}
