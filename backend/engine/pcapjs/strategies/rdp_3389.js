var INFO = {
  name: "3389通信检测",
  desc: "RDP 连接请求中携带 mstshash Cookie",
  type: "behavior", phase: "Lateral Movement", author: "奥村燐"
};

function process(pcap, util) {
  var rows = pcap.query('frame contains "Cookie: mstshash="', ["ip.src", "ip.dst", "tcp.dstport", "tcp.payload"]);
  var seen = {}, events = [];
  rows.forEach(function (r) {
    var k = r["ip.src"] + ">" + r["ip.dst"] + ":" + r["tcp.dstport"];
    if (seen[k]) return;
    seen[k] = true;
    var m = /mstshash=([^\r\n]*)/.exec(util.body(r["tcp.payload"] || ""));
    events.push({
      name: "RDP通信",
      desc: r["ip.src"] + " 通过 RDP 连接 " + r["ip.dst"] + ":" + r["tcp.dstport"] + (m ? "，用户: " + m[1] : ""),
      src: [r["ip.src"]], dst: [r["ip.dst"]]
    });
  });
  return events;
}
