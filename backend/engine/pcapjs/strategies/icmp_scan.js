var INFO = {
  name: "ICMP扫描",
  desc: "同一源向大量不同主机发送 ICMP echo request 探测存活",
  type: "attack", phase: "Reconnaissance", author: "Yjs"
};

function process(pcap, util) {
  var rows = pcap.query("icmp", ["ip.src", "ip.dst", "icmp.type"]);
  var scan = {}, alive = {};
  rows.forEach(function (r) {
    if (r["icmp.type"] === "8") {
      (scan[r["ip.src"]] || (scan[r["ip.src"]] = {}))[r["ip.dst"]] = true;
    } else if (r["icmp.type"] === "0") {
      alive[r["ip.src"]] = true;
    }
  });
  var events = [];
  Object.keys(scan).forEach(function (src) {
    var dsts = Object.keys(scan[src]);
    if (dsts.length >= 10) {
      var up = dsts.filter(function (d) { return alive[d]; });
      events.push({
        name: "ICMP扫描",
        desc: src + " 探测了 " + dsts.length + " 个主机，存活: " + (up.length ? up.join(",") : "无"),
        src: [src], dst: dsts.slice(0, 20)
      });
    }
  });
  return events;
}
