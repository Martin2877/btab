var INFO = {
  name: "FTP暴力破解",
  desc: "同一源向同一 FTP 服务高频提交大量不同密码",
  type: "attack", phase: "Credential Access", author: "tym"
};

function process(pcap, util) {
  var rows = pcap.query('ftp.request.command == "PASS"', ["ip.src", "ip.dst", "ftp.request.arg"]);
  var g = {};
  rows.forEach(function (r) {
    var k = r["ip.src"] + ">" + r["ip.dst"];
    var e = g[k] || (g[k] = { src: r["ip.src"], dst: r["ip.dst"], pass: [] });
    e.pass.push(r["ftp.request.arg"] || "");
  });
  var events = [];
  Object.keys(g).forEach(function (k) {
    var e = g[k], uniq = util.unique(e.pass);
    if (e.pass.length > 15 && uniq.length > e.pass.length / 2) {
      events.push({
        name: "FTP暴力破解",
        desc: e.src + " 向 " + e.dst + " 尝试了 " + e.pass.length + " 次密码（" + uniq.length + " 个不同）",
        src: [e.src], dst: [e.dst]
      });
    }
  });
  return events;
}
