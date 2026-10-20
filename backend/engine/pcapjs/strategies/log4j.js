var INFO = {
  name: "log4j攻击检测",
  desc: "还原 ${:-}、${upper:}、${lower:} 混淆后检测 ${jndi: 利用",
  type: "attack", phase: "Exploitation", author: "cjh"
};

function deobf(data) {
  for (var i = 0; i < 10; i++) {
    var next = data.replace(/\$\{(?:(?!\$\{)[^}])+?\}/g, function (m) {
      var x = /^\$\{[^:}]*:-(.*)\}$/.exec(m);
      if (x) return x[1];
      x = /^\$\{(?:lower|upper):(.*)\}$/.exec(m);
      return x ? x[1] : m;
    });
    if (next === data) break;
    data = next;
  }
  return data;
}

function process(pcap, util) {
  var rows = pcap.query('frame contains 24:7b', ["ip.src", "ip.dst", "tcp.payload"]);
  var events = [], seen = {};
  rows.forEach(function (r) {
    var body = util.body(r["tcp.payload"] || "");
    (body.match(/\$\{.+/g) || []).forEach(function (m) {
      var real = deobf(m);
      if (real.toLowerCase().indexOf("${jndi:") >= 0 && !seen[real]) {
        seen[real] = true;
        events.push({
          name: "检测到log4j漏洞攻击",
          desc: r["ip.src"] + " -> " + r["ip.dst"] + " payload: " + real.substring(0, 200),
          src: [r["ip.src"]], dst: [r["ip.dst"]]
        });
      }
    });
  });
  return events;
}
