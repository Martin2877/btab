var INFO = {
  name: "Telnet弱口令检测",
  desc: "还原 Telnet 登录过程中的用户名/密码，判断是否登录成功及密码强度",
  type: "attack", phase: "Credential Access", author: "Yjs"
};

function strength(p) {
  return /^[a-z]{2,8}$|^[A-Z]{2,8}$|^[0-9]{2,8}$/.test(p) ? "弱密码" : "强密码";
}

function process(pcap, util) {
  var rows = pcap.query("telnet.data", ["frame.number", "ip.src", "ip.dst", "tcp.stream", "telnet.data"]);
  rows.sort(function (a, b) { return Number(a["frame.number"]) - Number(b["frame.number"]); });
  var events = [];
  var sessions = {};
  rows.forEach(function (r) {
    var d = r["telnet.data"] || "";
    var s = sessions[r["tcp.stream"]] || (sessions[r["tcp.stream"]] = { state: "", user: "", pass: "", server: "" });
    if (/login:\s*$/i.test(d.trim()) || /login:/i.test(d)) {
      s.state = "user"; s.user = ""; s.server = r["ip.src"]; return;
    }
    if (/password:/i.test(d)) { s.state = "pass"; s.pass = ""; return; }
    if (s.state === "pass" && r["ip.src"] === s.server && !/\r|\n/.test(d) && d !== "") return;
    if (r["ip.src"] === s.server) {
      if (s.state === "result") {
        var ok = !/incorrect|failed|denied/i.test(d);
        events.push({
          name: "Telnet登录" + (ok ? "成功" : "失败"),
          desc: "源IP:" + s.client + " 连接 " + s.server + " 使用 " + s.user + "/" + s.pass + " 登录" + (ok ? "成功" : "失败") + "，" + strength(s.pass),
          src: [s.client], dst: [s.server]
        });
        s.state = "";
      }
      return;
    }
    s.client = r["ip.src"];
    if (s.state === "user" || s.state === "pass") {
      var key = s.state;
      if (/\r|\n/.test(d)) {
        s.state = key === "user" ? "wait" : "result";
        d = d.replace(/[\r\n]+/g, "");
      }
      s[key] += d;
    }
  });
  return events;
}
