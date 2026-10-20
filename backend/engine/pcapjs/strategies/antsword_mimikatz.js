var INFO = {
  name: "antsword上传恶意软件",
  desc: "蚁剑 POST 参数 base64 解码后包含 mimikatz",
  type: "attack", phase: "Execution", author: "Yjs"
};

function process(pcap, util) {
  var rows = pcap.query("http.request.method==POST", ["ip.src", "ip.dst", "http.file_data"]);
  var events = [];
  rows.forEach(function (r) {
    var body = util.urlDecode(util.body(r["http.file_data"] || ""));
    body.split("&").forEach(function (kv) {
      var v = kv.substring(kv.indexOf("=") + 1);
      if (v.length < 8 || !/^[A-Za-z0-9+\/=]+$/.test(v)) return;
      var d = util.b64Decode(v);
      if (d.toLowerCase().indexOf("mimikatz") >= 0) {
        events.push({
          name: "蚁剑上传mimikatz",
          desc: r["ip.src"] + " 通过蚁剑向 " + r["ip.dst"] + " 上传 mimikatz，内容: " + d.substring(0, 200),
          src: [r["ip.src"]], dst: [r["ip.dst"]]
        });
      }
    });
  });
  return events;
}
