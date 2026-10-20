var INFO = {
  name: "源码/备份文件泄露",
  desc: "探测 .git/.svn 等版本库目录，以及响应体为压缩包/文档等备份文件",
  type: "attack", phase: "Collection", author: "cjh"
};

var MAGIC = [
  ["504b0304", "zip"], ["52617221", "rar"], ["1f8b", "gz"], ["d0cf11e0", "xls/doc"],
  ["377abcaf271c", "7z"], ["425a68", "bz2"], ["7b5c727466", "rtf"]
];

function process(pcap, util) {
  var events = [];
  var reqs = pcap.query("http.request", ["ip.src", "ip.dst", "http.request.uri"]);
  var seen = {};
  reqs.forEach(function (r) {
    var m = /\/\.(git|svn|hg|bzr|cvs)(\/|$)/i.exec(r["http.request.uri"] || "");
    if (m) {
      var k = r["ip.src"] + ">" + r["ip.dst"] + m[1];
      if (seen[k]) return;
      seen[k] = true;
      events.push({
        name: "探测 ." + m[1].toLowerCase() + " 源码泄露",
        desc: r["ip.src"] + " 访问 " + r["ip.dst"] + r["http.request.uri"],
        src: [r["ip.src"]], dst: [r["ip.dst"]]
      });
    }
  });
  var resps = pcap.query("http.response && http.file_data", ["ip.src", "ip.dst", "http.request.uri", "http.file_data"]);
  resps.forEach(function (r) {
    var data = (r["http.file_data"] || "").toLowerCase().replace(/:/g, "");
    var hit = MAGIC.filter(function (m) { return data.indexOf(m[0]) === 0; })[0];
    if (hit) {
      events.push({
        name: "检测到" + hit[1] + "文件泄露",
        desc: r["ip.src"] + " 的 " + (r["http.request.uri"] || "") + " 返回了 " + hit[1] + " 文件",
        src: [r["ip.dst"]], dst: [r["ip.src"]]
      });
    }
  });
  return events;
}
