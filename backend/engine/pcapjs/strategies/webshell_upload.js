var INFO = {
  name: "webshell上传",
  desc: "HTTP 请求体中包含 PHP 危险函数调用",
  type: "attack", phase: "Persistence", author: "cjh"
};

var FUNCS = ["phpinfo", "eval", "passthru", "exec", "system", "chroot", "scandir", "chgrp", "chown", "shell_exec",
  "proc_open", "proc_get_status", "ini_alter", "ini_restore", "dl", "pfsockopen", "openlog", "syslog", "readlink",
  "symlink", "popen", "stream_socket_server", "fsockopen"];

function process(pcap, util) {
  var rows = pcap.query("http.request.method==POST", ["ip.src", "ip.dst", "http.request.uri", "http.file_data"]);
  var events = [];
  rows.forEach(function (r) {
    var body = util.body(r["http.file_data"] || "");
    var decoded = util.urlDecode(body);
    var hit = FUNCS.filter(function (f) { return decoded.indexOf(f + "(") >= 0; });
    if (hit.length) {
      events.push({
        name: "检测request body内容",
        desc: r["ip.src"] + " 向 " + r["ip.dst"] + r["http.request.uri"] + " 提交的请求体中包含危险函数: " + hit.join(","),
        src: [r["ip.src"]], dst: [r["ip.dst"]]
      });
    }
  });
  return events;
}
