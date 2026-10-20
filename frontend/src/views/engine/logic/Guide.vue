<template>
  <div class="guide">
    <n-alert type="info" :show-icon="false" style="margin-bottom: 14px">
      行为检测引擎使用 goja 在 Go 进程内运行 JavaScript 检测脚本（无需 python /
      suricata），报文数据按需由 tshark 提取。 每个脚本对同一个流量包独立执行，产出一组安全事件。
    </n-alert>

    <n-card size="small" title="1. 执行模型" class="sec">
      <div class="doc">
        <p
          >· 引擎加载 <code>stores/strategy/*.js</code>（用户脚本）与程序内置脚本，同名 ID
          的用户脚本覆盖内置版本。</p
        >
        <p
          >· 检测时每个脚本以协程并发执行（最多 4 个），单脚本超时 60
          秒，异常/超时不影响其他脚本。</p
        >
        <p
          >· <code>pcap.query(filter, fields)</code> 底层调用 tshark 提取报文；<b
            >相同 filter+fields 的查询在同一次检测中只执行一次</b
          >，多脚本共享缓存。</p
        >
        <p
          >· 运行时只有 <code>pcap</code>、<code>util</code> 两个注入对象，<b>没有</b> console /
          require / 网络 / 定时器；推荐使用 ES5 语法（var / function）。</p
        >
      </div>
    </n-card>

    <n-card size="small" title="2. 脚本骨架" class="sec">
      <div class="js-view" v-html="hi(SKELETON)"></div>
    </n-card>

    <n-card size="small" title="3. INFO 元信息" class="sec">
      <n-table size="small" :bordered="true">
        <thead>
          <tr><th style="width: 110px">字段</th><th style="width: 90px">必填</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr
            ><td><code>name</code></td
            ><td>建议</td
            ><td
              >脚本展示名；缺省用脚本
              ID（文件名）。该名称会同步到「风险检测-流量包检测」的策略选项中</td
            ></tr
          >
          <tr
            ><td><code>desc</code></td
            ><td>建议</td><td>一句话描述检测逻辑与命中条件</td></tr
          >
          <tr
            ><td><code>type</code></td
            ><td>可选</td
            ><td
              >事件类型，如 <code>attack / anomaly / info</code>，会作为检出事件与检测分类的类型</td
            ></tr
          >
          <tr
            ><td><code>phase</code></td
            ><td>可选</td
            ><td
              >攻击阶段标签，如 Recon / Exploitation / Installation / Command&amp;Control /
              Exfiltration</td
            ></tr
          >
          <tr
            ><td><code>author</code></td
            ><td>可选</td><td>作者标识</td></tr
          >
        </tbody>
      </n-table>
    </n-card>

    <n-card size="small" title="4. 返回值：事件数组" class="sec">
      <div class="doc">
        <p><code>process(pcap, util)</code> 返回事件对象数组，每个事件即一条检出结果：</p>
      </div>
      <n-table size="small" :bordered="true">
        <thead>
          <tr><th style="width: 110px">字段</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr
            ><td><code>name</code></td
            ><td>事件标题；缺省用脚本名称</td></tr
          >
          <tr
            ><td><code>desc</code></td
            ><td>事件详情，建议包含命中证据（payload、URI 等），前端按预格式文本展示</td></tr
          >
          <tr
            ><td><code>status</code></td
            ><td><code>false</code> 的事件会被过滤（可用于条件抑制）</td></tr
          >
          <tr
            ><td><code>src / dst</code></td
            ><td>字符串数组，事件关联的源/目的地址（通常取 <code>ip.src / ip.dst</code>）</td></tr
          >
        </tbody>
      </n-table>
      <div class="doc" style="margin-top: 8px">
        <p>事件的 <code>type / phase</code> 自动继承脚本 INFO，无需在事件里重复填写。</p>
      </div>
    </n-card>

    <n-card size="small" title="5. 报文查询 pcap.query / queryMulti" class="sec">
      <div class="doc">
        <p
          ><code>pcap.query(filter, fields)</code> → <code>[{字段: "首个取值"}]</code>；<code
            >pcap.queryMulti(filter, fields)</code
          >
          → <code>[{字段: ["全部取值"]}]</code></p
        >
        <p
          ><code>filter</code> 是 tshark 显示过滤器语法，<code>fields</code> 是 tshark
          字段名数组。</p
        >
      </div>
      <div class="js-view" v-html="hi(QUERY)"></div>
      <div class="doc" style="margin-top: 8px">
        <p
          >常用字段：<code>frame.number</code>、<code>frame.time</code>、<code>ip.src</code>、<code>ip.dst</code>、<code>tcp.srcport</code>、<code>tcp.dstport</code>、<code>tcp.stream</code>、<code>tcp.payload</code>、<code>http.request.method</code>、<code>http.request.uri</code>、<code>http.host</code>、<code>http.user_agent</code>、<code>http.file_data</code>、<code
            >dns.qry.name</code
          ></p
        >
        <p
          >HTTP 响应/请求体、TCP
          载荷等字段（<code>http.file_data</code>、<code>tcp.payload</code>）是<b>十六进制串</b>，用
          <code>util.body()</code> 转文本。</p
        >
      </div>
    </n-card>

    <n-card size="small" title="6. util 工具函数" class="sec">
      <n-table size="small" :bordered="true">
        <thead>
          <tr><th style="width: 220px">签名</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr
            ><td><code>util.body(hex)</code></td
            ><td>十六进制报文转文本；非十六进制输入原样返回</td></tr
          >
          <tr
            ><td><code>util.hexDecode(hex)</code></td
            ><td>严格十六进制解码（自动忽略冒号/空格），失败返回 ""</td></tr
          >
          <tr
            ><td><code>util.b64Decode(s)</code></td
            ><td>Base64 解码，自动尝试 Std/Raw/URL 各编码</td></tr
          >
          <tr
            ><td><code>util.urlDecode(s)</code></td
            ><td>URL 解码，失败原样返回</td></tr
          >
          <tr
            ><td><code>util.sqli(s)</code></td
            ><td>libinjection SQL 注入检测；命中返回指纹串，否则 ""</td></tr
          >
          <tr
            ><td><code>util.aesCbcDecrypt(data, key)</code></td
            ><td
              >AES-CBC 解密（base64 密文前 16 字节为 IV，base64 密钥），如 shiro
              rememberMe；失败返回 ""</td
            ></tr
          >
          <tr
            ><td><code>util.unique(arr)</code></td
            ><td>字符串数组去重并排序</td></tr
          >
        </tbody>
      </n-table>
    </n-card>

    <n-card size="small" title="7. 完整示例：检测 JNDI 注入" class="sec">
      <div class="js-view" v-html="hi(EXAMPLE)"></div>
    </n-card>

    <n-card size="small" title="8. 开发与调试流程" class="sec">
      <div class="doc">
        <p
          >① 「检测脚本」→ 新建脚本 / 上传 .js 文件（文件名即脚本
          ID，仅限字母数字、<code>_</code>、<code>-</code>）。</p
        >
        <p
          >② 编辑后先点「校验」确认语法与 INFO
          元信息无误，再保存；编译失败的脚本也会被保存但不生效。</p
        >
        <p>③ 「脚本调试」选择脚本 + 流量包运行，查看命中事件与报错；也可以直接粘贴代码调试。</p>
        <p
          >④
          保存且已启用的脚本自动生效于：风险检测-流量包检测（策略选项）、一键分析（pcap）、调试页"全部脚本"。</p
        >
        <p>⑤ 临时不用的脚本用列表里的开关「停用」即可，无需删除文件。</p>
      </div>
    </n-card>

    <n-card size="small" title="9. 注意事项" class="sec">
      <div class="doc">
        <p
          >· 单脚本超时 60 秒；过大的过滤结果集会拖慢 tshark，filter 尽量收窄（如先
          <code>http.request</code> 再二次判断）。</p
        >
        <p
          >· 脚本间不共享状态；如需跨报文关联，用 <code>queryMulti</code> 一次取全量字段后在 JS
          内聚合。</p
        >
        <p
          >· 正则、JSON、Math、Date 等 ES 内建对象可用；<code>console.log</code>
          不存在，排错请靠调试页的事件/报错输出。</p
        >
        <p>· 单个脚本文件上限 512KB。</p>
      </div>
    </n-card>
  </div>
</template>

<script lang="ts" setup>
  import { highlightJs } from './js';

  const hi = highlightJs;

  const SKELETON = `var INFO = {
  name: "脚本名称",
  desc: "检测逻辑与命中条件",
  type: "attack",        // 事件类型：attack / anomaly / info
  phase: "Exploitation", // 攻击阶段
  author: "me"
};

function process(pcap, util) {
  // 查询报文 → 判定 → 返回事件数组
  return [
    // { name, desc, status, src: [], dst: [] }
  ];
}`;

  const QUERY = `// 显示过滤器示例
pcap.query("http.request", ["ip.src", "http.request.uri"]);
pcap.query("dns", ["dns.qry.name"]);
pcap.query("frame contains 24:7b", ["tcp.payload"]);        // 载荷含 "\${" 的字节
pcap.query('http.request.uri contains "admin"', ["ip.src"]);

// queryMulti：同名字段取全部取值（如多个同名 HTTP 参数、DNS 应答）
var rows = pcap.queryMulti("dns", ["dns.resp.name", "dns.a"]);`;

  const EXAMPLE = `var INFO = {
  name: "JNDI 注入检测",
  desc: "检测 HTTP 请求 URI / 请求体中的 \${jndi:} 载荷",
  type: "attack",
  phase: "Exploitation",
  author: "me"
};

function process(pcap, util) {
  var rows = pcap.query("http.request", [
    "ip.src", "ip.dst",
    "http.request.uri", "http.file_data"
  ]);
  var events = [];
  rows.forEach(function (r) {
    var uri = util.urlDecode(r["http.request.uri"] || "");
    var body = util.body(r["http.file_data"] || ""); // hex -> 文本
    var target = uri + " " + body;
    if (target.indexOf("\${jndi:") >= 0) {
      events.push({
        name: "疑似 JNDI 注入",
        desc: r["ip.src"] + " → " + r["ip.dst"] +
              " 载荷: " + target.substring(0, 200),
        src: [r["ip.src"]],
        dst: [r["ip.dst"]]
      });
    }
  });
  return events;
}`;
</script>

<style lang="less" scoped>
  .guide {
    max-width: 860px;
  }
  .sec {
    margin-bottom: 14px;
  }
  .doc {
    font-size: 13px;
    line-height: 2;
    color: #444;
    p {
      margin: 2px 0;
    }
    code {
      background: rgba(128, 128, 128, 0.12);
      border-radius: 4px;
      padding: 1px 6px;
      font-family: Consolas, 'Courier New', monospace;
      font-size: 12px;
    }
  }
  .js-view {
    background: #0d1117;
    color: #c9d1d9;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.7;
    border-radius: 6px;
    padding: 12px 14px;
    overflow: auto;
    white-space: pre;
  }
  :deep(.jk-k) {
    color: #ff7b72;
  }
  :deep(.jk-s) {
    color: #a5d6ff;
  }
  :deep(.jk-c) {
    color: #8b949e;
    font-style: italic;
  }
  :deep(.jk-n) {
    color: #79c0ff;
  }
  :deep(.jk-r) {
    color: #7ee787;
  }
  :deep(.jk-f) {
    color: #d2a8ff;
  }
  :deep(.jk-b) {
    color: #ffa657;
  }
</style>
