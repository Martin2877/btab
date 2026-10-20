const esc = (x: string) => x.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const KEYWORDS = new Set(
  'break case catch class const continue debugger default delete do else export extends finally for function if import in instanceof let new of return static super switch this throw try typeof var void while with yield async await true false null undefined'.split(
    ' '
  )
);

// 引擎脚本约定中的全局对象/函数 + 常见内建对象
const BUILTINS = new Set(
  'INFO process pcap util console JSON Math Object Array String Number Boolean RegExp Date Error Set Map Promise parseInt parseFloat isNaN encodeURIComponent decodeURIComponent'.split(
    ' '
  )
);

// 前一个有效字符为这些时，/ 视为正则字面量起点而非除号
const REGEX_PREV = new Set('=([{,;:!&|?+-*~^<>'.split(''));

/**
 * highlightJs 将 JS 源码转为带语法高亮的 HTML（配合 .jk-* 样式使用）。
 * 单遍扫描：注释、字符串（含模板串）、正则、数字、关键字、函数调用、内建对象。
 */
export function highlightJs(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  let prevSig = ''; // 最近一个非空白、非注释字符（粗略用于正则判定）

  const push = (cls: string, s: string) =>
    out.push(cls ? `<span class="${cls}">${esc(s)}</span>` : esc(s));

  while (i < n) {
    const c = src[i];
    const two = src.substr(i, 2);

    // 注释
    if (two === '//') {
      let j = src.indexOf('\n', i);
      if (j < 0) j = n;
      push('jk-c', src.slice(i, j));
      i = j;
      continue;
    }
    if (two === '/*') {
      let j = src.indexOf('*/', i + 2);
      j = j < 0 ? n : j + 2;
      push('jk-c', src.slice(i, j));
      i = j;
      continue;
    }

    // 字符串
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1;
      while (j < n && src[j] !== c) {
        j += src[j] === '\\' ? 2 : 1;
      }
      j = Math.min(j + 1, n);
      push('jk-s', src.slice(i, j));
      i = j;
      prevSig = c;
      continue;
    }

    // 正则字面量
    if (c === '/' && (prevSig === '' || REGEX_PREV.has(prevSig))) {
      let j = i + 1;
      let cls = false; // 字符类 [...]
      while (j < n) {
        const ch = src[j];
        if (ch === '\\') j += 2;
        else if (ch === '[') {
          cls = true;
          j++;
        } else if (ch === ']') {
          cls = false;
          j++;
        } else if (ch === '/' && !cls) {
          j++;
          break;
        } else if (ch === '\n') break;
        else j++;
      }
      while (j < n && /[a-z]/i.test(src[j])) j++; // flags
      push('jk-r', src.slice(i, j));
      i = j;
      prevSig = '/';
      continue;
    }

    // 数字
    if (/\d/.test(c) || (c === '.' && /\d/.test(src[i + 1] || ''))) {
      let j = i + 1;
      while (j < n && /[\w.]/.test(src[j])) j++;
      push('jk-n', src.slice(i, j));
      i = j;
      prevSig = '0';
      continue;
    }

    // 标识符 / 关键字 / 函数调用
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < n && /[\w$]/.test(src[j])) j++;
      const word = src.slice(i, j);
      let k = j;
      while (k < n && /\s/.test(src[k])) k++;
      if (KEYWORDS.has(word)) push('jk-k', word);
      else if (BUILTINS.has(word)) push('jk-b', word);
      else if (src[k] === '(') push('jk-f', word);
      else push('', word);
      i = j;
      prevSig =
        word === 'return' || word === 'typeof' || word === 'case' || word === 'in' || word === 'of'
          ? ''
          : 'a';
      continue;
    }

    push('', c);
    if (!/\s/.test(c)) prevSig = c;
    i++;
  }
  return out.join('');
}

// 新脚本模板（引擎约定：INFO 元信息 + process(pcap, util) 入口）
export const SCRIPT_TEMPLATE = `var INFO = {
  name: "自定义检测",
  desc: "描述检测逻辑与命中条件",
  type: "attack",        // 事件类型：attack / anomaly / info ...
  phase: "Exploitation", // 攻击阶段
  author: "me"
};

function process(pcap, util) {
  // pcap.query(filter, fields)      -> [{field: "首个取值"}]
  // pcap.queryMulti(filter, fields) -> [{field: ["取值", ...]}]
  var rows = pcap.query("http.request", ["ip.src", "ip.dst", "http.request.uri"]);
  var events = [];
  rows.forEach(function (r) {
    // if (命中条件) {
    //   events.push({ name: "事件名", desc: "...", src: [r["ip.src"]], dst: [r["ip.dst"]] });
    // }
  });
  return events;
}
`;
