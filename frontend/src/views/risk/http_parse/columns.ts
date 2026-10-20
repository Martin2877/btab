import { h } from 'vue';
import { NTag, NEllipsis } from 'naive-ui';

// 参数来源位置的标签映射
const locationMap: Record<string, { label: string; type: string }> = {
  query: { label: 'Query 参数', type: 'info' },
  body: { label: 'Body 参数', type: 'warning' },
  form: { label: '表单字段', type: 'success' },
  file: { label: '上传文件', type: 'error' },
};

// 过长内容省略 + 悬浮查看全文
function ellipsize(content: any, width: number) {
  return h(
    NEllipsis,
    { style: `max-width:${width}px`, tooltip: { width: 460 } },
    { default: () => String(content ?? '') }
  );
}

// 初步判断结果的标签颜色
function judgeTagType(t: string) {
  if (!t) return 'default';
  if (t.includes('可疑') || t.includes('不匹配')) return 'warning';
  if (t.includes('编码') || t.includes('字符串') || t.includes('文件')) return 'info';
  return 'default';
}

// 参数解析表：来源、位置、参数名、原始值、解码值、类型判断
export function paramColumns() {
  return [
    { title: '#', key: '_no', width: 48, render: (_row, index: number) => index + 1 },
    {
      title: '请求',
      key: 'exchange',
      width: 56,
      render: (row) => `#${row.exchange}`,
    },
    {
      title: '位置',
      key: 'location',
      width: 96,
      render(row) {
        const loc = locationMap[row.location] || { label: row.location, type: 'default' };
        return h(NTag, { size: 'small', bordered: false, type: loc.type as any }, { default: () => loc.label });
      },
    },
    {
      title: '参数',
      key: 'name',
      width: 160,
      render: (row) => ellipsize(row.name, 180),
    },
    {
      title: '参数值',
      key: 'value',
      render: (row) => ellipsize(row.value, 340),
    },
    {
      title: '解码 / 还原',
      key: 'decoded',
      render(row) {
        if (!row.decoded) {
          return h('span', { style: 'color:#bbb' }, '—');
        }
        return ellipsize(row.decoded, 340);
      },
    },
    {
      title: '初步判断',
      key: 'type',
      width: 170,
      render(row) {
        return h(
          NTag,
          { size: 'small', bordered: false, type: judgeTagType(row.type) as any },
          { default: () => row.type || '未知' }
        );
      },
    },
  ];
}

// 请求/响应头明细表
export function headerColumns() {
  return [
    {
      title: 'Header',
      key: 'name',
      width: 180,
      render: (row) => h('span', { class: 'mono' }, row.name),
    },
    {
      title: '值',
      key: 'value',
      render: (row) => ellipsize(row.value, 420),
    },
  ];
}
