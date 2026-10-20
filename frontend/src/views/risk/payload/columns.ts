import { h } from 'vue';
import { NTag } from 'naive-ui';
import CodeView from '@/components/CodeView/index.vue';

// 展开行中的检测结果渲染为只读代码视图；JSON 结果做格式化
function expandCode(content: string, filename = '', height = 360) {
  return h(CodeView as any, { content, filename, height });
}

function prettyJson(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw || '';
  }
}

function stateRender(row) {
  var state;
  switch (row.state) {
    case 0: { state = '空闲'; break; }
    case 1: { state = '运行'; break; }
    case 2: { state = '暂停'; break; }
    case 3: { state = '停止'; break; }
    case 4: { state = '完成'; break; }
    default: { state = '空闲'; break; }
  }
  return h(NTag, { type: state }, { default: () => state });
}

// SQLi / XSS / Bash 共用列结构：关联 payload 文件名 + result 详情
export function payloadColumns() {
  return [
    {
      type: 'expand',
      expandable: (rowData) => rowData.result !== '[]',
      renderExpand: (rowData) => expandCode(prettyJson(rowData.result), 'result.json'),
    },
    { title: 'id', key: 'id', width: 30 },
    {
      title: '文件名称',
      key: 'name',
      width: 40,
      render(row) {
        if (row.ForeignPayload != null) {
          return row.ForeignPayload.name;
        }
      },
    },
    { title: '详情', key: 'result', width: 100 },
    { title: '检测时间', key: 'CreatedAt', width: 100 },
    { title: '状态', key: 'state', width: 50, render: stateRender },
  ];
}

// Webshell 列结构：关联 webshell 样本名 + 检出情况 + 去混淆代码 + 调用链
export function webshellColumns() {
  return [
    {
      type: 'expand',
      expandable: (rowData) => rowData.code !== '',
      renderExpand: (rowData) =>
        expandCode(rowData.code, rowData.ForeignWebshell?.name || '', 320),
    },
    { title: 'id', key: 'id', width: 30 },
    {
      title: 'webshell',
      key: 'name',
      width: 80,
      render(row) {
        if (row.ForeignWebshell != null) {
          return row.ForeignWebshell.name;
        }
      },
    },
    { title: '检出情况', key: 'result', width: 80 },
    { title: '去混淆代码', key: 'code', width: 80 },
    { title: '调用链', key: 'chain', width: 80 },
    { title: '检测时间', key: 'CreatedAt', width: 100 },
    { title: '状态', key: 'state', width: 50, render: stateRender },
  ];
}
