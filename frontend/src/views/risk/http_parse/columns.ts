import { h } from 'vue';

export const columns = [
  {
    title: 'id',
    key: 'id',
    width: 30,
  },
  {
    title: '参数',
    key: 'arg',
    width: 40,
  },
  {
    title: '参数值',
    key: 'value',
    width: 100,
  },
  {
    title: '初步判断',
    key: 'first_judge',
    width: 80,
  },
  {
    title: '辅助工具',
    key: 'other',
    width: 80,
    render() {
      return h(
        'Select',
        {
          props: {
            value: '123',
            type: 'on',
          },
          onClick: ($event) => {
            if ($event.target.value != '000') {
              // 后期需要判断url,防止跳转漏洞,暂时不加
              document.location.href = $event.target.value;
            }
          },
        },
        [
          h('option', { value: '000' }, '可选择组件进行深度检测'),
          h('option', { value: '#/risk/xss' }, 'XSS检测'),
          h('option', { value: '#/risk/sqli' }, 'SQL注入检测'),
          h('option', { value: '#/risk/webshell' }, 'Webshell检测'),
          h('option', { value: '#/risk/bash' }, 'Bash命令检测'),
        ]
      );
    },
  },
  // {
  //   title: '操作',
  //   key: 'action',
  //   width: 50,
  // },
];

export const columns_files = [
  {
    title: 'id',
    key: 'id',
    width: 30,
  },
  {
    title: '文件名',
    key: 'filename',
    width: 30,
  },
  {
    title: '文件类型',
    key: 'filetype',
    width: 30,
  },
  {
    title: '初步判断',
    key: 'filefirst_judge',
    width: 30,
  },
];
