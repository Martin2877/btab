<template>
  <div class="code-view">
    <n-alert v-if="truncated" type="warning" :show-icon="false" style="margin-bottom: 8px">
      内容过大，仅预览前 {{ maxSize / 1024 }}KB
    </n-alert>
    <Codemirror :value="viewContent" :options="cmOptions" border :height="height" />
  </div>
</template>

<script lang="ts" setup>
  import { computed } from 'vue';
  import Codemirror from 'codemirror-editor-vue3';
  import 'codemirror/theme/dracula.css';
  import 'codemirror/mode/xml/xml.js';
  import 'codemirror/mode/javascript/javascript.js';
  import 'codemirror/mode/css/css.js';
  import 'codemirror/mode/htmlmixed/htmlmixed.js';
  import 'codemirror/mode/htmlembedded/htmlembedded.js';
  import 'codemirror/mode/clike/clike.js';
  import 'codemirror/mode/php/php.js';
  import 'codemirror/mode/sql/sql.js';
  import 'codemirror/mode/shell/shell.js';
  import 'codemirror/mode/python/python.js';
  import 'codemirror/mode/powershell/powershell.js';
  import 'codemirror/mode/vbscript/vbscript.js';
  import 'codemirror/mode/yaml/yaml.js';
  import 'codemirror/mode/markdown/markdown.js';

  const props = defineProps({
    content: { type: String, default: '' },
    // 文件名用于推断语法高亮模式
    filename: { type: String, default: '' },
    height: { type: [String, Number], default: 460 },
    // 预览上限（字符数），超出截断，避免大字典文件卡死编辑器
    maxSize: { type: Number, default: 256 * 1024 },
  });

  // 扩展名 -> CodeMirror mode/mime
  const MODE_MAP: Record<string, string> = {
    jsp: 'application/x-jsp',
    jspx: 'application/x-jsp',
    asp: 'application/x-aspx',
    aspx: 'application/x-aspx',
    php: 'application/x-httpd-php',
    phtml: 'application/x-httpd-php',
    html: 'text/html',
    htm: 'text/html',
    xml: 'xml',
    js: 'javascript',
    json: 'application/json',
    ts: 'text/typescript',
    css: 'css',
    java: 'text/x-java',
    c: 'text/x-csrc',
    h: 'text/x-csrc',
    cpp: 'text/x-c++src',
    cs: 'text/x-csharp',
    sql: 'text/x-sql',
    sh: 'shell',
    bash: 'shell',
    py: 'python',
    ps1: 'powershell',
    vbs: 'text/vbscript',
    vb: 'text/vbscript',
    yml: 'yaml',
    yaml: 'yaml',
    md: 'markdown',
  };

  const mode = computed(() => {
    const ext = (props.filename.split('.').pop() || '').toLowerCase();
    return MODE_MAP[ext] || null;
  });

  const cmOptions = computed(() => ({
    mode: mode.value,
    theme: 'dracula',
    lineNumbers: true,
    lineWrapping: true,
    readOnly: true,
    indentUnit: 2,
    tabSize: 2,
  }));

  const truncated = computed(() => props.content.length > props.maxSize);
  const viewContent = computed(() =>
    truncated.value ? props.content.slice(0, props.maxSize) : props.content
  );
</script>

<style lang="less" scoped>
  .code-view {
    :deep(.CodeMirror) {
      font-family: Consolas, 'Courier New', monospace;
      font-size: 12px;
    }
  }
</style>
