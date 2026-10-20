<template>
  <div>
    <n-alert type="info" :show-icon="false" style="margin-bottom: 12px">
      粘贴一条 HTTP 请求（及响应），选择验证范围：全部已启用模板、指定模板 ID，或直接粘贴模板内容，查看请求特征与响应 matcher 是否命中。
    </n-alert>
    <n-space style="margin-bottom: 12px" align="center">
      <n-radio-group v-model:value="mode">
        <n-radio-button value="all">全部已启用模板</n-radio-button>
        <n-radio-button value="id">指定模板</n-radio-button>
        <n-radio-button value="content">粘贴模板</n-radio-button>
      </n-radio-group>
      <n-input-number v-if="mode === 'id'" v-model:value="tplId" :min="1" placeholder="模板记录 ID" style="width: 160px" />
      <n-button @click="fillSample">填充示例</n-button>
      <n-button type="primary" :loading="running" @click="run">开始验证</n-button>
    </n-space>

    <n-input v-if="mode === 'content'" v-model:value="tplContent" type="textarea" placeholder="nuclei 模板 yaml" :autosize="{ minRows: 8, maxRows: 16 }" class="mono" style="margin-bottom: 12px" />
    <n-grid :cols="2" :x-gap="12">
      <n-gi><n-input v-model:value="reqText" type="textarea" placeholder="HTTP 请求原文" :autosize="{ minRows: 8, maxRows: 16 }" class="mono" /></n-gi>
      <n-gi><n-input v-model:value="respText" type="textarea" placeholder="HTTP 响应原文（可选）" :autosize="{ minRows: 8, maxRows: 16 }" class="mono" /></n-gi>
    </n-grid>

    <div v-if="result" style="margin-top: 16px">
      <n-text>参与验证的模板：{{ result.templates }}；命中 <b>{{ result.findings.length }}</b> 条</n-text>
      <n-alert v-for="(e, i) in result.errors" :key="i" type="warning" :show-icon="false" style="margin-top: 6px">{{ e }}</n-alert>
      <n-card v-for="(f, i) in result.findings" :key="i" size="small" style="margin-top: 8px">
        <n-space align="center">
          <n-tag :type="sevType(f.severity)" :bordered="false">{{ f.severity }}</n-tag>
          <b>{{ f.name }}</b>
          <n-text depth="3">{{ f.template_id }}</n-text>
        </n-space>
        <div class="ev" v-if="(f.evidence || []).length">证据：{{ f.evidence.join(' | ') }}</div>
      </n-card>
      <n-data-table style="margin-top: 12px" size="small" :columns="diagCols" :data="result.diagnose" :max-height="320" />
    </div>
  </div>
</template>

<script lang="ts" setup>
import { h, ref, watch } from 'vue';
import { NTag, useMessage } from 'naive-ui';
import { debugVuln } from '@/api/engine/vuln';
import { sevType } from './yaml';

const props = defineProps<{ templateId: number }>();
const message = useMessage();
const mode = ref('all');
const tplId = ref<number | null>(null);
const tplContent = ref('');
const reqText = ref('');
const respText = ref('');
const running = ref(false);
const result = ref<any>(null);

watch(() => props.templateId, (v) => { if (v) { mode.value = 'id'; tplId.value = v; } }, { immediate: true });

const diagCols = [
  { title: '模板', key: 'template_id', width: 200, ellipsis: { tooltip: true } },
  { title: '块', key: 'block', width: 50 },
  { title: '请求特征', key: 'request_matched', width: 90, render: (r) => h(NTag, { size: 'small', bordered: false, type: r.request_matched ? 'success' : 'default' }, () => (r.request_matched ? '命中' : '未命中')) },
  { title: '响应 matcher', key: 'matchers_ok', width: 110, render: (r) => h(NTag, { size: 'small', bordered: false, type: r.matchers_ok ? 'success' : 'default' }, () => (r.matchers_ok ? '命中' : '未命中')) },
  { title: '说明', key: 'note', ellipsis: { tooltip: true } },
];

function fillSample() {
  mode.value = 'content';
  tplContent.value = `id: demo-lfi\ninfo:\n  name: 示例 LFI 读取 /etc/passwd\n  severity: high\n  tags: lfi\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/view?file={{file}}"\n    payloads:\n      file:\n        - /etc/passwd\n        - ../../etc/passwd\n    matchers-condition: and\n    matchers:\n      - type: regex\n        regex:\n          - "root:.*:0:0:"\n      - type: status\n        status:\n          - 200\n`;
  reqText.value = 'GET /view?file=../../etc/passwd HTTP/1.1\nHost: 10.0.0.5\nUser-Agent: curl/8.0\n\n';
  respText.value = 'HTTP/1.1 200 OK\nContent-Type: text/plain\n\nroot:x:0:0:root:/root:/bin/bash\n';
}

function run() {
  if (!reqText.value.trim()) return message.warning('请填写 HTTP 请求');
  const body: any = { request: reqText.value, response: respText.value };
  if (mode.value === 'id') {
    if (!tplId.value) return message.warning('请填写模板 ID');
    body.template_id = tplId.value;
  } else if (mode.value === 'content') {
    if (!tplContent.value.trim()) return message.warning('请粘贴模板内容');
    body.content = tplContent.value;
  }
  running.value = true;
  debugVuln(body).then((r) => (result.value = r)).finally(() => (running.value = false));
}
</script>

<style lang="less" scoped>
.mono :deep(textarea) { font-family: Consolas, 'Courier New', monospace; font-size: 12px; }
.ev { margin-top: 6px; font-size: 12px; color: #666; word-break: break-all; }
</style>
