<template>
  <div>
    <n-upload
      multiple
      directory-dnd
      action=""
      :show-file-list="false"
      :custom-request="processFile"
      accept=".yaml,.yml,.zip,.txt,.lst,.list,.dic,.dict"
    >
      <n-upload-dragger>
        <n-text style="font-size: 13px">点击或拖动文件到此处上传</n-text>
        <n-p depth="3" style="margin: 2px 0 0 0; font-size: 12px">
          支持 .yaml/.yml 模板；.zip 模板包（保留目录结构，自动识别并导入字典、helpers、workflows 等资源，如官方 nuclei-templates）
        </n-p>
      </n-upload-dragger>
    </n-upload>

    <n-space style="margin: 12px 0" align="center">
      <n-input v-model:value="q.search" placeholder="搜索 名称/路径/ID/CVE/标签" clearable style="width: 240px" @keyup.enter="reload()" />
      <n-select v-model:value="q.severity" :options="severityOptions" placeholder="严重级别" clearable style="width: 120px" @update:value="reload()" />
      <n-select v-model:value="q.status" :options="statusOptions" placeholder="状态" clearable style="width: 130px" @update:value="reload()" />
      <n-select v-model:value="q.enabled" :options="enabledOptions" placeholder="启用" clearable style="width: 100px" @update:value="reload()" />
      <n-tag v-if="q.tag" closable @close="q.tag = ''; reload()">标签：{{ q.tag }}</n-tag>
      <n-tag v-if="q.protocol" closable @close="q.protocol = ''; reload()">协议：{{ q.protocol }}</n-tag>
      <n-button type="primary" @click="reload()">查询</n-button>
      <n-button @click="openNew">新建模板</n-button>
    </n-space>

    <n-space style="margin-bottom: 10px" align="center" :size="8">
      <n-text depth="3">已选 {{ checked.length }} 项</n-text>
      <n-button size="small" :disabled="!checked.length" @click="batch('enable')">启用所选</n-button>
      <n-button size="small" :disabled="!checked.length" @click="batch('disable')">停用所选</n-button>
      <n-button size="small" type="error" :disabled="!checked.length" @click="batch('delete')">删除所选</n-button>
      <n-divider vertical />
      <n-button size="small" @click="batchAll('enable')">启用全部筛选结果（{{ total }}）</n-button>
      <n-button size="small" @click="batchAll('disable')">停用全部筛选结果</n-button>
    </n-space>

    <n-data-table
      remote
      :loading="loading"
      :columns="columns"
      :data="rows"
      :row-key="(r) => r.id"
      :pagination="pagination"
      v-model:checked-row-keys="checked"
      :scroll-x="1100"
      size="small"
    />

    <n-modal v-model:show="showView" :show-icon="false" preset="card" :style="{ width: '920px' }" :title="cur.title || cur.template_id || '新建模板'">
      <n-space v-if="cur.id" align="center" :size="8" style="margin-bottom: 10px">
        <n-tag :type="sevType(cur.severity)" :bordered="false">{{ cur.severity }}</n-tag>
        <n-tag type="info" :bordered="false">{{ cur.path }}</n-tag>
        <n-tag v-for="p in csv(cur.protocols)" :key="p" size="small" :bordered="false">{{ p }}</n-tag>
        <n-tag v-for="t in csv(cur.tags)" :key="t" size="small" :bordered="false">{{ t }}</n-tag>
      </n-space>
      <n-input v-if="!cur.id" v-model:value="newPath" placeholder="模板路径，如 custom/my-poc.yaml" style="margin-bottom: 10px" />
      <n-alert v-if="cur.parse_error" type="error" :show-icon="false" style="margin-bottom: 10px">{{ cur.parse_error }}</n-alert>
      <n-alert v-if="cur.missing_refs" type="warning" :show-icon="false" style="margin-bottom: 10px">
        缺少字典：{{ cur.missing_refs }}（请在「字典资源」上传；缺失时变量按通配符处理）
      </n-alert>
      <div v-if="!editing" class="yaml-view" v-html="yamlHtml"></div>
      <n-input v-else v-model:value="content" type="textarea" class="yaml-edit" :autosize="{ minRows: 18, maxRows: 26 }" />
      <n-alert v-if="check" :type="check.ok ? 'success' : 'error'" :show-icon="false" style="margin-top: 10px">
        <template v-if="check.ok">
          校验通过。字典引用：{{ (check.refs || []).join(', ') || '无' }}
          <span v-if="(check.missing_refs || []).length">；缺失：{{ check.missing_refs.join(', ') }}</span>
          <span v-if="(check.unsupported || []).length">；本引擎不处理的协议块：{{ check.unsupported.join(', ') }}</span>
        </template>
        <template v-else>{{ check.error }}</template>
      </n-alert>
      <template #footer>
        <n-space justify="end">
          <n-button v-if="cur.id" @click="emit('debug', cur.id)">去调试</n-button>
          <n-button v-if="!editing" @click="editing = true">编辑</n-button>
          <template v-else>
            <n-button @click="doValidate">校验</n-button>
            <n-button type="primary" @click="doSave">保存</n-button>
          </template>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
import { h, reactive, ref, computed, onMounted } from 'vue';
import { NTag, NSwitch, NButton, NSpace, useMessage, useDialog, UploadCustomRequestOptions } from 'naive-ui';
import {
  getVulnTemplates, getVulnTemplateContent, uploadVulnFile, saveVulnTemplate, validateVulnTemplate,
  batchVulnTemplates, delVulnTemplate, enableVulnTemplate,
} from '@/api/engine/vuln';
import { highlightYaml, sevType, severityOptions } from './yaml';

const emit = defineEmits<{ (e: 'debug', id: number): void }>();
const message = useMessage();
const dialog = useDialog();

const q = reactive({ search: '', severity: null as any, status: null as any, enabled: null as any, tag: '', protocol: '' });
const rows = ref<any[]>([]);
const total = ref(0);
const loading = ref(false);
const checked = ref<number[]>([]);
const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50, 100],
  prefix: ({ itemCount }) => `共 ${itemCount} 条`,
  onUpdatePage: (p: number) => { pagination.page = p; load(); },
  onUpdatePageSize: (s: number) => { pagination.pageSize = s; pagination.page = 1; load(); },
});

const statusOptions = [
  { label: '被动可用', value: 'passive' },
  { label: '仅主动/不支持', value: 'active' },
  { label: '解析失败', value: 'error' },
];
const enabledOptions = [{ label: '已启用', value: 'true' }, { label: '已停用', value: 'false' }];

const csv = (s: string) => (s || '').split(',').filter(Boolean);
const params = () => ({
  search: q.search, severity: q.severity || '', status: q.status || '', enabled: q.enabled || '', tag: q.tag, protocol: q.protocol,
});

function load() {
  loading.value = true;
  getVulnTemplates({ ...params(), page: pagination.page, pageSize: pagination.pageSize })
    .then((r) => {
      rows.value = r.list || [];
      pagination.itemCount = total.value = r.total || 0;
    })
    .finally(() => (loading.value = false));
}
function reload() {
  pagination.page = 1;
  checked.value = [];
  load();
}
function applyFilter(f: Record<string, any>) {
  Object.assign(q, { search: '', severity: null, status: null, enabled: null, tag: '', protocol: '' }, f);
  reload();
}
defineExpose({ applyFilter });
onMounted(load);

function statusTag(r: any) {
  if (r.parse_error) return h(NTag, { type: 'error', size: 'small', bordered: false }, () => '解析失败');
  if (csv(r.protocols).includes('http')) return h(NTag, { type: 'success', size: 'small', bordered: false }, () => '被动可用');
  return h(NTag, { size: 'small', bordered: false }, () => '仅主动');
}

const columns = computed<any[]>(() => [
  { type: 'selection' },
  {
    title: '模板', key: 'title', width: 260, ellipsis: { tooltip: true },
    render: (r) => h('div', [h('div', { style: 'font-weight:500' }, r.title || r.template_id || r.name), h('div', { style: 'font-size:12px;color:#999' }, r.template_id)]),
  },
  { title: '路径', key: 'path', width: 220, ellipsis: { tooltip: true } },
  { title: '级别', key: 'severity', width: 80, render: (r) => h(NTag, { type: sevType(r.severity), size: 'small', bordered: false }, () => r.severity) },
  {
    title: '标签', key: 'tags', width: 180,
    render: (r) => h(NSpace, { size: 4 }, () => csv(r.tags).slice(0, 3).map((t) => h(NTag, { size: 'small', bordered: false }, () => t))),
  },
  { title: '状态', key: 'status', width: 90, render: statusTag },
  {
    title: '字典', key: 'refs', width: 90,
    render: (r) => r.missing_refs
      ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => '缺失')
      : r.refs ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => '已引用') : '-',
  },
  {
    title: '启用', key: 'enabled', width: 70,
    render: (r) => h(NSwitch, { size: 'small', value: r.enabled, disabled: !!r.parse_error || !csv(r.protocols).includes('http'), onUpdateValue: (v: boolean) => toggle(r, v) }),
  },
  {
    title: '操作', key: 'action', width: 130, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', text: true, type: 'primary', onClick: () => openView(r) }, () => '查看'),
      h(NButton, { size: 'tiny', text: true, type: 'primary', onClick: () => emit('debug', r.id) }, () => '调试'),
      h(NButton, { size: 'tiny', text: true, type: 'error', onClick: () => del(r) }, () => '删除'),
    ]),
  },
]);

function toggle(r: any, v: boolean) {
  enableVulnTemplate({ id: r.id, enabled: v }).then(() => { r.enabled = v; });
}
function del(r: any) {
  dialog.warning({
    title: '删除模板', content: `确认删除 ${r.path}？`, positiveText: '删除', negativeText: '取消',
    onPositiveClick: () => delVulnTemplate({ id: r.id }).then(() => { message.success('已删除'); load(); }),
  });
}
function batch(action: string) {
  const run = () => batchVulnTemplates({ ids: checked.value, action }).then((r) => {
    message.success(`已处理 ${r.affected} 项`);
    checked.value = [];
    load();
  });
  if (action !== 'delete') return run();
  dialog.warning({ title: '批量删除', content: `确认删除所选 ${checked.value.length} 个模板？`, positiveText: '删除', negativeText: '取消', onPositiveClick: run });
}
function batchAll(action: string) {
  dialog.info({
    title: action === 'enable' ? '启用全部筛选结果' : '停用全部筛选结果',
    content: `将对当前筛选条件下的 ${total.value} 个模板执行操作（解析失败的模板不会被启用）。`,
    positiveText: '确认', negativeText: '取消',
    onPositiveClick: () => {
      const f = params();
      const filter = action === 'enable' ? { ...f, status: f.status || 'ok' } : f;
      return batchVulnTemplates({ all: true, filter, action }).then((r) => { message.success(`已处理 ${r.affected} 项`); load(); });
    },
  });
}

const pending = ref(0);
const processFile = ({ file, onFinish, onError }: UploadCustomRequestOptions) => {
  const fd = new FormData();
  fd.append('file', file.file as File);
  pending.value++;
  const hide = file.name.toLowerCase().endsWith('.zip') ? message.loading(`正在导入 ${file.name} ...`, { duration: 0 }) : null;
  uploadVulnFile(fd)
    .then((r) => { message.success(r?.message || '上传成功'); onFinish(); })
    .catch(() => onError())
    .finally(() => { hide?.destroy(); if (--pending.value === 0) load(); });
};

// 查看 / 编辑
const showView = ref(false);
const editing = ref(false);
const cur = reactive<any>({});
const content = ref('');
const newPath = ref('custom/new-template.yaml');
const check = ref<any>(null);
const yamlHtml = computed(() => highlightYaml(content.value));

function resetCur(r: any = {}) {
  Object.keys(cur).forEach((k) => delete cur[k]);
  Object.assign(cur, r);
  check.value = null;
}
function openView(r: any) {
  getVulnTemplateContent({ id: r.id }).then((c) => {
    resetCur(r);
    content.value = c || '';
    editing.value = false;
    showView.value = true;
  });
}
function openNew() {
  resetCur();
  content.value = `id: my-template\ninfo:\n  name: 自定义模板\n  author: me\n  severity: medium\n  tags: custom\n\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/vuln?id={{id}}"\n    matchers:\n      - type: word\n        part: body\n        words:\n          - "vulnerable"\n`;
  editing.value = true;
  showView.value = true;
}
function doValidate() {
  return validateVulnTemplate({ content: content.value }).then((r) => { check.value = r; return r; });
}
function doSave() {
  saveVulnTemplate({ id: cur.id || 0, path: newPath.value, content: content.value }).then((r) => {
    check.value = r;
    if (r.ok) message.success('已保存'); else message.warning('已保存，但模板存在错误，不会生效');
    showView.value = false;
    load();
  });
}
</script>

<style lang="less" scoped>
.yaml-view {
  background: #0d1117;
  color: #c9d1d9;
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.5;
  border-radius: 6px;
  padding: 12px 14px;
  overflow: auto;
  max-height: 55vh;
  white-space: pre;
}
.yaml-edit :deep(textarea) {
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
}
:deep(.yk-k) { color: #79c0ff; }
:deep(.yk-c) { color: #8b949e; }
:deep(.yk-t) { color: #ffa657; font-weight: 600; }
</style>
