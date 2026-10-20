<template>
  <div>
    <n-alert type="info" :show-icon="false" style="margin-bottom: 12px">
      字典资源供模板的 <code>payloads</code> 引用（如 <code>helpers/wordlists/users.txt</code>），按路径后缀匹配，目录前缀可不一致。
      被动检测时字典值会展开为具体请求特征；缺少字典则该变量按通配符匹配。zip 模板包会自动导入其中的字典。
    </n-alert>
    <n-space style="margin-bottom: 12px" align="center">
      <n-input v-model:value="q.search" placeholder="搜索路径" clearable style="width: 220px" @keyup.enter="reload" />
      <n-select v-model:value="q.kind" :options="kindOptions" placeholder="类型" clearable style="width: 130px" @update:value="reload" />
      <n-button type="primary" @click="reload">查询</n-button>
      <n-upload multiple action="" :show-file-list="false" :custom-request="processFile" accept=".txt,.lst,.list,.dic,.dict,.csv,.json,.zip">
        <n-button>上传字典</n-button>
      </n-upload>
      <n-input v-model:value="uploadPath" placeholder="上传路径（可选，如 helpers/wordlists/users.txt）" style="width: 320px" />
    </n-space>
    <n-data-table remote size="small" :loading="loading" :columns="columns" :data="rows" :pagination="pagination" :row-key="(r) => r.id" />

    <n-modal v-model:show="show" preset="card" :style="{ width: '760px' }" :title="view.path">
      <n-text depth="3">共 {{ view.lines }} 行<span v-if="view.truncated">，仅预览前 200 行</span></n-text>
      <pre class="res-view">{{ view.content }}</pre>
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
import { h, reactive, ref, onMounted } from 'vue';
import { NTag, NButton, NSpace, useMessage, useDialog, UploadCustomRequestOptions } from 'naive-ui';
import { getVulnResources, getVulnResourceContent, delVulnResource, uploadVulnFile } from '@/api/engine/vuln';

const message = useMessage();
const dialog = useDialog();
const q = reactive({ search: '', kind: null as any });
const rows = ref<any[]>([]);
const loading = ref(false);
const uploadPath = ref('');
const show = ref(false);
const view = reactive<any>({});
const kindOptions = ['wordlist', 'payload', 'helper', 'workflow', 'profile'].map((v) => ({ label: v, value: v }));
const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  prefix: ({ itemCount }) => `共 ${itemCount} 条`,
  onUpdatePage: (p: number) => { pagination.page = p; load(); },
  onUpdatePageSize: (s: number) => { pagination.pageSize = s; pagination.page = 1; load(); },
});

function load() {
  loading.value = true;
  getVulnResources({ search: q.search, kind: q.kind || '', page: pagination.page, pageSize: pagination.pageSize })
    .then((r) => { rows.value = r.list || []; pagination.itemCount = r.total || 0; })
    .finally(() => (loading.value = false));
}
function reload() { pagination.page = 1; load(); }
onMounted(load);

const columns = [
  { title: '路径', key: 'path', ellipsis: { tooltip: true } },
  { title: '类型', key: 'kind', width: 90, render: (r) => h(NTag, { size: 'small', bordered: false }, () => r.kind) },
  { title: '行数', key: 'lines', width: 80 },
  { title: '大小', key: 'size', width: 90, render: (r) => (r.size / 1024).toFixed(1) + 'KB' },
  { title: '更新时间', key: 'UpdatedAt', width: 180, render: (r) => (r.UpdatedAt || '').replace('T', ' ').slice(0, 19) },
  {
    title: '操作', key: 'action', width: 110,
    render: (r) => h(NSpace, { size: 6 }, () => [
      h(NButton, { size: 'tiny', text: true, type: 'primary', onClick: () => preview(r) }, () => '预览'),
      h(NButton, { size: 'tiny', text: true, type: 'error', onClick: () => del(r) }, () => '删除'),
    ]),
  },
];

function preview(r: any) {
  getVulnResourceContent({ id: r.id, limit: 200 }).then((c) => { Object.assign(view, c); show.value = true; });
}
function del(r: any) {
  dialog.warning({
    title: '删除资源', content: `确认删除 ${r.path}？引用它的模板将回退为通配匹配。`, positiveText: '删除', negativeText: '取消',
    onPositiveClick: () => delVulnResource({ id: r.id }).then(() => { message.success('已删除'); load(); }),
  });
}
const processFile = ({ file, onFinish, onError }: UploadCustomRequestOptions) => {
  const fd = new FormData();
  fd.append('file', file.file as File);
  if (uploadPath.value && !file.name.toLowerCase().endsWith('.zip')) fd.append('path', uploadPath.value);
  uploadVulnFile(fd).then((r) => { message.success(r?.message || '上传成功'); onFinish(); load(); }).catch(() => onError());
};
</script>

<style lang="less" scoped>
.res-view {
  background: #0d1117;
  color: #c9d1d9;
  font-family: Consolas, 'Courier New', monospace;
  font-size: 12px;
  border-radius: 6px;
  padding: 10px 12px;
  max-height: 55vh;
  overflow: auto;
}
</style>
