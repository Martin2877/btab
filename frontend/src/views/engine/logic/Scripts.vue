<template>
  <div>
    <n-upload
      multiple
      directory-dnd
      action=""
      :show-file-list="false"
      :custom-request="processFile"
      accept=".js"
    >
      <n-upload-dragger>
        <n-text style="font-size: 13px">点击或拖动 .js 脚本文件到此处上传</n-text>
        <n-p depth="3" style="margin: 2px 0 0 0; font-size: 12px">
          脚本保存到用户目录（文件名即脚本 ID），与内置脚本同名时覆盖内置版本
        </n-p>
      </n-upload-dragger>
    </n-upload>

    <n-space style="margin: 12px 0" align="center">
      <n-input
        v-model:value="q.search"
        placeholder="搜索 ID/名称/描述/作者"
        clearable
        style="width: 240px"
        @keyup.enter="reload()"
      />
      <n-select
        v-model:value="q.type"
        :options="typeOptions"
        placeholder="类型"
        clearable
        style="width: 120px"
        @update:value="reload()"
      />
      <n-select
        v-model:value="q.origin"
        :options="originOptions"
        placeholder="来源"
        clearable
        style="width: 110px"
        @update:value="reload()"
      />
      <n-select
        v-model:value="q.disabled"
        :options="disabledOptions"
        placeholder="启用状态"
        clearable
        style="width: 110px"
        @update:value="reload()"
      />
      <n-button type="primary" @click="reload()">查询</n-button>
      <n-button @click="openNew">新建脚本</n-button>
    </n-space>

    <n-data-table
      remote
      :loading="loading"
      :columns="columns"
      :data="rows"
      :row-key="(r) => r.id"
      :pagination="pagination"
      :scroll-x="1100"
      size="small"
    />

    <n-modal
      v-model:show="showView"
      :show-icon="false"
      preset="card"
      :style="{ width: '960px' }"
      :title="cur.name && cur.name !== cur.id ? `${cur.name}（${cur.id}）` : cur.id || '新建脚本'"
    >
      <n-space v-if="cur.id" align="center" :size="8" style="margin-bottom: 10px">
        <n-tag :bordered="false" type="info">{{ cur.id }}.js</n-tag>
        <n-tag v-if="cur.type" size="small" :bordered="false">{{ cur.type }}</n-tag>
        <n-tag v-if="cur.phase" size="small" type="info" :bordered="false">{{ cur.phase }}</n-tag>
        <n-tag v-if="cur.author" size="small" :bordered="false">{{ cur.author }}</n-tag>
        <n-tag v-if="cur.overridden" size="small" type="warning" :bordered="false"
          >自定义·覆盖内置</n-tag
        >
        <n-tag v-else-if="cur.custom" size="small" type="success" :bordered="false">自定义</n-tag>
        <n-tag v-else size="small" :bordered="false">内置</n-tag>
      </n-space>
      <n-input
        v-if="!cur.id"
        v-model:value="newId"
        placeholder="脚本 ID（即文件名，字母数字、_、-），如 my_check"
        style="margin-bottom: 6px"
      />
      <div v-if="!cur.id" class="guide-tip">
        不熟悉脚本接口约定？
        <a class="guide-link" @click="goGuide">查看脚本开发指南</a>
      </div>
      <n-alert v-if="cur.error" type="error" :show-icon="false" style="margin-bottom: 10px"
        >编译失败：{{ cur.error }}</n-alert
      >
      <n-alert
        v-if="editing && cur.builtin && !cur.custom"
        type="info"
        :show-icon="false"
        style="margin-bottom: 10px"
      >
        内置脚本不可直接修改，保存后将写入用户目录形成同名自定义版本覆盖内置版本。
      </n-alert>
      <div v-if="!editing" class="js-view" v-html="jsHtml"></div>
      <Codemirror
        v-else
        v-model:value="content"
        :options="cmOptions"
        border
        :height="440"
        placeholder="// 在此编写检测脚本"
      />
      <n-alert
        v-if="check"
        :type="check.ok ? 'success' : 'error'"
        :show-icon="false"
        style="margin-top: 10px"
      >
        <template v-if="check.ok">
          校验通过<template v-if="check.meta"
            >。INFO：{{ check.meta.name
            }}<template v-if="check.meta.desc"> — {{ check.meta.desc }}</template></template
          >
        </template>
        <template v-else>{{ check.error }}</template>
      </n-alert>
      <template #footer>
        <n-space justify="end">
          <n-button v-if="cur.id" @click="emit('debug', cur.id)">去调试</n-button>
          <n-button v-if="!editing" @click="editing = true">编辑</n-button>
          <template v-else>
            <n-button :loading="checking" @click="doValidate">校验</n-button>
            <n-button type="primary" :loading="saving" @click="doSave">保存</n-button>
          </template>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
  import { h, reactive, ref, computed, onMounted } from 'vue';
  import {
    NTag,
    NButton,
    NSpace,
    NSwitch,
    useMessage,
    useDialog,
    UploadCustomRequestOptions,
  } from 'naive-ui';
  import Codemirror from 'codemirror-editor-vue3';
  import 'codemirror/mode/javascript/javascript.js';
  import 'codemirror/theme/dracula.css';
  import {
    getLogicScripts,
    getLogicScriptContent,
    uploadLogicFile,
    saveLogicScript,
    validateLogicScript,
    delLogicScript,
    setLogicScriptEnabled,
    getLogicOverview,
  } from '@/api/engine/logic';
  import { highlightJs, SCRIPT_TEMPLATE } from './js';

  const emit = defineEmits<{
    (e: 'debug', id: string): void;
    (e: 'goto', target: string): void;
  }>();
  const message = useMessage();
  const dialog = useDialog();

  const cmOptions = {
    mode: 'javascript',
    theme: 'dracula',
    lineNumbers: true,
    indentUnit: 2,
    tabSize: 2,
  };

  const q = reactive({ search: '', type: null as any, origin: null as any, disabled: null as any });
  const rows = ref<any[]>([]);
  const total = ref(0);
  const loading = ref(false);
  const typeOptions = ref<any[]>([]);
  const originOptions = [
    { label: '内置', value: 'builtin' },
    { label: '自定义', value: 'custom' },
  ];
  const disabledOptions = [
    { label: '启用', value: '0' },
    { label: '停用', value: '1' },
  ];
  const pagination = reactive({
    page: 1,
    pageSize: 20,
    itemCount: 0,
    showSizePicker: true,
    pageSizes: [10, 20, 50, 100],
    prefix: ({ itemCount }) => `共 ${itemCount} 条`,
    onUpdatePage: (p: number) => {
      pagination.page = p;
      load();
    },
    onUpdatePageSize: (s: number) => {
      pagination.pageSize = s;
      pagination.page = 1;
      load();
    },
  });

  function load() {
    loading.value = true;
    getLogicScripts({
      search: q.search,
      type: q.type || '',
      origin: q.origin || '',
      disabled: q.disabled ?? '',
      page: pagination.page,
      pageSize: pagination.pageSize,
    })
      .then((r) => {
        rows.value = r.list || [];
        pagination.itemCount = total.value = r.total || 0;
      })
      .finally(() => (loading.value = false));
  }
  function reload() {
    pagination.page = 1;
    load();
  }
  function applyFilter(f: Record<string, any>) {
    Object.assign(q, { search: '', type: null, origin: null, disabled: null }, f);
    reload();
  }
  defineExpose({ applyFilter });
  onMounted(() => {
    load();
    getLogicOverview()
      .then((r) => {
        typeOptions.value = Object.keys(r.types || {})
          .sort()
          .map((t) => ({ label: t, value: t }));
      })
      .catch(() => {});
  });

  const sourceTag = (r: any) =>
    r.overridden
      ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => '自定义·覆盖内置')
      : r.custom
      ? h(NTag, { type: 'success', size: 'small', bordered: false }, () => '自定义')
      : h(NTag, { size: 'small', bordered: false }, () => '内置');

  const columns = computed<any[]>(() => [
    {
      title: '脚本',
      key: 'id',
      width: 240,
      ellipsis: { tooltip: true },
      render: (r) =>
        h('div', [
          h('div', { style: 'font-weight:500' }, r.name || r.id),
          h('div', { style: 'font-size:12px;color:#999' }, r.id + '.js'),
        ]),
    },
    { title: '描述', key: 'desc', ellipsis: { tooltip: true } },
    {
      title: '类型',
      key: 'type',
      width: 90,
      render: (r) => (r.type ? h(NTag, { size: 'small', bordered: false }, () => r.type) : '-'),
    },
    {
      title: '阶段',
      key: 'phase',
      width: 110,
      render: (r) =>
        r.phase ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => r.phase) : '-',
    },
    { title: '作者', key: 'author', width: 100, ellipsis: { tooltip: true } },
    { title: '来源', key: 'source', width: 130, render: sourceTag },
    {
      title: '启用',
      key: 'disabled',
      width: 70,
      render: (r) =>
        h(NSwitch, {
          size: 'small',
          value: !r.disabled,
          loading: toggling.value === r.id,
          onUpdateValue: (v: boolean) => toggle(r, v),
        }),
    },
    {
      title: '状态',
      key: 'status',
      width: 90,
      render: (r) =>
        r.disabled
          ? h(NTag, { size: 'small', bordered: false }, () => '已停用')
          : r.error
          ? h(NTag, { type: 'error', size: 'small', bordered: false }, () => '编译失败')
          : h(NTag, { type: 'success', size: 'small', bordered: false }, () => '正常'),
    },
    {
      title: '操作',
      key: 'action',
      width: 130,
      fixed: 'right',
      render: (r) =>
        h(NSpace, { size: 4 }, () => [
          h(
            NButton,
            { size: 'tiny', text: true, type: 'primary', onClick: () => openView(r) },
            () => '查看'
          ),
          h(
            NButton,
            { size: 'tiny', text: true, type: 'primary', onClick: () => emit('debug', r.id) },
            () => '调试'
          ),
          r.custom
            ? h(
                NButton,
                { size: 'tiny', text: true, type: 'error', onClick: () => del(r) },
                () => '删除'
              )
            : null,
        ]),
    },
  ]);

  // 启用/停用
  const toggling = ref('');
  function toggle(r: any, v: boolean) {
    toggling.value = r.id;
    setLogicScriptEnabled({ id: r.id, enable: v })
      .then((res: any) => {
        r.disabled = !v;
        message.success(typeof res === 'string' ? res : v ? '已启用' : '已停用');
      })
      .catch(() => load())
      .finally(() => (toggling.value = ''));
  }

  function del(r: any) {
    dialog.warning({
      title: '删除脚本',
      content: r.overridden
        ? `确认删除自定义脚本 ${r.id}.js？删除后恢复为内置版本。`
        : `确认删除自定义脚本 ${r.id}.js？`,
      positiveText: '删除',
      negativeText: '取消',
      onPositiveClick: () =>
        delLogicScript({ id: r.id }).then((res: any) => {
          message.success(typeof res === 'string' ? res : '已删除');
          load();
        }),
    });
  }

  const processFile = ({ file, onFinish, onError }: UploadCustomRequestOptions) => {
    const fd = new FormData();
    fd.append('file', file.file as File);
    uploadLogicFile(fd)
      .then((r: any) => {
        if (r?.ok === false) {
          message.warning(
            r.message ? `${r.message}，但脚本编译失败：${r.error}` : '已导入，但脚本编译失败'
          );
        } else {
          message.success(r?.message || '上传成功');
        }
        onFinish();
        load();
      })
      .catch(() => onError());
  };

  // 查看 / 编辑
  const showView = ref(false);
  const editing = ref(false);
  const cur = reactive<any>({});
  const content = ref('');
  const newId = ref('my_check');
  const check = ref<any>(null);
  const checking = ref(false);
  const saving = ref(false);
  const jsHtml = computed(() => highlightJs(content.value));

  function resetCur(r: any = {}) {
    Object.keys(cur).forEach((k) => delete cur[k]);
    Object.assign(cur, r);
    check.value = null;
  }
  function openView(r: any) {
    getLogicScriptContent({ id: r.id }).then((c) => {
      resetCur({ ...r, ...(c?.meta || {}) });
      content.value = c?.content || '';
      editing.value = false;
      showView.value = true;
    });
  }
  function openNew() {
    resetCur();
    newId.value = 'my_check';
    content.value = SCRIPT_TEMPLATE;
    editing.value = true;
    showView.value = true;
  }
  function goGuide() {
    showView.value = false;
    emit('goto', 'guide');
  }
  function doValidate() {
    checking.value = true;
    return validateLogicScript({ id: cur.id || newId.value, content: content.value })
      .then((r) => {
        check.value = r;
        return r;
      })
      .finally(() => (checking.value = false));
  }
  function doSave() {
    const id = cur.id || newId.value;
    saving.value = true;
    saveLogicScript({ id, content: content.value })
      .then((r) => {
        check.value = r;
        if (r.ok) message.success('已保存');
        else message.warning('已保存，但脚本编译失败，不会生效');
        showView.value = false;
        load();
      })
      .finally(() => (saving.value = false));
  }
</script>

<style lang="less" scoped>
  .guide-tip {
    font-size: 12px;
    color: #999;
    margin-bottom: 10px;
  }
  .guide-link {
    color: #2d8cf0;
    cursor: pointer;
    &:hover {
      text-decoration: underline;
    }
  }
  .js-view {
    background: #0d1117;
    color: #c9d1d9;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.6;
    border-radius: 6px;
    padding: 12px 14px;
    overflow: auto;
    max-height: 55vh;
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
  :deep(.CodeMirror) {
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
  }
</style>
