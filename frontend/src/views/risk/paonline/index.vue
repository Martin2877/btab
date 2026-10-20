<template>
  <div>
    <n-card :bordered="false" class="proCard">
      <n-alert
        v-if="tsharkChecked && !tsharkStatus.ok"
        type="warning"
        :show-icon="true"
        title="tshark 不可用，流量包检测将无法执行"
        style="margin-bottom: 12px"
      >
        {{ tsharkStatus.error || '未检测到 tshark 可执行文件' }}
        <n-button size="small" text type="primary" @click="goSetting" style="margin-left: 8px">
          前往系统设置
        </n-button>
      </n-alert>
      <BasicTable
        :columns="columns"
        :request="loadDataTable"
        :row-key="(row) => row.id"
        ref="actionRef"
        :actionColumn="actionColumn"
        @update:checked-row-keys="onCheckedRow"
        :scroll-x="1090"
      >
        <template #tableTitle>
          <n-button type="primary" @click="addTable">
            <template #icon>
              <n-icon>
                <PlusOutlined />
              </n-icon>
            </template>
            添加检测任务
          </n-button>
          <n-button @click="uploadPcap">
            <template #icon>
              <n-icon>
                <PlusOutlined />
              </n-icon>
            </template>
            上传流量包
          </n-button>
          <n-button :loading="formBtnLoading" @click="runDemo">示例</n-button>
        </template>

        <template #toolbar>
          <n-button type="primary" @click="reloadTable">刷新数据</n-button>
        </template>
      </BasicTable>

      <n-modal
        v-model:show="showModal"
        :show-icon="false"
        preset="dialog"
        title="添加检测任务"
        :style="{ width: '800px' }"
      >
        <n-form
          :model="formParams"
          :rules="rules"
          ref="formRef"
          label-placement="left"
          :label-width="80"
          class="py-4"
        >
          <n-form-item label="任务名称" path="name">
            <n-input placeholder="请输入任务名称" v-model:value="formParams.name" />
          </n-form-item>
          <n-form-item label="流量包" path="pcap">
            <n-select
              placeholder="请选择流量包"
              :options="pcapList"
              v-model:value="formParams.pcap"
            />
          </n-form-item>

          <!-- <n-form-item label="检测项" path="item">
            <n-select
              placeholder="请选择检测项"
              label-field="label"
              value-field="value"
              children-field="children"
              filterable
              :options="itemList"
              v-model:value="formParams.item"
            />
          </n-form-item> -->

          <n-form-item label="检测项" path="strategy">
            <n-transfer
              ref="transfer"
              v-model:value="formParams.strategy"
              :options="options2"
              virtual-scroll
              source-filterable
              target-filterable
            />
          </n-form-item>
        </n-form>

        <template #action>
          <n-space>
            <n-button @click="() => (showModal = false)">取消</n-button>
            <n-button type="info" :loading="formBtnLoading" @click="confirmForm"
              >确定</n-button
            >
          </n-space>
        </template>
      </n-modal>

      <n-modal
        v-model:show="showResultModal"
        :show-icon="false"
        preset="dialog"
        :title="`检测结果${resultTask ? ' - ' + resultTask.name : ''}`"
        :style="{ width: '900px' }"
      >
        <div v-if="resultRunning" style="margin-bottom: 12px">
          <n-progress
            type="line"
            :percentage="resultPercent"
            indicator-placement="inside"
            processing
          />
          <div style="margin-top: 6px; color: #888; font-size: 12px">
            正在检测：已完成 {{ resultDone }}/{{ resultTotal }} 个策略，已检出
            {{ resultEvents.length }} 条事件
          </div>
        </div>
        <n-alert
          v-if="resultErrors.length > 0"
          type="warning"
          :show-icon="false"
          style="margin-bottom: 12px"
          title="策略执行异常"
        >
          <div v-for="(e, i) in resultErrors" :key="i">{{ e }}</div>
        </n-alert>
        <div v-if="resultEvents.length" class="result-summary">
          <n-tag size="small" :bordered="false">检出 {{ resultEvents.length }} 条</n-tag>
          <n-tag v-if="attackCount" size="small" type="error" :bordered="false">
            攻击事件 {{ attackCount }} 条
          </n-tag>
        </div>
        <div v-if="resultEvents.length" class="event-list">
          <n-card
            v-for="(ev, i) in resultEvents"
            :key="i"
            size="small"
            class="event-card"
            :class="{ 'is-attack': ev.type === 'attack' }"
          >
            <template #header>
              <n-space align="center" :size="8" :wrap-item="false">
                <n-tag
                  v-if="ev.severity"
                  size="small"
                  :bordered="false"
                  :color="{ color: sevColor(ev.severity), textColor: '#fff' }"
                >
                  {{ ev.severity }}
                </n-tag>
                <span class="event-name">{{ ev.name || '未命名事件' }}</span>
                <n-tag
                  v-if="ev.type"
                  size="small"
                  :type="ev.type === 'attack' ? 'error' : 'default'"
                >
                  {{ ev.type }}
                </n-tag>
                <n-tag v-if="ev.phase" size="small" type="info" :bordered="false">
                  {{ ev.phase }}
                </n-tag>
                <n-tag v-if="ev.strategy" size="small" type="warning" :bordered="false">
                  {{ ev.strategy }}
                </n-tag>
              </n-space>
            </template>
            <template v-if="ev.desc" #header-extra>
              <n-button text size="tiny" @click="copyText(ev.desc)">
                <template #icon>
                  <n-icon><CopyOutlined /></n-icon>
                </template>
              </n-button>
            </template>
            <div class="event-meta">
              <div class="meta-row">
                <span class="meta-label">源地址</span>
                <span class="meta-val">{{ (ev.src || []).join(', ') || '?' }}</span>
              </div>
              <div class="meta-row">
                <span class="meta-label">目的地址</span>
                <span class="meta-val">{{ (ev.dst || []).join(', ') || '?' }}</span>
              </div>
            </div>
            <pre v-if="ev.desc" class="event-desc">{{ ev.desc }}</pre>
          </n-card>
        </div>
        <n-empty
          v-else-if="!resultRunning"
          description="未检出事件"
          style="padding: 24px 0"
        />
        <template #action>
          <n-button @click="() => (showResultModal = false)">关闭</n-button>
        </template>
      </n-modal>
    </n-card>
  </div>
</template>

<script lang="ts" setup>
import { h, computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import {
  useMessage,
  SelectOption,
  SelectGroupOption,
  // NTree,
  // TransferRenderSourceList,
} from "naive-ui";
import { BasicTable, TableAction } from "@/components/Table";
import { useForm } from "@/components/Form/index";
import {
  submitPATask,
  getSecTypeTableList,
  getPcapTableList,
  getPATableList,
  getPAProgress,
  getStrategyTableList,
} from "@/api/table/list";
import { getSystemConfig } from "@/api/system/system";

import { columns } from "./columns";
import { PlusOutlined, CopyOutlined } from "@vicons/antd";
import { useRouter } from "vue-router";
// import { repeat } from "seemly";
// import { kMaxLength } from "buffer";
// import { Options } from "@vicons/ionicons5";

const pcapList = ref<Array<String>>([]);

const itemList = ref<Array<SelectOption | SelectGroupOption | Option>>([]);

const sec_typeList = ref<Array<String>>([]);
const strategyList = ref<Array<String>>([]);

// 从 api 接口获取 apiList
function getPcapList() {
  getPcapTableList({ pageSize: 10000, page: 1 }).then(function (resp) {
    var arr = new Array();
    for (let i = 0; i < resp["list"].length; i++) {
      arr.push({
        label: resp["list"][i]["name"],
        value: resp["list"][i]["id"],
      });
    }
    pcapList.value = arr;
  });
}

// 从 api 接口获取 SecTypeList
function getSecTypeList() {
  getSecTypeTableList({ pageSize: 10000, page: 1 }).then(function (resp) {
    var arr = new Array();
    for (let i = 0; i < resp["list"].length; i++) {
      arr.push({
        label: resp["list"][i]["name"],
        // value: {"sec_type":resp["list"][i]["id"]},
        value: "sec_type_" + resp["list"][i]["id"],
      });
    }
    sec_typeList.value = arr;
  });
}

// 从 api 接口获取 StrategyList
function getStratgyList() {
  getStrategyTableList({ pageSize: 10000, page: 1 }).then(function (resp) {
    var arr = new Array();
    for (let i = 0; i < resp["list"].length; i++) {
      arr.push({
        label: resp["list"][i]["name"],
        // value: {"strategy": resp["list"][i]["id"]},
        value: "strategy_" + resp["list"][i]["id"],
      });
    }
    strategyList.value = arr;
  });
}

function getItemOptions() {
  getSecTypeList();
  getStratgyList();
  setTimeout(() => {
    var arr = new Array();
    arr.push(
      {
        type: "group",
        label: "安全分类",
        key: "SecType",
        children: sec_typeList,
      },
      {
        type: "group",
        label: "策略",
        key: "Strategy",
        children: strategyList,
      }
    );
    itemList.value = arr;
  });
}

// function createLabel(level: number): string {
//   if (level === 4) return "道生一";
//   if (level === 3) return "一生二";
//   if (level === 2) return "二生三";
//   if (level === 1) return "三生万物";
//   return "";
// }

type Option = {
  label: string;
  value: string;
  children?: Option[];
};

// function createData(level = 4, baseKey = ""): Option[] | undefined {
//   if (!level) return undefined;
//   return repeat(6 - level, undefined).map((_, index) => {
//     const value = "" + baseKey + level + index;
//     return {
//       label: createLabel(level),
//       value,
//       children: createData(level - 1, value),
//     };
//   });
// }

// 加载 createData 数据
function createData(): Option[] | undefined {
  var arr = new Array<Option>();
  // 内置引擎：nuclei 规则检测 + 跨会话分析（值为 engine_ 前缀，由后端识别）
  arr.push(
    { label: 'nuclei 规则检测（内置引擎）', value: 'engine_nuclei' },
    { label: '跨会话分析 / webshell（内置引擎）', value: 'engine_session' },
  );
  getStrategyTableList({ pageSize: 10000, page: 1 }).then(function (resp) {
    for (let i = 0; i < resp["list"].length; i++) {
      arr.push({
        label: resp["list"][i]["name"],
        // value: {"strategy": resp["list"][i]["id"]},
        value: resp["list"][i]["id"],
        // value: resp["list"][i]["name"],
      });
    }
  });
  console.log(arr);
  return arr;
}

// function flattenTree(list: undefined | Option[]): Option[] {
//   const result: Option[] = [];
//   function flatten(_list: Option[] = []) {
//     _list.forEach((item) => {
//       result.push(item);
//       flatten(item.children);
//     });
//   }
//   flatten(list);
//   return result;
// }

// const treeData = createData();
const valueRef = ref<Array<string | number>>([]);
// const renderSourceList: TransferRenderSourceList = function ({ onCheck, pattern }) {
//   return h(NTree, {
//     style: "margin: 0 4px;",
//     keyField: "value",
//     checkable: true,
//     selectable: false,
//     blockLine: true,
//     checkOnClick: true,
//     data: treeData,
//     pattern,
//     checkedKeys: valueRef.value,
//     onUpdateCheckedKeys: (checkedKeys: Array<string | number>) => {
//       onCheck(checkedKeys);
//     },
//   });
// };

const options2 = createData();
// const options2 = ref(flattenTree(createData()));
const value2 = valueRef;

// -------------------------------------

const rules = {
  name: {
    required: true,
    message: "请输入任务名称",
  },
  pcap: {
    required: true,
    type: "number",
    message: "请选择流量包",
    trigger: ["blur", "change"],
  },
  item: {
    required: true,
    message: "请输入检测项",
  },
};

const router = useRouter();
const formRef: any = ref(null);
const message = useMessage();
const actionRef = ref();

// tshark 可用性检查：不可用时在页面顶部提示并引导至系统设置
const tsharkStatus = ref<any>({ ok: true });
const tsharkChecked = ref(false);

function loadTsharkStatus() {
  getSystemConfig()
    .then((resp) => {
      tsharkStatus.value = (resp && resp.tshark) || { ok: true };
      tsharkChecked.value = true;
    })
    .catch(() => {});
}

function goSetting() {
  router.push({ name: "setting-system" });
}

onMounted(loadTsharkStatus);

// ---------- 检测结果详情 / 实时进度 ----------
const showResultModal = ref(false);
const resultTask = ref<any>(null);
const resultEvents = ref<any[]>([]);
const resultErrors = ref<string[]>([]);
const resultRunning = ref(false);
const resultDone = ref(0);
const resultTotal = ref(0);

const resultPercent = computed(() =>
  resultTotal.value > 0 ? Math.round((resultDone.value / resultTotal.value) * 100) : 0
);

const attackCount = computed(
  () => resultEvents.value.filter((e) => e.type === "attack").length
);

// 检出等级配色：critical 红 / high 橙 / medium 金 / low 绿 / info 灰
const sevColor = (s?: string) => {
  switch (String(s || "").toLowerCase()) {
    case "critical":
      return "#d03050";
    case "high":
      return "#e8801a";
    case "medium":
      return "#d9a021";
    case "low":
      return "#18a058";
    default:
      return "#909399";
  }
};

function copyText(text: string) {
  navigator.clipboard
    .writeText(text)
    .then(() => message.success("已复制"))
    .catch(() => message.error("复制失败"));
}

async function fetchProgress() {
  if (!resultTask.value) return;
  try {
    const resp = await getPAProgress({ id: resultTask.value.id });
    resultEvents.value = resp.events || [];
    resultErrors.value = resp.errors || [];
    resultDone.value = resp.done || 0;
    resultTotal.value = resp.total || 0;
    resultRunning.value = !!resp.running;
  } catch (e) {}
}

let resultTimer: any = null;
function stopResultPolling() {
  if (resultTimer) {
    clearInterval(resultTimer);
    resultTimer = null;
  }
}
function startResultPolling() {
  stopResultPolling();
  resultTimer = setInterval(async () => {
    await fetchProgress();
    if (!resultRunning.value) {
      stopResultPolling();
      reloadTable(); // 任务结束同步刷新列表状态
    }
  }, 1500);
}

function showResult(record) {
  resultTask.value = record;
  resultEvents.value = [];
  resultErrors.value = [];
  resultRunning.value = record.state === 1;
  resultDone.value = 0;
  resultTotal.value = 0;
  showResultModal.value = true;
}

watch(showResultModal, (v) => {
  if (v) {
    fetchProgress();
    startResultPolling();
  } else {
    stopResultPolling();
  }
});
onUnmounted(stopResultPolling);

// 存在运行中的任务时自动刷新列表
let listTimer: any = null;
function scheduleListRefresh(hasRunning: boolean) {
  if (listTimer) {
    clearTimeout(listTimer);
    listTimer = null;
  }
  if (hasRunning) {
    listTimer = setTimeout(() => {
      if (actionRef.value) actionRef.value.reload();
    }, 2000);
  }
}
onUnmounted(() => {
  if (listTimer) clearTimeout(listTimer);
});

const showModal = ref(false);
const formBtnLoading = ref(false);

const initialState = {
  name: "test",
  pcap: "",
  sec_type: Number(),
  strategy: [],
  item: "",
};
const formParams = reactive({ ...initialState });

const params = ref({
  // name: null,
  // state: null,
  pageSize: 10,
});

const actionColumn = reactive({
  width: 160,
  title: "操作",
  key: "action",
  fixed: "right",
  render(record) {
    return h(TableAction as any, {
      style: "button",
      actions: [
        // {
        //   label: "详情",
        //   onClick: handleDetail.bind(null, record),
        //   ifShow: () => {
        //     return true;
        //   },
        //   auth: ["basic_list"],
        // },
        {
          label: "结果",
          onClick: showResult.bind(null, record),
          ifShow: () => {
            return true;
          },
          auth: ["basic_list"],
        },
        {
          label: "删除",
          onClick: handleDelete.bind(null, record),
          ifShow: () => {
            return true;
          },
          auth: ["basic_list"],
        },
      ],
    });
  },
});

const [{}] = useForm({
  gridProps: { cols: "1 s:1 m:2 l:3 xl:4 2xl:4" },
  labelWidth: 80,
});

function addTable() {
  Object.assign(formParams, initialState);
  // 点击添加时，调用读取 API 和策略列表
  getPcapList();
  getItemOptions();
  showModal.value = true;
}

const loadDataTable = async (res) => {
  const resp = await getPATableList({ ...formParams, ...params.value, ...res });
  const hasRunning = (resp.list || []).some((r) => r.state === 1);
  scheduleListRefresh(hasRunning);
  return resp;
};

// 示例：选择体积最小的内置流量包，以全部策略提交演示任务并打开结果
async function runDemo() {
  formBtnLoading.value = true;
  try {
    const resp = await getPcapTableList({ pageSize: 10000, page: 1 });
    const list = (resp && resp["list"]) || [];
    if (!list.length) {
      message.error("暂无可用流量包，请先上传");
      return;
    }
    // 优先使用内置示例包（检测命中率高），否则取体积最小的一个
    const prefer = ["sqlinjection", "log4j_test2", "log4j"];
    const demo =
      prefer.map((k) => list.find((p) => (p.name || "").includes(k))).find(Boolean) ||
      list.reduce((a, b) => ((a.size || 0) <= (b.size || 0) ? a : b));
    const name = `示例检测-${demo.name}`;
    const sub = await submitPATask({ name, pcap: demo.id, strategy: [] });
    const id = sub?.result?.id;
    message.success("示例任务已提交，正在检测");
    reloadTable();
    if (id) {
      showResult({ id, name, state: 1 });
    }
  } catch (e) {
    message.error("示例任务提交失败");
  } finally {
    formBtnLoading.value = false;
  }
}

function uploadPcap(record: Recordable) {
  let routeData = router.resolve({ name: "pcap-list", query: { uid: record.uid } });
  window.open(routeData.href, "_blank");
}

// const submitPATaskReq = async (res) => {
//   if (formParams.item.includes("sec_type")) {
//     formParams.sec_type = parseInt(formParams.item.split("_")[2]);
//     formParams.strategy = Number.NaN;
//   } else if (formParams.item.includes("strategy")) {
//     formParams.strategy = Number.NaN;
//     formParams.strategy = parseInt(formParams.item.split("_")[1]);
//   }
//   return await submitPATask({ ...formParams, ...params.value, ...res });
// };

const submitPATaskReq = async (res) => {
  return await submitPATask({
    name: res.name,
    pcap: res.pcap,
    strategy: res.strategy,
  });
};

function reloadTable() {
  Object.assign(formParams, initialState);
  actionRef.value.reload();
}

function confirmForm(e) {
  e.preventDefault();
  formRef.value.validate(async (errors) => {
    if (errors) {
      message.error("请填写完整信息");
      return;
    }
    formBtnLoading.value = true;
    try {
      const resp: any = await submitPATaskReq(formParams);
      if (resp && resp.code === 200) {
        message.success("新建成功");
        showModal.value = false;
        reloadTable();
      } else {
        message.error(resp?.message || "新建失败");
      }
    } catch (err) {
      message.error("新建任务提交失败");
    } finally {
      formBtnLoading.value = false;
    }
  });
}

function onCheckedRow(rowKeys) {
  console.log(rowKeys);
}

function handleDetail(record: Recordable) {
  // console.log('点击了详情', record);
  // router.push({ name: 'traderbot-info', query: { uid: record.uid } });
  let routeData = router.resolve({ name: "traderbot-info", query: { uid: record.uid } });
  window.open(routeData.href, "_blank");
}

function handleDelete(record: Recordable) {
  message.info("点击了删除");
  setTimeout(() => {
    showModal.value = false;
    reloadTable();
  }, 500);
}
</script>

<style lang="less" scoped>
.result-summary {
  display: flex;
  gap: 8px;
  margin-bottom: 10px;
}
.event-list {
  max-height: 520px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-right: 4px;
}
.event-card {
  &.is-attack {
    border-left: 3px solid #d03050;
  }
  :deep(.n-card-header) {
    padding: 8px 12px;
  }
  :deep(.n-card__content) {
    padding: 8px 12px;
  }
}
.event-name {
  font-weight: 600;
}
.event-meta {
  margin-bottom: 6px;
}
.meta-row {
  display: flex;
  align-items: baseline;
  font-size: 12px;
  line-height: 1.8;
}
.meta-label {
  flex: none;
  width: 52px;
  opacity: 0.55;
}
.meta-val {
  font-family: monospace;
  word-break: break-all;
}
.event-desc {
  margin: 0;
  padding: 8px 10px;
  background: rgba(128, 128, 128, 0.08);
  border: 1px solid rgba(128, 128, 128, 0.15);
  border-radius: 4px;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
}
</style>
