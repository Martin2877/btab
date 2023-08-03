<template>
  <div>
    <n-card :bordered="false" class="proCard">
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
    </n-card>
  </div>
</template>

<script lang="ts" setup>
import { h, reactive, ref } from "vue";
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
  getStrategyTableList,
} from "@/api/table/list";

import { columns } from "./columns";
import { PlusOutlined } from "@vicons/antd";
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
  item: {
    required: true,
    message: "请输入检测项",
  },
};

const router = useRouter();
const formRef: any = ref(null);
const message = useMessage();
const actionRef = ref();

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
  return await getPATableList({ ...formParams, ...params.value, ...res });
};

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
  return await submitPATask({ ...res });
};

function reloadTable() {
  Object.assign(formParams, initialState);
  actionRef.value.reload();
}

function confirmForm(e) {
  e.preventDefault();
  formBtnLoading.value = true;
  formRef.value.validate((errors) => {
    if (!errors) {
      submitPATaskReq(formParams);
      message.success("新建成功");
      setTimeout(() => {
        showModal.value = false;
        reloadTable();
      });
    } else {
      message.error("请填写完整信息");
    }
    formBtnLoading.value = false;
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

<style lang="less" scoped></style>
