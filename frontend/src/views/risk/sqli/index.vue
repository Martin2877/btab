<template>
<div>


<n-form
  :model="textValue"
  ref="formRef"
  label-placement="left"
  class="py-8"
>
  <n-space vertical>
    <n-input
      placeholder="填写sqli内容"
      type="textarea"
      size="medium"
      :autosize="{
        minRows: 4,
        maxRows: 10
      }"
      show-count clearable
      v-model:value="textValue.payload"
    />
  </n-space>
  <n-space>
      <n-button type="primary" :loading="formBtnLoading" @click="textSubmit">提交检测</n-button>
      <n-button @click="resetForm">重置</n-button>
    </n-space>
</n-form>

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
        <n-button @click="uploadSqli">
          <template #icon>
            <n-icon>
              <PlusOutlined />
            </n-icon>
          </template>
          上传sqli文件
        </n-button>
      </template>

      <template #toolbar>
        <n-button type="primary" @click="reloadTable">刷新数据</n-button>
      </template>
    </BasicTable>

    <n-modal v-model:show="showModal" :show-icon="false" preset="dialog" title="添加检测任务">
      <n-form
        :model="formParams"
        ref="formRef"
        label-placement="left"
        :label-width="80"
        class="py-4"
      >
      <n-form-item label="payload" path="payload">
        <n-select
          placeholder="请选择文件"
          label-field="label"
          value-field="value"
          children-field="children"
          filterable
          :options="sqliList"
          v-model:value="formParams.payload"
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
</div>
</template>

<script lang="ts" setup>
import { h, reactive, ref } from 'vue';
import { useMessage } from 'naive-ui';
import { BasicTable, TableAction } from '@/components/Table';
import {  useForm } from '@/components/Form/index';
import { getPayloadTableList,getTableRiskSqliList,addTableRiskSqliList,addOnceRiskSqliList,delTableRiskSqliList } from '@/api/table/list';
import { columns } from './columns';
import { PlusOutlined } from '@vicons/antd';
import { useRouter } from "vue-router";

const sqliList = ref<Array<String>>([]);

const getSqliDataTable = async () => {
  return await getPayloadTableList({pageSize:10000,page:1});
};

// 从 api 接口获取 sqliList
function getSqliList () {
  getSqliDataTable().then(
    function(resp){
      var arr = new Array();
      for (let i = 0; i < resp["list"].length; i++) {
        arr.push(
          {
              label: resp["list"][i]["name"],
              value: resp["list"][i]["id"],
          })
      }
      sqliList.value = arr;
    }
  );
}


// const rules = {
//   sqlifile: {
//     required: false,
//     trigger: ['input'],
//     message: '请选择 sqli 文件',
//   },
// };


const router = useRouter();
const formRef: any = ref(null);
const message = useMessage();
const actionRef = ref();

const showModal = ref(false);
const formBtnLoading = ref(false);

const initialState = {
  payload: `) or true--","' or 'x'='x","'`,
};

const formParams = reactive({ ...initialState });

const textValue = reactive({ ...initialState });


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
          ifShow: () => {
            return true;
          },
          auth: ['basic_list'],
        },
      ],
    },)
  }
});

const [{}] = useForm({
  gridProps: { cols: '1 s:1 m:2 l:3 xl:4 2xl:4' },
  labelWidth: 80,
});

function addTable() {
  Object.assign(formParams, initialState);
  // 点击添加时，调用读取
  getSqliList();
  showModal.value = true;
}


const addDataTable = async (res) => {
  return await addTableRiskSqliList({ ...res});
};

const addOnceDataTable = async (res) => {
  return await addOnceRiskSqliList({ ...res});
};


const loadDataTable = async (res) => {
  return await getTableRiskSqliList({ ...formParams, ...params.value, ...res });
};


function onCheckedRow(rowKeys) {
  console.log(rowKeys);
}

function reloadTable() {
  Object.assign(formParams, initialState);
  actionRef.value.reload();
}

function confirmForm(e) {
  e.preventDefault();
  formBtnLoading.value = true;
  formRef.value.validate((errors) => {
    if (!errors) {
      addDataTable(formParams);
      message.success('新建成功');
      setTimeout(() => {
        showModal.value = false;
        reloadTable();
      },500);
    } else {
      message.error('请填写完整信息');
    }
    formBtnLoading.value = false;
  });
}

function handleDelete(record: Recordable) {
  message.info("点击了删除");
  setTimeout(() => {
    delTableRiskSqliList(record);
    reloadTable();
  }, 500);
}

function uploadSqli(record: Recordable) {
  let routeData = router.resolve({ name: "payload-list", query: { uid: record.uid } });
  window.open(routeData.href, "_blank");
}

// 即时检测 formSubmit

function textSubmit(e) {
    e.preventDefault();
    formBtnLoading.value = true;
    formRef.value.validate((errors) => {
      if (!errors) {
        addOnceDataTable(textValue).then((resp)=>{
          message.success(resp.result.result);
        });
      } else {
        message.error('请填写完整信息');
      }
      formBtnLoading.value = false;
    });
  }

function resetForm(){
  textValue.payload = "";
}



</script>

<style lang="less" scoped>
  .light-green {
    display: flex;
    align-items: center;
    justify-content: center;
    // height: 200px;
    // background-color: rgba(0, 128, 0, 0.12);
  }
</style>
