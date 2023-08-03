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
      placeholder="填写webshell内容"
      type="textarea"
      size="small"
      :autosize="{
        minRows: 10,
        maxRows: 40
      }"
      show-count clearable
      v-model:value="textValue.webshell"
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
        <n-button @click="uploadWebshell">
          <template #icon>
            <n-icon>
              <PlusOutlined />
            </n-icon>
          </template>
          上传webshell文件
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
      <n-form-item label="webshell" path="webshell">
        <n-select
          placeholder="请选择文件"
          label-field="label"
          value-field="value"
          children-field="children"
          filterable
          :options="webshellList"
          v-model:value="formParams.webshell"
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

  <n-modal  v-model:show="showModal2" :show-icon="false" preset="dialog" title="详情">
        <n-card
          title=""
          preset="card"
          :bordered="false"
          size="huge"
          :segmented="{
              content: 'soft',
              footer: 'soft' 
            }"
        >
          <template #header-extra>
            {{detailsParams.key["name"]}}
          </template>
          {{detailsParams}}
          <template #footer>
            尾部
          </template>
        </n-card>
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
  import { h, reactive, ref } from 'vue';
  import { useMessage } from 'naive-ui';
  import { BasicTable, TableAction } from '@/components/Table';
  import { useForm } from '@/components/Form/index';
  import { getWebshellTableList,getTableRiskWebshellList,addTableRiskWebshellList,addOnceRiskWebshellList,delTableRiskWebshellList } from '@/api/table/list';
  import { columns } from './columns';
  import { PlusOutlined } from '@vicons/antd';
  import { useRouter } from "vue-router";

 const webshellList = ref<Array<String>>([]);

  const getWebshellDataTable = async () => {
    return await getWebshellTableList({pageSize:10000,page:1});
  };

  // 从 api 接口获取 webshellList
  function getWebshellList () {
    getWebshellDataTable().then(
      function(resp){
        var arr = new Array();
        for (let i = 0; i < resp["list"].length; i++) {
          arr.push(
            {
                label: resp["list"][i]["name"],
                value: resp["list"][i]["id"],
            })
        }
        webshellList.value = arr;
      }
    );
  }


  const router = useRouter();
  const formRef: any = ref(null);
  const message = useMessage();
  const actionRef = ref();

  const showModal = ref(false);
  const formBtnLoading = ref(false);

  const showModal2 = ref(false);


  const initialState = {
    webshell: `<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"  version="1.2"> 
<jsp:directive.page contentType="text/html" pageEncoding="UTF-8" /> 
<jsp:scriptlet> 
Runtime.getRuntime().exec(request.getParameter("i")); 
</jsp:scriptlet> 
</jsp:root>`,
  };

  const formParams = reactive({ ...initialState });

  const textValue = reactive({ ...initialState });

  const detailsParams = reactive({...columns[0]});

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
            label: '详情',
            onClick: handleDetail.bind(null, record),
            ifShow: () => {
              return true;
            },
            auth: ['basic_list'],
          },
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
    formParams.webshell = "";
    getWebshellList();
    showModal.value = true;
  }


  const addDataTable = async (res) => {
    return await addTableRiskWebshellList({ ...res});
  };

  const addOnceDataTable = async (res) => {
    return await addOnceRiskWebshellList({ ...res});
  };


  const loadDataTable = async (res) => {
    return await getTableRiskWebshellList({ ...formParams, ...params.value, ...res });
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
    setTimeout(() => {
      delTableRiskWebshellList(record);
      reloadTable();
    }, 500);
  }

  function uploadWebshell(record: Recordable) {
  let routeData = router.resolve({ name: "webshell-list", query: { uid: record.uid } });
  window.open(routeData.href, "_blank");
  }

// 即时检测 formSubmit

function textSubmit(e) {
    e.preventDefault();
    formBtnLoading.value = true;
    formRef.value.validate((errors) => {
      if (!errors) {
        addOnceDataTable(textValue).then((resp)=>{
          if (resp.result.webshell == "true"){
            message.success("检测到webshell");
          }else{
            message.success(resp.result.message);
          }
        });
      } else {
        message.error('请填写完整信息');
      }
      formBtnLoading.value = false;
    });
  }

function resetForm(){
  textValue.webshell = "";
}


function handleDetail(record: Recordable) {
    Object.assign(detailsParams, record);
    console.log(detailsParams);
    showModal2.value = true;
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
