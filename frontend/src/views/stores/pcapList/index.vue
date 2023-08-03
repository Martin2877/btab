<template>
  <div>
  <n-upload
    ref="fileRef"
    multiple
    directory-dnd
    action="https://www.mocky.io/v2/5e4bafc63100007100d8b70f"
    :max="5"
    :custom-request="processFile"
    @click="clearList"
  >
    <n-upload-dragger>
      <div style="margin-bottom: 3px">
        <n-icon size="30" :depth="3">
          <archive-icon />
        </n-icon>
      </div>
      <n-text style="font-size: 12px"> 点击或者拖动文件到该区域来上传 </n-text>
      <n-p depth="3" style="margin: 1px 0 0 0; font-size: 1px"> 大小限制 50m </n-p>
    </n-upload-dragger>
  </n-upload>

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
        <n-button type="primary" @click="openDir">
          <template #icon>
            <n-icon>
              <PlusOutlined />
            </n-icon>
          </template>
          文件目录
        </n-button>
      </template>

      <template #toolbar>
        <n-button type="primary" @click="reloadTable">刷新数据</n-button>
      </template>
    </BasicTable>

    <n-modal v-model:show="showModal" :show-icon="false" preset="dialog" title="">
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
import { useMessage,UploadCustomRequestOptions } from "naive-ui";
import { BasicTable, TableAction } from "@/components/Table";
// import { BasicForm } from "@/components/Form/index";
import { getPcapTableList, openDirReq, uploadDataReq, delPcapTableList } from "@/api/table/list";
import { columns } from "./columns";
import { PlusOutlined } from "@vicons/antd";
import { ArchiveOutline as ArchiveIcon } from "@vicons/ionicons5";


const formRef: any = ref(null);
const message = useMessage();
const fileRef = ref();
const actionRef = ref();

const showModal = ref(false);
const formBtnLoading = ref(false);

const initialState = {
  name: "",
  address: "",
  date: null,
};
const formParams = reactive({ ...initialState });

const params = ref({
  pageSize: 5,
});

const choseFile = ref<File>();

const actionColumn = reactive({
  width: 220,
  title: "操作",
  key: "action",
  fixed: "right",
  render(record) {
    return h(TableAction as any, {
      style: "button",
      actions: [
        {
          label: "删除",
          // icon: "ic:outline-delete-outline",
          onClick: handleDelete.bind(null, record),
          // 根据业务控制是否显示 isShow 和 auth 是并且关系
          ifShow: () => {
            return true;
          },
          // 根据权限控制是否显示: 有权限，会显示，支持多个
          auth: ["basic_list"],
        },
      ],
      select: (key) => {
        message.info(`您点击了，${key} 按钮`);
      },
    });
  },
});

// const [register, {}] = useForm({
//   gridProps: { cols: '1 s:1 m:2 l:3 xl:4 2xl:4' },
//   labelWidth: 80,
//   schemas,
// });

// function addTable() {
//   showModal.value = true;
// }

function openDir() {
  openDirRequset().then(function (resp) {
    message.info("存储目录: " + resp);
  });
}

const openDirRequset = async () => {
  return await openDirReq();
};

const loadDataTable = async (res) => {
  return await getPcapTableList({ ...formParams, ...params.value, ...res });
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


function handleDelete(record: Recordable) {
  delPcap(record);
  setTimeout(() => {
          reloadTable();
        });
}

// function handleSubmit(values: Recordable) {
//   console.log(values);
//   reloadTable();
// }

// function handleReset(values: Recordable) {
//   console.log(values);
// }

const uploadData = async (res) => {
  return await uploadDataReq(res);
};

const delPcap = async (res) => {
  return await delPcapTableList(res);
};



const processFile = ({file, data} : UploadCustomRequestOptions) => {
  // const { file } = uploadFileInfo.file;
  // const { data } = uploadFileInfo.data;
  if (data) {
    Object.keys(data).forEach(key => {
      formData.append(key, data[key as keyof UploadCustomRequestOptions['data']])
    })
  }
  choseFile.value = file.file as File;
  let formData = new FormData();
  formData.append("file", choseFile.value as File);
  uploadData(formData);
  setTimeout(() => {
        reloadTable();
      });
};

const clearList = () => {
  fileRef.value.clear();
}


</script>

<style lang="less" scoped></style>
