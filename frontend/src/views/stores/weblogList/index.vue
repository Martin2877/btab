<template>
  <div>
    <n-upload
      ref="fileRef"
      multiple
      directory-dnd
      action=""
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
        <n-text style="font-size: 12px">上传 web 访问日志（nginx / apache，combined / common 格式）</n-text>
        <n-p depth="3" style="margin: 1px 0 0 0; font-size: 1px">大小限制 50m</n-p>
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
        <template #toolbar>
          <n-button type="primary" @click="reloadTable">刷新数据</n-button>
        </template>
      </BasicTable>
    </n-card>

    <n-modal
      v-model:show="showDetail"
      :show-icon="false"
      preset="card"
      :style="{ width: '960px' }"
      :title="detailName || '日志详情'"
    >
      <CodeView :content="detailContent" :filename="detailName" />
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
  import { h, reactive, ref } from 'vue';
  import { useMessage, UploadCustomRequestOptions } from 'naive-ui';
  import { useRouter } from 'vue-router';
  import { BasicTable, TableAction } from '@/components/Table';
  import {
    getWeblogTableList,
    uploadWeblogDataReq,
    delWeblogTableList,
    getWeblogDetailTableList,
  } from '@/api/table/list';
  import { submitAnalyzeTask } from '@/api/analyze';
  import { columns } from './columns';
  import { ArchiveOutline as ArchiveIcon } from '@vicons/ionicons5';
  import CodeView from '@/components/CodeView/index.vue';

  const message = useMessage();
  const router = useRouter();
  const fileRef = ref();
  const actionRef = ref();

  const showDetail = ref(false);
  const detailName = ref('');
  const detailContent = ref('');

  const formParams = reactive({ search: '' });
  const params = ref({ pageSize: 10 });
  const choseFile = ref<File>();

  const analyzing = ref(false);

  const actionColumn = reactive({
    width: 260,
    title: '操作',
    key: 'action',
    fixed: 'right',
    render(record) {
      return h(TableAction as any, {
        style: 'button',
        actions: [
          {
            label: '详情',
            onClick: () => handleDetail(record),
            ifShow: () => true,
            auth: ['basic_list'],
          },
          {
            label: '分析',
            onClick: () => handleAnalyze(record),
            ifShow: () => true,
            auth: ['basic_list'],
          },
          {
            label: '删除',
            onClick: () => handleDelete(record),
            ifShow: () => true,
            auth: ['basic_list'],
          },
        ],
        select: (key) => {
          message.info(`您点击了，${key} 按钮`);
        },
      });
    },
  });

  const loadDataTable = async (res) => {
    return await getWeblogTableList({ ...formParams, ...params.value, ...res });
  };

  function onCheckedRow(rowKeys) {
    console.log(rowKeys);
  }

  function reloadTable() {
    actionRef.value.reload();
  }

  function handleDelete(record: Recordable) {
    delWeblogTableList(record).then(() => {
      message.success('删除成功');
      setTimeout(reloadTable);
    });
  }

  function handleDetail(record: Recordable) {
    getWeblogDetailTableList({ id: record.id }).then((resp) => {
      detailName.value = record.name;
      detailContent.value = resp || '';
      showDetail.value = true;
    });
  }

  // 一键分析：复用统一入口的 weblog_id 通道
  function handleAnalyze(record: Recordable) {
    if (analyzing.value) return;
    analyzing.value = true;
    submitAnalyzeTask({ weblog_id: record.id, name: `日志-${record.name}` })
      .then(() => {
        message.success('已提交分析，跳转统一分析入口…');
        router.push('/analyze');
      })
      .catch(() => message.error('分析任务提交失败'))
      .finally(() => (analyzing.value = false));
  }

  const processFile = ({ file, data }: UploadCustomRequestOptions) => {
    const formData = new FormData();
    if (data) {
      Object.keys(data).forEach((key) => {
        formData.append(key, data[key as keyof UploadCustomRequestOptions['data']]);
      });
    }
    choseFile.value = file.file as File;
    formData.append('file', choseFile.value as File);
    uploadWeblogDataReq(formData).then(
      () => message.success('上传成功'),
      (e: any) => message.error(e?.message || '上传失败')
    );
    setTimeout(reloadTable);
  };

  const clearList = () => {
    fileRef.value.clear();
  };
</script>

<style lang="less" scoped></style>
