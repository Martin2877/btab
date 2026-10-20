<template>
  <div>
    <n-card :bordered="false" class="proCard">
      <n-space style="margin-bottom: 12px" align="center">
        <n-input v-model:value="query.search" placeholder="搜索名称/类别/正则" clearable style="width: 220px" @keyup.enter="reloadTable" />
        <n-select v-model:value="query.place" :options="placeOptions" placeholder="位置" clearable style="width: 130px" />
        <n-select v-model:value="query.level" :options="levelOptions" placeholder="级别" clearable style="width: 120px" />
        <n-select v-model:value="query.enabled" :options="enabledOptions" placeholder="状态" clearable style="width: 110px" />
        <n-button type="primary" @click="reloadTable">查询</n-button>
      </n-space>

      <BasicTable
        :columns="columns"
        :request="loadDataTable"
        :row-key="(row) => row.id"
        ref="actionRef"
        :actionColumn="actionColumn"
        :scroll-x="1200"
      >
        <template #toolbar>
          <n-space>
            <n-button type="primary" @click="openEdit(null)">新增规则</n-button>
            <n-upload :show-file-list="false" :custom-request="importYaml" accept=".yaml,.yml">
              <n-button>导入规则集</n-button>
            </n-upload>
            <n-button @click="showDebug = true">在线检测</n-button>
            <n-button @click="reloadTable">刷新</n-button>
          </n-space>
        </template>
      </BasicTable>
    </n-card>

    <!-- 编辑/新增 -->
    <n-modal v-model:show="showEdit" preset="card" :style="{ width: '720px' }" :title="editForm.id ? '编辑规则' : '新增规则'">
      <n-form label-placement="left" label-width="90">
        <n-form-item label="规则名"><n-input v-model:value="editForm.name" placeholder="展示名（默认同行为描述）" /></n-form-item>
        <n-form-item label="正则" required><n-input v-model:value="editForm.regex" type="textarea" :autosize="{ minRows: 2, maxRows: 5 }" placeholder="匹配表达式，作用于解码前后的原始值" /></n-form-item>
        <n-space>
          <n-form-item label="位置"><n-select v-model:value="editForm.place" :options="placeOptions" style="width: 160px" /></n-form-item>
          <n-form-item label="级别"><n-select v-model:value="editForm.level" :options="levelOptions" style="width: 140px" /></n-form-item>
          <n-form-item label="启用"><n-switch v-model:value="editForm.enabled" /></n-form-item>
        </n-space>
        <n-form-item label="攻击类别"><n-input v-model:value="editForm.type_name" placeholder="如 SQL注入攻击 / XSS跨站脚本攻击 / 扫描器" /></n-form-item>
        <n-form-item label="行为描述"><n-input v-model:value="editForm.action_desc" placeholder="如 正在进行联合查询注入" /></n-form-item>
      </n-form>
      <template #action>
        <n-space>
          <n-button @click="showEdit = false">取消</n-button>
          <n-button @click="validateEdit" :loading="validating">校验正则</n-button>
          <n-button type="primary" @click="saveEdit" :loading="saving">保存</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 在线检测 -->
    <n-modal v-model:show="showDebug" preset="card" :style="{ width: '820px' }" title="URL 在线检测">
      <n-space vertical>
        <n-space align="center">
          <n-select v-model:value="debugPlace" :options="placeOptions" style="width: 140px" />
          <n-input v-model:value="debugValue" placeholder="输入待检测的 URL / UA / Referer" style="width: 480px" />
          <n-button type="primary" :loading="debugging" @click="runDebug">检测</n-button>
        </n-space>
        <n-alert v-if="debugResult" :type="debugResult.hits?.length ? 'warning' : 'success'">
          {{ debugResult.hits?.length ? `命中 ${debugResult.hits.length} 条规则` : `未命中（启用规则 ${debugResult.rules} 条）` }}
        </n-alert>
        <n-table v-if="debugResult?.hits?.length" size="small" :bordered="false">
          <thead><tr><th>规则</th><th>类别</th><th>级别</th><th>命中</th></tr></thead>
          <tbody>
            <tr v-for="(h, i) in debugResult.hits" :key="i">
              <td>{{ h.name }}（{{ h.rule_id }}）</td>
              <td>{{ h.type_name }}</td>
              <td><n-tag size="small" :type="levelTag(h.level)">{{ h.level }}</n-tag></td>
              <td style="word-break: break-all">{{ h.matched }}</td>
            </tr>
          </tbody>
        </n-table>
      </n-space>
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
  import { h, reactive, ref } from 'vue';
  import { useMessage, NSwitch, NTag, UploadCustomRequestOptions } from 'naive-ui';
  import { BasicTable, TableAction } from '@/components/Table';
  import {
    getUrlRuleList, saveUrlRule, delUrlRule, enableUrlRule,
    validateUrlRule, uploadUrlRuleYaml, debugUrlRule,
  } from '@/api/engine/urlrule';

  const message = useMessage();
  const actionRef = ref();

  const placeOptions = [
    { label: 'url', value: 'url' },
    { label: 'useragent', value: 'useragent' },
    { label: 'referer', value: 'referer' },
  ];
  const levelOptions = ['info', 'low', 'medium', 'high', 'critical'].map((l) => ({ label: l, value: l }));
  const enabledOptions = [
    { label: '启用', value: '1' },
    { label: '停用', value: '0' },
  ];

  const query = reactive({ search: '', place: null, level: null, enabled: null });

  const levelTag = (lv: string) =>
    ({ critical: 'error', high: 'error', medium: 'warning', low: 'info', info: 'default' } as any)[lv] || 'default';

  const columns = [
    { title: 'id', key: 'id', width: 50 },
    { title: '规则标识', key: 'rule_id', width: 110 },
    { title: '名称', key: 'name', width: 200 },
    { title: '位置', key: 'place', width: 90 },
    {
      title: '级别', key: 'level', width: 90,
      render: (row) => h(NTag, { size: 'small', type: levelTag(row.level) }, { default: () => row.level }),
    },
    { title: '攻击类别', key: 'type_name', width: 150 },
    {
      title: '启用', key: 'enabled', width: 70,
      render: (row) =>
        h(NSwitch, {
          size: 'small', value: row.enabled,
          onUpdateValue: (v: boolean) => toggle(row, v),
        }),
    },
    {
      title: '来源', key: 'builtin', width: 80,
      render: (row) => (row.builtin ? '内置' : row.source || 'custom'),
    },
  ];

  const actionColumn = reactive({
    width: 160,
    title: '操作',
    key: 'action',
    fixed: 'right',
    render(record) {
      return h(TableAction as any, {
        style: 'button',
        actions: [
          { label: '编辑', onClick: () => openEdit(record), ifShow: () => true, auth: ['basic_list'] },
          { label: '删除', onClick: () => remove(record), ifShow: () => true, auth: ['basic_list'] },
        ],
        select: () => {},
      });
    },
  });

  const loadDataTable = async (res) => {
    return await getUrlRuleList({ ...query, ...res });
  };

  function reloadTable() {
    actionRef.value.reload();
  }

  function toggle(row, v: boolean) {
    enableUrlRule({ id: row.id, enable: v }).then(() => {
      row.enabled = v;
      message.success(v ? '已启用' : '已停用');
    });
  }

  function remove(row) {
    delUrlRule({ id: row.id }).then(() => {
      message.success('删除成功');
      setTimeout(reloadTable);
    });
  }

  // ===== 编辑 =====
  const showEdit = ref(false);
  const saving = ref(false);
  const validating = ref(false);
  const editForm = reactive<any>({ id: 0, name: '', regex: '', place: 'url', level: 'medium', type_name: '', action_desc: '', enabled: true });

  function openEdit(row: any) {
    if (row) {
      Object.assign(editForm, {
        id: row.id, name: row.name, regex: row.regex, place: row.place,
        level: row.level, type_name: row.type_name, action_desc: row.action_desc, enabled: row.enabled,
      });
    } else {
      Object.assign(editForm, { id: 0, name: '', regex: '', place: 'url', level: 'medium', type_name: '', action_desc: '', enabled: true });
    }
    showEdit.value = true;
  }

  function validateEdit() {
    validating.value = true;
    validateUrlRule({ regex: editForm.regex, place: editForm.place })
      .then((r: any) => {
        if (r?.ok) message.success('正则有效');
        else message.error(r?.error || '正则无效');
      })
      .finally(() => (validating.value = false));
  }

  function saveEdit() {
    if (!editForm.regex) {
      message.error('正则不能为空');
      return;
    }
    saving.value = true;
    saveUrlRule({ ...editForm })
      .then(() => {
        message.success('保存成功');
        showEdit.value = false;
        reloadTable();
      })
      .catch((e: any) => message.error(e?.message || '保存失败'))
      .finally(() => (saving.value = false));
  }

  // ===== 导入 =====
  const importYaml = ({ file }: UploadCustomRequestOptions) => {
    const fd = new FormData();
    fd.append('file', file.file as File);
    uploadUrlRuleYaml(fd).then((r: any) => {
      message.success(`导入 ${r?.imported || 0} 条，跳过 ${r?.skipped || 0}，无效 ${r?.invalid || 0}`);
      reloadTable();
    });
  };

  // ===== 在线检测 =====
  const showDebug = ref(false);
  const debugging = ref(false);
  const debugPlace = ref('url');
  const debugValue = ref('');
  const debugResult = ref<any>(null);

  function runDebug() {
    if (!debugValue.value) return;
    debugging.value = true;
    debugUrlRule({ value: debugValue.value, place: debugPlace.value })
      .then((r: any) => (debugResult.value = r))
      .finally(() => (debugging.value = false));
  }
</script>

<style lang="less" scoped></style>
