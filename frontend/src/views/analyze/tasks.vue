<template>
  <n-card :bordered="false" class="proCard">
    <n-space style="margin-bottom: 12px" align="center">
      <n-input
        v-model:value="search"
        placeholder="搜索任务名称/内容"
        clearable
        style="width: 260px"
        @keyup.enter="reload()"
      />
      <n-button type="primary" @click="reload()">查询</n-button>
      <n-button @click="goHome">新建分析</n-button>
    </n-space>
    <n-data-table
      remote
      :loading="loading"
      :columns="columns"
      :data="rows"
      :row-key="(r) => r.id"
      :pagination="pagination"
      :scroll-x="1000"
      size="small"
    />
  </n-card>
</template>

<script lang="ts" setup>
  import { h, ref, reactive, computed, onMounted, onUnmounted } from 'vue';
  import { NTag, NButton, NSpace, NProgress, useMessage, useDialog } from 'naive-ui';
  import { useRouter } from 'vue-router';
  import { getAnalyzeTasks, delAnalyzeTask } from '@/api/analyze';

  const message = useMessage();
  const dialog = useDialog();
  const router = useRouter();

  const search = ref('');
  const rows = ref<any[]>([]);
  const loading = ref(false);
  const pagination = reactive({
    page: 1,
    pageSize: 20,
    itemCount: 0,
    showSizePicker: true,
    pageSizes: [10, 20, 50],
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

  const stateTag = (s: number) =>
    s === 1
      ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => '分析中')
      : s === 4
      ? h(NTag, { type: 'success', size: 'small', bordered: false }, () => '已完成')
      : h(NTag, { type: 'error', size: 'small', bordered: false }, () => '失败');

  const inputTag = (t: string) =>
    t === 'pcap'
      ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => '流量包')
      : t === 'log'
      ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => 'web日志')
      : h(NTag, { size: 'small', bordered: false }, () => '文本');

  const columns = computed<any[]>(() => [
    { title: 'ID', key: 'id', width: 60 },
    { title: '任务', key: 'name', width: 220, ellipsis: { tooltip: true } },
    {
      title: '输入',
      key: 'input',
      width: 160,
      render: (r) =>
        h('div', [
          inputTag(r.input_type),
          h('div', { style: 'font-size:12px;color:#999;margin-top:2px' }, r.input_name),
        ]),
    },
    {
      title: '状态',
      key: 'state',
      width: 110,
      render: (r) => {
        const tag = stateTag(r.state);
        const p = r.progress;
        if (r.state === 1 && p) {
          const pct = p.total ? Math.round(((p.done || 0) / p.total) * 100) : 0;
          return h('div', [
            tag,
            h(NProgress, {
              type: 'line',
              percentage: pct,
              height: 4,
              processing: true,
              showIndicator: false,
              style: 'margin-top:5px;width:86px',
            }),
            h(
              'div',
              { style: 'font-size:11px;color:#999;margin-top:2px' },
              `${p.current || '分析中'} ${p.done}/${p.total}`
            ),
          ]);
        }
        return tag;
      },
    },
    {
      title: '结论',
      key: 'verdict',
      ellipsis: { tooltip: true },
      render: (r) =>
        r.risk
          ? h(
              NTag,
              { type: 'error', size: 'small', bordered: false },
              () => r.verdict || '检出风险'
            )
          : h('span', { style: 'color:#666;font-size:12px' }, r.verdict || '-'),
    },
    { title: '时间', key: 'CreatedAt', width: 170, render: (r) => fmtTime(r.CreatedAt) },
    {
      title: '操作',
      key: 'action',
      width: 150,
      fixed: 'right',
      render: (r) =>
        h(NSpace, { size: 8, align: 'center' }, () => [
          h(
            NButton,
            {
              size: 'small',
              type: 'primary',
              secondary: true,
              onClick: () => openReport(r),
            },
            () => '报告'
          ),
          h(
            NButton,
            { size: 'tiny', text: true, type: 'error', onClick: () => del(r) },
            () => '删除'
          ),
        ]),
    },
  ]);

  function fmtTime(t: string) {
    if (!t) return '-';
    return t
      .replace('T', ' ')
      .replace(/\.\d+.*$/, '')
      .replace(/\+\d+:\d+$/, '');
  }

  function load() {
    loading.value = true;
    getAnalyzeTasks({ search: search.value, page: pagination.page, pageSize: pagination.pageSize })
      .then((r) => {
        rows.value = r.list || [];
        pagination.itemCount = r.total || 0;
        hasRunning = (r.list || []).some((x: any) => x.state === 1);
      })
      .finally(() => (loading.value = false));
  }
  function reload() {
    pagination.page = 1;
    load();
  }
  function goHome() {
    router.push({ name: 'analyze-home' });
  }
  function openReport(r: any) {
    router.push({ name: 'analyze-report', query: { id: r.id } });
  }
  function del(r: any) {
    dialog.warning({
      title: '删除任务',
      content: `确认删除任务「${r.name}」及其报告？`,
      positiveText: '删除',
      negativeText: '取消',
      onPositiveClick: () =>
        delAnalyzeTask({ id: r.id }).then(() => {
          message.success('已删除');
          load();
        }),
    });
  }

  let hasRunning = false;
  let timer: any = null;
  onMounted(() => {
    load();
    timer = setInterval(() => {
      if (hasRunning) load();
    }, 2500);
  });
  onUnmounted(() => timer && clearInterval(timer));
</script>
