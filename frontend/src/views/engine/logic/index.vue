<template>
  <n-card :bordered="false" class="proCard">
    <n-tabs v-model:value="tab" type="line" animated>
      <n-tab-pane name="overview" tab="概览">
        <Overview :active="tab === 'overview'" @goto="onGoto" />
      </n-tab-pane>
      <n-tab-pane name="scripts" tab="检测脚本" display-directive="show:lazy">
        <Scripts ref="scriptRef" @debug="onDebug" @goto="onGoto" />
      </n-tab-pane>
      <n-tab-pane name="guide" tab="开发指南" display-directive="show:lazy">
        <Guide />
      </n-tab-pane>
      <n-tab-pane name="debug" tab="脚本调试" display-directive="show:lazy">
        <Debug :script-id="debugId" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>

<script lang="ts" setup>
  import { ref, nextTick, onMounted } from 'vue';
  import { useRoute } from 'vue-router';
  import Overview from './Overview.vue';
  import Scripts from './Scripts.vue';
  import Guide from './Guide.vue';
  import Debug from './Debug.vue';

  const route = useRoute();
  const tab = ref('overview');
  const scriptRef = ref();
  const debugId = ref('');

  function onGoto(target: string, filter?: Record<string, any>) {
    tab.value = target;
    if (target === 'scripts' && filter) {
      nextTick(() => scriptRef.value?.applyFilter(filter));
    }
  }

  function onDebug(id: string) {
    debugId.value = id;
    tab.value = 'debug';
  }

  // 支持外部跳转深链：/engine/logic?tab=scripts&search=<脚本id>
  onMounted(() => {
    const t = String(route.query.tab || '');
    if (['overview', 'scripts', 'guide', 'debug'].includes(t)) {
      tab.value = t;
    }
    const search = String(route.query.search || '');
    if (search) {
      nextTick(() => scriptRef.value?.applyFilter({ search }));
    }
  });
</script>
