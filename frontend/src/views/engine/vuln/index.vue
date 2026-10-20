<template>
  <n-card :bordered="false" class="proCard">
    <n-tabs v-model:value="tab" type="line" animated>
      <n-tab-pane name="overview" tab="概览">
        <Overview :active="tab === 'overview'" @goto="onGoto" />
      </n-tab-pane>
      <n-tab-pane name="templates" tab="规则模板" display-directive="show:lazy">
        <Templates ref="tplRef" @debug="onDebug" />
      </n-tab-pane>
      <n-tab-pane name="resources" tab="字典资源" display-directive="show:lazy">
        <Resources />
      </n-tab-pane>
      <n-tab-pane name="settings" tab="引擎配置" display-directive="show:lazy">
        <Settings />
      </n-tab-pane>
      <n-tab-pane name="debug" tab="规则调试" display-directive="show:lazy">
        <Debug :template-id="debugId" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>

<script lang="ts" setup>
import { ref, nextTick, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import Overview from './Overview.vue';
import Templates from './Templates.vue';
import Resources from './Resources.vue';
import Settings from './Settings.vue';
import Debug from './Debug.vue';

const route = useRoute();
const tab = ref('overview');
const tplRef = ref();
const debugId = ref(0);

function onGoto(target: string, filter?: Record<string, any>) {
  tab.value = target;
  if (target === 'templates' && filter) {
    nextTick(() => tplRef.value?.applyFilter(filter));
  }
}

function onDebug(id: number) {
  debugId.value = id;
  tab.value = 'debug';
}

// 支持外部跳转深链：/engine/vuln?tab=templates&search=<模板id/路径>
onMounted(() => {
  const t = String(route.query.tab || '');
  if (['overview', 'templates', 'resources', 'settings', 'debug'].includes(t)) {
    tab.value = t;
  }
  const search = String(route.query.search || '');
  if (tab.value === 'templates' && search) {
    nextTick(() => tplRef.value?.applyFilter({ search }));
  }
});
</script>
