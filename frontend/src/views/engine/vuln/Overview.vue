<template>
  <div>
    <n-alert type="info" :show-icon="false" style="margin-bottom: 14px">
      漏洞检测引擎集成 nuclei 规则：被动匹配流量包 / HTTP 请求响应 / 攻击载荷中的漏洞特征。
      此处管理规则模板、字典资源与引擎配置，各检测功能自动使用已启用的规则。
    </n-alert>
    <n-alert v-if="data.loading" type="warning" :show-icon="false" style="margin-bottom: 14px">
      引擎模板编译中，统计稍后自动刷新…
    </n-alert>
    <n-grid :cols="5" :x-gap="12" :y-gap="12">
      <n-gi v-for="c in cards" :key="c.label">
        <n-card size="small" hoverable :bordered="true" @click="c.go && emit('goto', 'templates', c.go)">
          <n-statistic :label="c.label" :value="c.value" />
        </n-card>
      </n-gi>
    </n-grid>

    <n-grid :cols="3" :x-gap="12" style="margin-top: 14px">
      <n-gi>
        <n-card size="small" title="严重级别分布">
          <div v-for="s in sevList" :key="s.name" class="bar-row" @click="emit('goto', 'templates', { severity: s.name })">
            <n-tag :type="sevType(s.name)" size="small" :bordered="false" style="width: 70px">{{ s.name }}</n-tag>
            <div class="bar"><div class="bar-in" :style="{ width: pct(s.count, total) }"></div></div>
            <span class="bar-n">{{ s.count }}</span>
          </div>
          <n-empty v-if="!sevList.length" description="暂无模板" />
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" title="协议分布">
          <div v-for="s in protoList" :key="s.name" class="bar-row" @click="emit('goto', 'templates', { protocol: s.name })">
            <n-tag size="small" :bordered="false" style="width: 90px">{{ s.name }}</n-tag>
            <div class="bar"><div class="bar-in" :style="{ width: pct(s.count, total) }"></div></div>
            <span class="bar-n">{{ s.count }}</span>
          </div>
          <div class="hint" v-if="protoList.length">仅 http 协议的模板可用于被动检测，其余协议模板需要主动扫描能力。</div>
          <n-empty v-else description="暂无模板" />
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" title="热门标签（Top 20）">
          <n-space size="small">
            <n-tag
              v-for="t in data.stats?.top_tags || []"
              :key="t.name"
              size="small"
              :bordered="false"
              style="cursor: pointer"
              @click="emit('goto', 'templates', { tag: t.name })"
            >{{ t.name }} · {{ t.count }}</n-tag>
          </n-space>
          <n-empty v-if="!(data.stats?.top_tags || []).length" description="暂无标签" />
        </n-card>
      </n-gi>
    </n-grid>
  </div>
</template>

<script lang="ts" setup>
import { computed, reactive, watch, onUnmounted } from 'vue';
import { getVulnOverview } from '@/api/engine/vuln';
import { sevType } from './yaml';

const props = defineProps<{ active: boolean }>();
const emit = defineEmits<{ (e: 'goto', target: string, filter?: Record<string, any>): void }>();
const data = reactive<any>({});

// 引擎未编译完成时后端返回 loading，间隔轮询直到就绪
let retryTimer: ReturnType<typeof setTimeout> | null = null;
function load() {
  getVulnOverview().then((r) => {
    Object.assign(data, r);
    data.loading = r?.loading === true;
    if (data.loading) {
      retryTimer = setTimeout(load, 1500);
    }
  });
}
watch(() => props.active, (v) => v && load(), { immediate: true });
onUnmounted(() => retryTimer && clearTimeout(retryTimer));

const total = computed(() => data.stats?.total || 0);
const cards = computed(() => {
  const s = data.stats || {};
  return [
    { label: '模板总数', value: s.total || 0, go: {} },
    { label: '已启用', value: s.enabled || 0, go: { enabled: 'true' } },
    { label: '被动可用', value: s.passive || 0, go: { status: 'passive' } },
    { label: '解析失败', value: s.errors || 0, go: { status: 'error' } },
    { label: '字典资源', value: data.resources || 0, go: null },
  ];
});
const toList = (m: Record<string, number> = {}) =>
  Object.entries(m).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
const order = ['critical', 'high', 'medium', 'low', 'info'];
const sevList = computed(() =>
  toList(data.stats?.severity).sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name))
);
const protoList = computed(() => toList(data.stats?.protocols));
const pct = (n: number, t: number) => (t ? Math.max(2, Math.round((n / t) * 100)) + '%' : '0');
</script>

<style lang="less" scoped>
.bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
  cursor: pointer;
}
.bar {
  flex: 1;
  height: 8px;
  background: #f0f0f0;
  border-radius: 4px;
  overflow: hidden;
}
.bar-in {
  height: 100%;
  background: #2d8cf0;
}
.bar-n {
  width: 44px;
  text-align: right;
  font-size: 12px;
  color: #666;
}
.hint {
  margin-top: 8px;
  font-size: 12px;
  color: #999;
}
</style>
