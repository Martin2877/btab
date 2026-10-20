<template>
  <div>
    <n-alert type="info" :show-icon="false" style="margin-bottom: 14px">
      行为检测引擎基于 goja 运行 JavaScript 检测脚本（无需 python / suricata），报文提取依托
      tshark。 此处管理检测脚本：内置脚本随程序发布，自定义脚本保存在
      {{ data.user_dir || 'stores/strategy' }}/ 目录，同名 ID 覆盖内置版本。
    </n-alert>
    <n-grid :cols="5" :x-gap="12" :y-gap="12">
      <n-gi v-for="c in cards" :key="c.label">
        <n-card
          size="small"
          hoverable
          :bordered="true"
          @click="c.go && emit('goto', 'scripts', c.go)"
        >
          <n-statistic :label="c.label" :value="c.value" />
        </n-card>
      </n-gi>
    </n-grid>

    <n-grid :cols="2" :x-gap="12" style="margin-top: 14px">
      <n-gi>
        <n-card size="small" title="类型分布">
          <div
            v-for="s in typeList"
            :key="s.name"
            class="bar-row"
            @click="emit('goto', 'scripts', { type: s.name })"
          >
            <n-tag size="small" :bordered="false" style="width: 90px">{{ s.name }}</n-tag>
            <div class="bar"
              ><div class="bar-in" :style="{ width: pct(s.count, total) }"></div
            ></div>
            <span class="bar-n">{{ s.count }}</span>
          </div>
          <n-empty v-if="!typeList.length" description="暂无脚本" />
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" title="攻击阶段分布">
          <div v-for="s in phaseList" :key="s.name" class="bar-row">
            <n-tag size="small" type="info" :bordered="false" style="width: 110px">{{
              s.name
            }}</n-tag>
            <div class="bar"
              ><div class="bar-in" :style="{ width: pct(s.count, total) }"></div
            ></div>
            <span class="bar-n">{{ s.count }}</span>
          </div>
          <n-empty v-if="!phaseList.length" description="暂无脚本" />
        </n-card>
      </n-gi>
    </n-grid>

    <n-card size="small" style="margin-top: 14px">
      <div class="doc doc-link">
        编写自定义检测脚本需要遵循引擎接口约定（INFO 元信息 + process(pcap, util) 入口）， 详见
        <a @click="emit('goto', 'guide')">「开发指南」</a>。
      </div>
    </n-card>
  </div>
</template>

<script lang="ts" setup>
  import { computed, reactive, watch } from 'vue';
  import { getLogicOverview } from '@/api/engine/logic';

  const props = defineProps<{ active: boolean }>();
  const emit = defineEmits<{ (e: 'goto', target: string, filter?: Record<string, any>): void }>();
  const data = reactive<any>({});

  function load() {
    getLogicOverview().then((r) => Object.assign(data, r));
  }
  watch(
    () => props.active,
    (v) => v && load(),
    { immediate: true }
  );

  const total = computed(() => data.total || 0);
  const cards = computed(() => [
    { label: '脚本总数', value: data.total || 0, go: {} },
    { label: '已启用', value: (data.total || 0) - (data.disabled || 0), go: { disabled: '0' } },
    { label: '内置脚本', value: data.builtin || 0, go: { origin: 'builtin' } },
    { label: '自定义脚本', value: data.custom || 0, go: { origin: 'custom' } },
    { label: '编译失败', value: data.errors || 0, go: null },
  ]);
  const toList = (m: Record<string, number> = {}) =>
    Object.entries(m)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  const typeList = computed(() => toList(data.types));
  const phaseList = computed(() => toList(data.phases));
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
  .doc {
    font-size: 13px;
    line-height: 2;
    p {
      margin: 4px 0;
    }
    code {
      background: rgba(128, 128, 128, 0.12);
      border-radius: 4px;
      padding: 1px 6px;
      font-family: Consolas, 'Courier New', monospace;
      font-size: 12px;
    }
  }
  .doc-link a {
    color: #2d8cf0;
    cursor: pointer;
    &:hover {
      text-decoration: underline;
    }
  }
</style>
