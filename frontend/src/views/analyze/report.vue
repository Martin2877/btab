<template>
  <n-card :bordered="false" class="proCard">
    <n-space align="center" style="margin-bottom: 14px">
      <n-button size="small" @click="goBack">{{ $t('report.back') }}</n-button>
      <n-h4 style="margin: 0">{{ task.name || $t('report.title') }}</n-h4>
      <n-tag v-if="task.state === 1" type="info" :bordered="false">{{ $t('report.running') }}</n-tag>
      <n-tag v-else-if="task.state === 4 && task.risk" type="error" :bordered="false">{{
        $t('report.riskFound')
      }}</n-tag>
      <n-tag v-else-if="task.state === 4" type="success" :bordered="false">{{
        $t('report.noRisk')
      }}</n-tag>
      <n-tag v-else type="error" :bordered="false">{{ $t('report.failed') }}</n-tag>
      <span class="muted">{{ fmtTime(task.CreatedAt) }}</span>
    </n-space>

    <n-card v-if="progress?.running" size="small" style="margin-bottom: 14px">
      <n-space align="center" :wrap-item="false" style="width: 100%">
        <n-spin size="small" />
        <div style="flex: 1">
          <n-progress
            type="line"
            :percentage="progressPct"
            :height="5"
            :border-radius="2"
            processing
            :show-indicator="false"
          />
        </div>
        <span class="muted" style="flex: none"
          >{{ progress.current || '进行中' }}（{{ progress.done }}/{{ progress.total }}）</span
        >
      </n-space>
    </n-card>

    <n-card size="small" :title="$t('report.inputInfo')" style="margin-bottom: 14px">
      <n-descriptions :column="3" label-placement="left" size="small" bordered>
        <n-descriptions-item :label="$t('report.inputType')">{{
          task.input_type === 'pcap'
            ? $t('report.inputPcap')
            : task.input_type === 'log'
            ? $t('report.inputLog')
            : $t('report.inputText')
        }}</n-descriptions-item>
        <n-descriptions-item :label="$t('report.inputSource')">{{ task.input_name }}</n-descriptions-item>
        <n-descriptions-item :label="$t('report.size')">{{ fmtSize(task.input_size) }}</n-descriptions-item>
        <n-descriptions-item :label="$t('report.methods')">{{ methodText }}</n-descriptions-item>
        <n-descriptions-item :label="$t('report.taskId')">{{ task.id }}</n-descriptions-item>
        <n-descriptions-item label="UUID">{{ task.uuid }}</n-descriptions-item>
      </n-descriptions>
      <pre v-if="task.preview" class="preview">{{ task.preview }}</pre>
    </n-card>

    <n-card size="small" :title="$t('report.process')" style="margin-bottom: 14px">
      <n-timeline v-if="steps.length">
        <n-timeline-item
          v-for="(s, i) in steps"
          :key="i"
          :type="
            s.status === 'hit'
              ? 'error'
              : s.status === 'error'
              ? 'warning'
              : s.status === 'running'
              ? 'info'
              : s.status === 'skip'
              ? 'default'
              : 'success'
          "
          :title="s.name"
        >
          <div class="step-line">
            <n-tag size="tiny" :bordered="false" :type="stepTagType(s.status)">{{
              stepText(s.status)
            }}</n-tag>
            <span class="step-detail">{{ s.detail }}</span>
            <span class="muted" v-if="s.status !== 'running'">{{ s.ms }}ms</span>
            <n-spin v-else size="tiny" />
          </div>
        </n-timeline-item>
      </n-timeline>
      <n-empty v-else :description="$t('report.noProcess')" />
    </n-card>

    <n-card v-if="sankey.nodes.length" size="small" style="margin-bottom: 14px">
      <template #header>
        <n-space align="center" :size="8">
          <span>{{ $t('report.link') }}</span>
          <span class="muted">Src IP → Dst IP</span>
        </n-space>
      </template>
      <div ref="sankeyRef" class="sankey" :style="{ height: sankeyHeight + 'px' }" />
    </n-card>

    <n-card size="small" :title="$t('report.result')">
      <n-alert
        :type="report.risk ? 'error' : 'success'"
        :show-icon="false"
        style="margin-bottom: 12px"
      >
        {{ report.verdict || task.verdict || $t('report.noVerdict') }}
      </n-alert>
      <n-space v-if="(report.types || []).length" size="small" style="margin-bottom: 12px">
        <n-tag v-for="t in report.types" :key="t" size="small" type="warning" :bordered="false">{{
          t
        }}</n-tag>
      </n-space>
      <n-alert
        v-for="(e, i) in report.errors || []"
        :key="'err' + i"
        type="warning"
        :show-icon="false"
        style="margin-bottom: 6px"
      >
        {{ e }}
      </n-alert>

      <n-collapse v-model:expanded-names="expPanels" class="result-collapse">
        <n-collapse-item v-if="(report.items || []).length" name="items">
          <template #header>
            <span class="sec-title"
              >{{ $t('report.items') }}
              <n-tag size="tiny" :bordered="false">{{ report.items.length }}</n-tag></span
            >
          </template>
          <n-data-table size="small" :columns="itemCols" :data="report.items" :pagination="false" />
        </n-collapse-item>

        <n-collapse-item v-if="httpSummary.length" name="http" :title="$t('report.http')">
          <n-descriptions :column="2" label-placement="left" size="small" bordered>
            <n-descriptions-item v-for="it in httpSummary" :key="it.k" :label="it.k">{{
              it.v
            }}</n-descriptions-item>
          </n-descriptions>
          <template v-if="httpArgs.length">
            <n-divider dashed style="margin: 10px 0">可疑参数</n-divider>
            <n-descriptions :column="2" label-placement="left" size="small" bordered>
              <n-descriptions-item v-for="it in httpArgs" :key="it.k" :label="it.k">
                {{ it.type }}：{{ it.value }}
              </n-descriptions-item>
            </n-descriptions>
          </template>
        </n-collapse-item>

        <n-collapse-item v-if="report.log" name="log" :title="$t('report.logOverview')">
          <n-descriptions :column="3" label-placement="left" size="small" bordered>
            <n-descriptions-item :label="$t('report.logLines')">{{ report.log.lines }}</n-descriptions-item>
            <n-descriptions-item :label="$t('report.startTime')">{{ report.log.start_time || '-' }}</n-descriptions-item>
            <n-descriptions-item :label="$t('report.endTime')">{{ report.log.end_time || '-' }}</n-descriptions-item>
          </n-descriptions>
          <template v-if="(report.log.top_ip || []).length">
            <n-divider dashed style="margin: 10px 0">{{ $t('report.topIp') }}</n-divider>
            <n-descriptions :column="2" label-placement="left" size="small" bordered>
              <n-descriptions-item v-for="it in report.log.top_ip" :key="it[0]" :label="it[0]">
                {{ it[1] }} 次
              </n-descriptions-item>
            </n-descriptions>
          </template>
          <template v-if="(report.log.top_path || []).length">
            <n-divider dashed style="margin: 10px 0">{{ $t('report.topPath') }}</n-divider>
            <n-descriptions :column="1" label-placement="left" size="small" bordered>
              <n-descriptions-item v-for="it in report.log.top_path" :key="it[0]" :label="it[0]">
                {{ it[1] }} 次
              </n-descriptions-item>
            </n-descriptions>
          </template>
          <template v-if="report.log.status && Object.keys(report.log.status).length">
            <n-divider dashed style="margin: 10px 0">{{ $t('report.statusDist') }}</n-divider>
            <n-space size="small">
              <n-tag v-for="(cnt, code) in report.log.status" :key="code" size="small"
                     :type="+code >= 500 ? 'error' : +code >= 400 ? 'warning' : 'success'" :bordered="false">
                {{ code }} × {{ cnt }}
              </n-tag>
            </n-space>
          </template>
        </n-collapse-item>

        <n-collapse-item v-if="(report.events || []).length" name="events">
          <template #header>
            <span class="sec-title"
              >{{ $t('report.events') }}
              <n-tag size="tiny" :bordered="false">{{ report.events.length }}</n-tag>
              <span v-if="report.flows != null" class="muted"
                >，HTTP 会话 {{ report.flows }} 条</span
              ></span
            >
          </template>
          <div class="ev-toolbar">
            <a @click="expandAllEvents">{{ $t('report.expandAll') }}</a>
            <n-divider vertical />
            <a @click="expEvents = []">{{ $t('report.collapseAll') }}</a>
          </div>
          <n-collapse v-model:expanded-names="expEvents" class="ev-collapse">
            <n-collapse-item v-for="(ev, i) in report.events" :key="i" :name="i">
              <template #header>
                <n-space align="center" :size="8" :wrap-item="false">
                  <span class="ev-dot" :class="{ attack: ev.type === 'attack' }"></span>
                  <n-tag
                    v-if="ev.severity"
                    size="tiny"
                    :bordered="false"
                    :color="{ color: sevColor(ev.severity), textColor: '#fff' }"
                    class="sev-tag"
                    >{{ ev.severity }}</n-tag
                  >
                  <span class="event-name">{{ ev.name || '未命名事件' }}</span>
                  <n-tag
                    v-if="ev.type"
                    size="tiny"
                    :bordered="false"
                    :type="ev.type === 'attack' ? 'error' : 'default'"
                    >{{ ev.type }}</n-tag
                  >
                  <n-tag v-if="ev.engine" size="tiny" type="primary" :bordered="false">{{
                    ev.engine
                  }}</n-tag>
                  <n-tag v-if="ev.rule" size="tiny" :bordered="false" class="rule-tag">{{
                    ev.rule
                  }}</n-tag>
                  <n-tag v-if="ev.phase" size="tiny" type="info" :bordered="false">{{
                    ev.phase
                  }}</n-tag>
                  <n-tag v-if="ev.strategy" size="tiny" type="warning" :bordered="false">{{
                    ev.strategy
                  }}</n-tag>
                </n-space>
              </template>
              <div class="event-meta" v-if="(ev.src || []).length || (ev.dst || []).length">
                <span class="meta-label">源/目的</span>
                <span class="meta-val"
                  >{{ (ev.src || []).join(', ') || '?' }} →
                  {{ (ev.dst || []).join(', ') || '?' }}</span
                >
              </div>
              <pre v-if="ev.desc" class="event-desc">{{ ev.desc }}</pre>
            </n-collapse-item>
          </n-collapse>
        </n-collapse-item>
      </n-collapse>
      <n-empty v-if="emptyResult" :description="$t('report.emptyResult')" style="padding: 20px 0" />
    </n-card>
  </n-card>
</template>

<script lang="ts" setup>
  import { h, ref, reactive, computed, watch, nextTick, onMounted, onUnmounted } from 'vue';
  import type { Ref } from 'vue';
  import { NTag, useMessage } from 'naive-ui';
  import { useRoute, useRouter } from 'vue-router';
  import { SankeyChart } from 'echarts/charts';
  import { getAnalyzeTask, getAnalyzeMethods } from '@/api/analyze';
  import { useECharts } from '@/hooks/web/useECharts';

  const route = useRoute();
  const router = useRouter();
  const message = useMessage();

  const task = reactive<any>({});
  const report = reactive<any>({});
  const progress = ref<any>(null);
  const methodNames = ref<Record<string, string>>({});

  // ===== 攻击链路桑基图：源 IP → 目的 IP =====
  // 节点 key 带层级前缀（s:/d:），避免同一 IP 既为源又为目的时成环
  const sankeyRef = ref<HTMLDivElement | null>(null);
  const { setOptions: setSankeyOptions, echarts } = useECharts(
    sankeyRef as Ref<HTMLDivElement>
  );
  echarts.use([SankeyChart]);

  const stripKey = (n: string) => String(n).replace(/^[spd]:/, '');
  // 单列节点数过多时按热度收敛，避免图形不可读
  function topKeys(m: Map<string, number>, limit: number, otherKey: string) {
    if (m.size <= limit) return (k: string) => k;
    const keep = new Set(
      [...m.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit)
        .map(([k]) => k)
    );
    return (k: string) => (keep.has(k) ? k : otherKey);
  }
  const sankey = computed(() => {
    const srcN = new Map<string, number>();
    const dstN = new Map<string, number>();
    const evs = (report.events || []).filter(
      (e: any) => (e.src || []).length || (e.dst || []).length
    );
    for (const e of evs) {
      (e.src || []).forEach((s: string) => srcN.set(s, (srcN.get(s) || 0) + 1));
      (e.dst || []).forEach((d: string) => dstN.set(d, (dstN.get(d) || 0) + 1));
    }
    const mapSrc = topKeys(srcN, 15, '其他来源');
    const mapDst = topKeys(dstN, 15, '其他目标');
    const nodes = new Map<string, any>();
    const linkN = new Map<string, { value: number; phases: Set<string> }>();
    const node = (key: string, color: string) => {
      if (!nodes.has(key)) nodes.set(key, { name: key, itemStyle: { color } });
    };
    for (const e of evs) {
      // 源/目的缺省时挂到占位节点，保证事件数与列表一致
      const srcs = (e.src || []).length ? (e.src || []).map(mapSrc) : ['(未知源)'];
      const dsts = (e.dst || []).length ? (e.dst || []).map(mapDst) : ['(未知目的)'];
      for (const s of srcs) {
        node('s:' + s, '#2d8cf0');
        for (const d of dsts) {
          node('d:' + d, '#d03050');
          const k = 's:' + s + '→d:' + d;
          let l = linkN.get(k);
          if (!l) linkN.set(k, (l = { value: 0, phases: new Set<string>() }));
          l.value++;
          if (e.phase) l.phases.add(e.phase);
        }
      }
    }
    return {
      nodes: [...nodes.values()],
      links: [...linkN.entries()].map(([k, v]) => {
        const [source, target] = k.split('→');
        return { source, target, value: v.value, phases: [...v.phases] };
      }),
    };
  });
  // 高度按最多的单列节点数伸缩
  const sankeyHeight = computed(() => {
    const s = sankey.value.nodes.filter((n) => n.name.startsWith('s:')).length;
    const d = sankey.value.nodes.filter((n) => n.name.startsWith('d:')).length;
    return Math.min(Math.max(s, d, 3) * 34 + 40, 520);
  });
  watch(
    () => sankey.value,
    (d) => {
      if (!d.nodes.length) return;
      nextTick(() =>
        setSankeyOptions({
          tooltip: {
            trigger: 'item',
            formatter: (p: any) =>
              p.dataType === 'edge'
                ? `${stripKey(p.data.source)} → ${stripKey(p.data.target)}：${p.data.value} 条事件` +
                  (p.data.phases?.length ? `<br/>阶段：${p.data.phases.join('、')}` : '')
                : `${stripKey(p.name)}：${p.value} 条事件`,
          },
          series: [
            {
              type: 'sankey',
              left: 16,
              // 最右列节点标签向右绘制，留出足够边距避免被裁剪
              right: 110,
              top: 10,
              bottom: 10,
              nodeWidth: 12,
              nodeGap: 10,
              emphasis: { focus: 'adjacency' },
              label: { fontSize: 11, formatter: (p: any) => stripKey(p.name) },
              lineStyle: { color: 'gradient', curveness: 0.5, opacity: 0.35 },
              data: d.nodes,
              links: d.links,
            },
          ],
        })
      );
    },
    { deep: true }
  );

  // 运行中优先展示后端实时回传的步骤快照，末尾追加"进行中"的当前步骤
  const steps = computed(() => {
    const live = progress.value?.steps || [];
    const base = live.length > (report.steps || []).length ? live : report.steps || [];
    const arr = [...base];
    if (progress.value?.running && progress.value.current) {
      arr.push({ name: progress.value.current, status: 'running', detail: '', ms: 0 });
    }
    return arr;
  });
  const progressPct = computed(() => {
    const p = progress.value;
    return p?.total ? Math.round(((p.done || 0) / p.total) * 100) : 0;
  });
  // 检出等级配色：critical 红 / high 橙 / medium 金 / low 绿 / info 灰
  const sevColor = (s?: string) => {
    switch (String(s || '').toLowerCase()) {
      case 'critical':
        return '#d03050';
      case 'high':
        return '#e8801a';
      case 'medium':
        return '#d9a021';
      case 'low':
        return '#18a058';
      default:
        return '#909399';
    }
  };
  // 结果区块折叠状态；事件逐个可折叠，事件少时默认展开
  const expPanels = ref<string[]>(['items', 'http', 'log', 'events']);
  const expEvents = ref<number[]>([]);
  let evInit = false;
  const allEventNames = () => (report.events || []).map((_: any, i: number) => i);
  function expandAllEvents() {
    expEvents.value = allEventNames();
  }

  const itemCols = [
    {
      type: 'expand',
      width: 36,
      renderExpand: (r: any) =>
        h('pre', { class: 'item-expand' }, String(r.result ?? '') || '无详情'),
    },
    { title: '引擎', key: 'title', width: 120 },
    {
      title: '判定',
      key: 'found',
      width: 80,
      render: (r: any) =>
        h(NTag, { size: 'small', bordered: false, type: r.found ? 'error' : 'default' }, () =>
          r.found ? '命中' : '未命中'
        ),
    },
    { title: '分值', key: 'score', width: 60 },
    {
      title: '结果',
      key: 'result',
      ellipsis: { tooltip: true },
      render: (r: any) => String(r.result ?? ''),
    },
  ];

  const httpSummary = computed(() => {
    const s = report.http?.summary || {};
    return Object.entries(s)
      .filter(([, v]) => v !== '' && v != null)
      .map(([k, v]) => ({ k, v: String(v) }));
  });
  const httpArgs = computed(() => {
    const a = report.http?.url_args || {};
    return Object.entries(a)
      .filter(([, v]: any) => v?.type === '可疑')
      .map(([k, v]: any) => ({ k, type: v.type, value: String(v.value ?? '') }));
  });
  const emptyResult = computed(
    () =>
      !report.risk &&
      !(report.items || []).length &&
      !httpSummary.value.length &&
      !(report.events || []).length &&
      !report.log
  );

  const methodText = computed(() => {
    if (!task.methods) return '自动（全部适用）';
    return task.methods
      .split(',')
      .map((m: string) => methodNames.value[m] || m)
      .join('、');
  });

  function fmtSize(n: number) {
    if (!n) return '0 B';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }
  function fmtTime(t: string) {
    if (!t) return '';
    return t
      .replace('T', ' ')
      .replace(/\.\d+.*$/, '')
      .replace(/\+\d+:\d+$/, '');
  }
  const stepText = (s: string) =>
    (({ hit: '检出', error: '异常', skip: '跳过', ok: '完成', running: '进行中' } as any)[s] || s);
  const stepTagType = (s: string) =>
    (({ hit: 'error', error: 'warning', skip: 'default', ok: 'success', running: 'info' } as any)[
      s
    ] || 'default');

  let timer: any = null;
  let errs = 0;
  function load() {
    const id = Number(route.query.id);
    if (!id) {
      message.warning('缺少任务 id');
      return;
    }
    getAnalyzeTask({ id })
      .then((r: any) => {
        errs = 0;
        Object.assign(task, r.task || {});
        if (r.report) Object.assign(report, r.report);
        const evN = (r.report?.events || []).length;
        if (!evInit && evN > 0) {
          evInit = true;
          expEvents.value = evN <= 5 ? allEventNames() : [];
        }
        progress.value = r.progress || null;
        if (task.state === 1 && !timer) {
          timer = setInterval(load, 1500);
        }
        if (task.state !== 1 && timer) {
          clearInterval(timer);
          timer = null;
        }
      })
      .catch(() => {
        // 连续失败（如任务被删）时停止轮询
        if (++errs >= 5 && timer) {
          clearInterval(timer);
          timer = null;
        }
      });
  }
  function goBack() {
    router.push({ name: 'analyze-tasks' });
  }

  onMounted(() => {
    load();
    getAnalyzeMethods()
      .then((r: any[]) => {
        (r || []).forEach((m) => (methodNames.value[m.key] = m.label));
      })
      .catch(() => {});
  });
  onUnmounted(() => timer && clearInterval(timer));
</script>

<style lang="less" scoped>
  .muted {
    font-size: 12px;
    color: #999;
  }
  .sankey {
    width: 100%;
  }
  .preview {
    margin: 10px 0 0;
    padding: 10px 12px;
    background: #0d1117;
    color: #c9d1d9;
    border-radius: 6px;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
  }
  .step-line {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 13px;
  }
  .step-detail {
    flex: 1;
    word-break: break-all;
  }
  .sec-title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
  }
  .result-collapse {
    :deep(.n-collapse-item__header) {
      padding: 10px 0;
    }
  }
  .ev-toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    margin-bottom: 6px;
    a {
      color: #2d8cf0;
      cursor: pointer;
      &:hover {
        text-decoration: underline;
      }
    }
  }
  .ev-collapse {
    :deep(.n-collapse-item) {
      border-bottom: 1px solid rgba(16, 24, 40, 0.06);
    }
    :deep(.n-collapse-item__header) {
      padding: 8px 0;
    }
  }
  .item-expand {
    margin: 0;
    padding: 10px 12px;
    background: #0d1117;
    color: #c9d1d9;
    border-radius: 6px;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 320px;
    overflow-y: auto;
  }
  .ev-dot {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #c2c8d0;
    &.attack {
      background: #d03050;
      box-shadow: 0 0 0 3px rgba(208, 48, 80, 0.15);
    }
  }
  .event-name {
    font-weight: 600;
  }
  .rule-tag {
    font-family: Consolas, 'Courier New', monospace;
  }
  .event-meta {
    display: flex;
    align-items: baseline;
    font-size: 12px;
    margin-bottom: 6px;
  }
  .meta-label {
    flex: none;
    width: 52px;
    opacity: 0.55;
  }
  .meta-val {
    font-family: monospace;
    word-break: break-all;
  }
  .event-desc {
    margin: 0;
    padding: 10px 12px;
    background: #0d1117;
    color: #c9d1d9;
    border-radius: 6px;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.7;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 320px;
    overflow-y: auto;
  }
</style>
