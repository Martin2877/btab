<template>
  <div>
    <n-alert type="info" :show-icon="false" style="margin-bottom: 12px">
      选择已保存的脚本或粘贴脚本内容，对流量包执行调试。脚本检测依赖 tshark 提取报文字段。
    </n-alert>
    <n-space style="margin-bottom: 12px" align="center">
      <n-radio-group v-model:value="mode">
        <n-radio-button value="id">已有脚本</n-radio-button>
        <n-radio-button value="content">粘贴脚本</n-radio-button>
        <n-radio-button value="all">全部脚本</n-radio-button>
      </n-radio-group>
      <n-select
        v-if="mode === 'id'"
        v-model:value="selScript"
        :options="scriptOptions"
        placeholder="选择脚本"
        filterable
        style="width: 260px"
      />
      <n-button type="primary" :loading="running" @click="run">开始调试</n-button>
    </n-space>

    <Codemirror
      v-if="mode === 'content'"
      v-model:value="content"
      :options="cmOptions"
      border
      :height="260"
      placeholder="粘贴 JS 检测脚本"
      style="margin-bottom: 12px"
    />

    <n-space style="margin-bottom: 12px" align="center">
      <n-select
        v-model:value="pcapId"
        :options="pcapOptions"
        placeholder="选择流量包（stores/pcap）"
        filterable
        clearable
        style="width: 320px"
        :disabled="!!uploadFile"
      />
      <n-upload
        action=""
        :show-file-list="false"
        :custom-request="pickPcap"
        accept=".pcap,.pcapng,.cap"
      >
        <n-button>或上传流量包</n-button>
      </n-upload>
      <n-tag v-if="uploadFile" closable @close="uploadFile = null">{{ uploadFile.name }}</n-tag>
    </n-space>

    <div v-if="result" style="margin-top: 8px">
      <n-space align="center" style="margin-bottom: 10px">
        <n-text>
          执行 {{ result.summary?.strategies || 0 }} 个脚本，命中
          <b>{{ result.summary?.hit || 0 }}</b> 个，检出
          <b>{{ result.summary?.events || 0 }}</b> 条事件
        </n-text>
      </n-space>
      <n-alert
        v-for="(r, i) in errResults"
        :key="'e' + i"
        type="error"
        :show-icon="false"
        style="margin-bottom: 6px"
      >
        {{ r.strategy }}：{{ r.error }}
      </n-alert>
      <n-card
        v-for="(ev, i) in result.events"
        :key="i"
        size="small"
        class="event-card"
        :class="{ 'is-attack': ev.type === 'attack' }"
      >
        <template #header>
          <n-space align="center" :size="8" :wrap-item="false">
            <span class="event-name">{{ ev.name || '未命名事件' }}</span>
            <n-tag v-if="ev.type" size="small" :type="ev.type === 'attack' ? 'error' : 'default'">{{
              ev.type
            }}</n-tag>
            <n-tag v-if="ev.phase" size="small" type="info" :bordered="false">{{ ev.phase }}</n-tag>
            <n-tag v-if="ev.strategy" size="small" type="warning" :bordered="false">{{
              ev.strategy
            }}</n-tag>
          </n-space>
        </template>
        <div class="event-meta" v-if="(ev.src || []).length || (ev.dst || []).length">
          <span class="meta-label">源/目的</span>
          <span class="meta-val"
            >{{ (ev.src || []).join(', ') || '?' }} → {{ (ev.dst || []).join(', ') || '?' }}</span
          >
        </div>
        <pre v-if="ev.desc" class="event-desc">{{ ev.desc }}</pre>
      </n-card>
      <n-empty
        v-if="!result.events.length && !errResults.length"
        description="未检出事件"
        style="padding: 24px 0"
      />
    </div>
  </div>
</template>

<script lang="ts" setup>
  import { ref, computed, watch, onMounted } from 'vue';
  import { useMessage } from 'naive-ui';
  import Codemirror from 'codemirror-editor-vue3';
  import 'codemirror/mode/javascript/javascript.js';
  import 'codemirror/theme/dracula.css';
  import {
    getLogicScripts,
    getLogicScriptContent,
    debugLogic,
    debugLogicUpload,
  } from '@/api/engine/logic';
  import { getPcapTableList } from '@/api/table/list';

  const props = defineProps<{ scriptId: string }>();
  const message = useMessage();

  const cmOptions = {
    mode: 'javascript',
    theme: 'dracula',
    lineNumbers: true,
    indentUnit: 2,
    tabSize: 2,
  };

  const mode = ref('id');
  const selScript = ref<string | null>(null);
  const content = ref('');
  const pcapId = ref<number | null>(null);
  const uploadFile = ref<File | null>(null);
  const running = ref(false);
  const result = ref<any>(null);
  const scriptOptions = ref<any[]>([]);
  const pcapOptions = ref<any[]>([]);

  watch(
    () => props.scriptId,
    (v) => {
      if (v) {
        mode.value = 'id';
        selScript.value = v;
        getLogicScriptContent({ id: v })
          .then((c) => (content.value = c?.content || ''))
          .catch(() => {});
      }
    },
    { immediate: true }
  );

  onMounted(() => {
    getLogicScripts({ page: 1, pageSize: 10000 }).then((r) => {
      scriptOptions.value = (r.list || []).map((s: any) => ({
        label: `${s.name}（${s.id}）`,
        value: s.id,
      }));
    });
    getPcapTableList({ page: 1, pageSize: 10000 }).then((r) => {
      pcapOptions.value = (r.list || []).map((p: any) => ({ label: p.name, value: p.id }));
    });
  });

  const errResults = computed(() => (result.value?.results || []).filter((r: any) => r.error));

  const pickPcap = ({ file }: { file: any }) => {
    uploadFile.value = file.file as File;
  };

  function run() {
    if (mode.value === 'id' && !selScript.value) return message.warning('请选择脚本');
    if (mode.value === 'content' && !content.value.trim()) return message.warning('请粘贴脚本内容');
    if (!uploadFile.value && !pcapId.value) return message.warning('请选择或上传流量包');
    running.value = true;
    result.value = null;
    const done = (r: any) => (result.value = r);
    const fin = () => (running.value = false);
    if (uploadFile.value) {
      const fd = new FormData();
      fd.append('file', uploadFile.value);
      if (mode.value === 'id') fd.append('id', selScript.value!);
      else if (mode.value === 'content') fd.append('content', content.value);
      debugLogicUpload(fd).then(done).finally(fin);
    } else {
      const body: any = { pcap: pcapId.value };
      if (mode.value === 'id') body.id = selScript.value;
      else if (mode.value === 'content') body.content = content.value;
      debugLogic(body).then(done).finally(fin);
    }
  }
</script>

<style lang="less" scoped>
  .event-card {
    margin-bottom: 8px;
    &.is-attack {
      border-left: 3px solid #d03050;
    }
    :deep(.n-card-header) {
      padding: 8px 12px;
    }
    :deep(.n-card__content) {
      padding: 8px 12px;
    }
  }
  .event-name {
    font-weight: 600;
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
    padding: 8px 10px;
    background: rgba(128, 128, 128, 0.08);
    border: 1px solid rgba(128, 128, 128, 0.15);
    border-radius: 4px;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 12px;
  }
  :deep(.CodeMirror) {
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
  }
</style>
