<template>
  <n-card
    :bordered="false"
    class="proCard chat-page"
    @dragenter="onDragEnter"
    @dragover.prevent
    @dragleave="onDragLeave"
    @drop.prevent="onDrop"
  >
    <div class="page-bg"></div>

    <transition name="fade">
      <div v-if="dragging" class="drop-mask">
        <div class="drop-box">
          <n-icon size="56" color="#2d8cf0"><CloudUploadOutlined /></n-icon>
          <div class="drop-title">{{ $t('analyze.releaseFile') }}</div>
          <div class="drop-desc">{{ $t('analyze.releaseDesc') }}</div>
        </div>
      </div>
    </transition>

    <div class="chat-list" ref="listRef">
      <div v-if="!msgs.length" class="hero">
        <img class="hero-img" :src="analysisImg" alt="" />
        <div class="hero-title">{{ $t('analyze.heroTitle') }}</div>
        <div class="hero-desc">{{ $t('analyze.heroDesc') }}</div>
        <div class="hero-caps">
          <span v-for="c in caps" :key="c" class="cap">{{ c }}</span>
        </div>
        <div class="hero-hint">
          <n-icon size="14" style="vertical-align: -2px"><CloudUploadOutlined /></n-icon>
          {{ $t('analyze.heroHint') }}
        </div>
      </div>
      <template v-for="m in msgs" :key="m.key">
        <div class="msg user" v-if="m.role === 'user'">
          <div class="bubble user-b">
            <div class="msg-meta">{{ m.time }}</div>
            <n-tag v-if="m.file" size="small" class="file-chip" :bordered="false">{{
              m.file
            }}</n-tag>
            <pre v-if="m.text" class="msg-text">{{ m.text }}</pre>
            <n-space v-if="m.methods" size="small" style="margin-top: 6px">
              <n-tag v-for="t in m.methods" :key="t" size="small" type="info" :bordered="false">{{
                t
              }}</n-tag>
            </n-space>
          </div>
        </div>
        <div class="msg bot" v-else>
          <div class="bubble bot-b">
            <div class="msg-meta">{{ $t('analyze.taskPrefix') }}{{ m.taskId }}</div>
            <template v-if="m.running">
              <n-progress
                type="line"
                :percentage="pct(m)"
                :height="4"
                :border-radius="2"
                processing
                :show-indicator="false"
                style="margin-bottom: 10px"
              />
              <div class="bot-status">
                <n-spin size="small" style="margin-right: 8px" />
                <span
                  >{{ m.progress || $t('analyze.running')
                  }}<span class="muted" v-if="m.total">（{{ m.done }}/{{ m.total }}）</span></span
                >
              </div>
              <div v-if="(m.steps || []).length" class="mini-steps">
                <div v-for="(s, i) in m.steps" :key="i" class="mini-step">
                  <span class="dot" :class="s.status"></span>
                  <span class="mini-name">{{ s.name }}</span>
                  <span class="mini-detail">{{ s.detail }}</span>
                </div>
              </div>
            </template>
            <template v-else-if="m.error">
              <n-alert type="error" :show-icon="false">{{ m.error }}</n-alert>
            </template>
            <template v-else>
              <n-space align="center" size="small" style="margin-bottom: 6px">
                <n-tag :type="m.risk ? 'error' : 'success'" :bordered="false">
                  {{ m.risk ? $t('analyze.riskFound') : $t('analyze.noRisk') }}
                </n-tag>
                <n-tag v-for="t in m.types" :key="t" size="small" :bordered="false">{{ t }}</n-tag>
              </n-space>
              <div class="verdict">{{ m.verdict }}</div>
              <n-button
                type="primary"
                round
                size="medium"
                @click="openReport(m.taskId)"
                style="margin-top: 10px"
              >
                <template #icon
                  ><n-icon><FileSearchOutlined /></n-icon
                ></template>
                {{ $t('analyze.viewReport') }}
              </n-button>
            </template>
          </div>
        </div>
      </template>
    </div>

    <div class="composer">
      <div class="composer-box" :class="{ 'has-file': !!file }">
        <n-upload
          v-if="file"
          action=""
          :show-file-list="false"
          :custom-request="pickFile"
          class="file-slot"
        >
          <div class="file-pill">
            <n-icon size="16" style="margin-right: 6px"><FileOutlined /></n-icon>
            <span class="file-name">{{ file.name }}</span>
            <span class="file-size">{{ fmtSize(file.size) }}</span>
            <n-icon size="14" class="file-close" @click.stop="file = null"
              ><CloseOutlined
            /></n-icon>
          </div>
        </n-upload>
        <n-input
          v-model:value="text"
          type="textarea"
          :autosize="{ minRows: 2, maxRows: 8 }"
          :bordered="false"
          :placeholder="file ? $t('analyze.fileHint') : $t('analyze.placeholder')"
          @keydown.enter.ctrl="send"
        />
        <div class="composer-bar">
          <n-upload action="" :show-file-list="false" :custom-request="pickFile">
            <n-button size="small" secondary>
              <template #icon
                ><n-icon><CloudUploadOutlined /></n-icon
              ></template>
              {{ $t('analyze.uploadFile') }}
            </n-button>
          </n-upload>
          <n-button size="small" secondary :loading="sampling" @click="runSample">
            <template #icon
              ><n-icon><PlayCircleOutlined /></n-icon
            ></template>
            {{ $t('analyze.samplePcap') }}
          </n-button>
          <n-select
            v-model:value="methods"
            multiple
            :options="methodOptions"
            :placeholder="$t('analyze.methodPlaceholder')"
            size="small"
            style="width: 300px"
            max-tag-count="responsive"
          />
          <div style="flex: 1"></div>
          <n-button type="primary" round :disabled="!canSend" :loading="submitting" @click="send">
            <template #icon
              ><n-icon><ThunderboltOutlined /></n-icon
            ></template>
            {{ $t('analyze.run') }}
          </n-button>
        </div>
      </div>
    </div>
  </n-card>
</template>

<script lang="ts" setup>
  import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue';
  import { useRouter } from 'vue-router';
  import { useMessage } from 'naive-ui';
  import {
    CloudUploadOutlined,
    ThunderboltOutlined,
    FileOutlined,
    CloseOutlined,
    FileSearchOutlined,
    PlayCircleOutlined,
  } from '@vicons/antd';
  import {
    getAnalyzeMethods,
    submitAnalyzeTask,
    submitAnalyzeFile,
    getAnalyzeTask,
  } from '@/api/analyze';
  import { getPcapTableList } from '@/api/table/list';
  import analysisImg from '@/assets/images/analysis.svg';
  import { useI18n } from 'vue-i18n';

  const router = useRouter();
  const message = useMessage();
  const { t } = useI18n();

  const text = ref('');
  const file = ref<File | null>(null);
  const methods = ref<string[]>([]);
  const methodOptions = ref<any[]>([]);
  const submitting = ref(false);
  const sampling = ref(false);
  const msgs = ref<any[]>([]);
  const listRef = ref<HTMLElement>();
  const dragging = ref(0);
  let seq = 0;

  const canSend = computed(() => !!file.value || !!text.value.trim());
  const caps = computed(() => methodOptions.value.map((o: any) => o.label));
  const pct = (m: any) => (m.total ? Math.round(((m.done || 0) / m.total) * 100) : 0);

  const pickFile = ({ file: f }: any) => {
    file.value = f.file as File;
  };

  function fmtSize(n: number) {
    if (!n) return '';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  const hasFiles = (e: DragEvent) => !!e.dataTransfer?.types?.includes('Files');
  function onDragEnter(e: DragEvent) {
    if (hasFiles(e)) dragging.value++;
  }
  function onDragLeave(e: DragEvent) {
    if (hasFiles(e)) dragging.value = Math.max(0, dragging.value - 1);
  }
  function onDrop(e: DragEvent) {
    dragging.value = 0;
    const f = e.dataTransfer?.files?.[0];
    if (!f) return;
    file.value = f;
    message.info(`${t('analyze.fileImported')}${f.name}`);
  }

  onMounted(() => {
    getAnalyzeMethods()
      .then((r: any[]) => {
        methodOptions.value = (r || []).map((m) => ({ label: m.label, value: m.key }));
      })
      .catch(() => {});
  });

  function scrollBottom() {
    nextTick(() => {
      if (listRef.value) listRef.value.scrollTop = listRef.value.scrollHeight;
    });
  }

  function methodLabels() {
    if (!methods.value.length) return null;
    return methodOptions.value.filter((o) => methods.value.includes(o.value)).map((o) => o.label);
  }

  function now() {
    return new Date().toLocaleTimeString();
  }

  // launch 推送用户/机器人消息后提交任务并轮询进度；doSubmit 返回任务提交响应
  async function launch(userMsg: any, doSubmit: () => Promise<any>) {
    msgs.value.push(userMsg);
    const bot: any = {
      key: ++seq,
      role: 'bot',
      taskId: 0,
      running: true,
      progress: t('analyze.submitting'),
      done: 0,
      total: 0,
      steps: [],
    };
    msgs.value.push(bot);
    scrollBottom();
    try {
      const resp: any = await doSubmit();
      bot.taskId = resp?.id || 0;
      bot.progress = t('analyze.running');
      if (bot.taskId) {
        poll(bot);
      } else {
        bot.running = false;
        bot.error = t('analyze.taskFail');
      }
    } catch (e: any) {
      bot.running = false;
      bot.error = e?.message || t('analyze.taskFail');
    } finally {
      scrollBottom();
    }
  }

  async function send() {
    if (!canSend.value) return;
    submitting.value = true;
    const userMsg = {
      key: ++seq,
      role: 'user',
      time: now(),
      text: file.value ? '' : text.value.slice(0, 2000),
      file: file.value ? `${t('analyze.filePrefix')}${file.value.name}` : '',
      methods: methodLabels(),
    };
    const doSubmit = file.value
      ? () => {
          const fd = new FormData();
          fd.append('file', file.value as File);
          if (methods.value.length) fd.append('methods', methods.value.join(','));
          return submitAnalyzeFile(fd);
        }
      : () => submitAnalyzeTask({ content: text.value, methods: methods.value });
    await launch(userMsg, doSubmit);
    text.value = '';
    file.value = null;
    submitting.value = false;
  }

  // 示例：直接引用威胁仓库中内置的 goby.pcap（随包发布，列表接口自动补录），免上传提交分析
  async function runSample() {
    if (sampling.value) return;
    sampling.value = true;
    try {
      const resp: any = await getPcapTableList({ search: 'goby', page: 1, pageSize: 10 });
      const demo = (resp?.list || []).find((p: any) => (p.name || '').includes('goby'));
      if (!demo) {
        message.error(t('analyze.sampleFail'));
        return;
      }
      const userMsg = {
        key: ++seq,
        role: 'user',
        time: now(),
        text: '',
        file: `${t('analyze.samplePrefix')}${demo.name}`,
        methods: methodLabels(),
      };
      await launch(userMsg, () =>
        submitAnalyzeTask({
          pcap_id: demo.id,
          name: `示例-${demo.name}`,
          methods: methods.value,
        })
      );
    } catch (e) {
      message.error(t('analyze.sampleSubmitFail'));
    } finally {
      sampling.value = false;
    }
  }

  const timers = new Set<any>();
  onUnmounted(() => timers.forEach((t) => clearInterval(t)));

  function poll(bot: any) {
    let errs = 0;
    const t = setInterval(async () => {
      try {
        const r: any = await getAnalyzeTask({ id: bot.taskId });
        errs = 0;
        const p = r?.progress;
        const task = r?.task;
        if (p?.running) {
          bot.progress = p.current || '分析中';
          bot.done = p.done || 0;
          bot.total = p.total || 0;
          bot.steps = p.steps || [];
        } else if (task && task.state === 1) {
          bot.progress = '排队等待执行…';
        }
        if (task && task.state !== 1) {
          clearInterval(t);
          timers.delete(t);
          bot.running = false;
          if (task.state === 4) {
            bot.risk = task.risk;
            bot.verdict = task.verdict || '';
            bot.types = (r?.report?.types || []).slice(0, 5);
          } else {
            bot.error = task.verdict || '分析失败';
          }
          scrollBottom();
        }
      } catch (e) {
        // 连续失败说明任务已消失或服务异常，停止无限重试
        if (++errs >= 5) {
          clearInterval(t);
          timers.delete(t);
          bot.running = false;
          bot.error = '进度查询失败，任务可能已删除或服务异常';
          scrollBottom();
        }
      }
    }, 1000);
    timers.add(t);
  }

  function openReport(id: number) {
    router.push({ name: 'analyze-report', query: { id } });
  }
</script>

<style lang="less" scoped>
  .chat-page {
    position: relative;
    display: flex;
    flex-direction: column;
    height: calc(100vh - 140px);
    overflow: hidden;
  }
  // 背景：浅色渐变 + 右下角装饰插画水印
  .page-bg {
    position: absolute;
    inset: 0;
    pointer-events: none;
    background: url('../../assets/images/analysis.svg') right -40px bottom -30px / 380px auto
        no-repeat,
      linear-gradient(160deg, #f4f8ff 0%, #f7f9fc 45%, #f2f5fa 100%);
    opacity: 0.5;
  }
  .chat-list {
    position: relative;
    flex: 1;
    overflow-y: auto;
    padding: 8px 4px;
  }
  .hero {
    text-align: center;
    padding: 48px 24px 32px;
    .hero-img {
      width: 300px;
      max-width: 70%;
      filter: drop-shadow(0 12px 24px rgba(45, 140, 240, 0.12));
    }
    .hero-title {
      font-size: 22px;
      font-weight: 700;
      margin-top: 18px;
      background: linear-gradient(90deg, #1f3a68, #2d8cf0);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }
    .hero-desc {
      font-size: 13px;
      line-height: 1.9;
      color: #667085;
      max-width: 560px;
      margin: 12px auto 0;
    }
    .hero-caps {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px;
      margin-top: 18px;
      .cap {
        font-size: 12px;
        color: #2d5a9e;
        background: rgba(45, 140, 240, 0.08);
        border: 1px solid rgba(45, 140, 240, 0.18);
        border-radius: 999px;
        padding: 3px 12px;
      }
    }
    .hero-hint {
      margin-top: 20px;
      font-size: 12px;
      color: #98a2b3;
    }
  }
  .msg {
    display: flex;
    margin-bottom: 14px;
    &.user {
      justify-content: flex-end;
    }
    &.bot {
      justify-content: flex-start;
    }
  }
  .bubble {
    max-width: 72%;
    border-radius: 10px;
    padding: 10px 14px;
    font-size: 13px;
    line-height: 1.6;
    box-shadow: 0 1px 3px rgba(16, 24, 40, 0.06);
  }
  .user-b {
    background: linear-gradient(135deg, #d3e5ff, #c2d9ff);
    color: #1a1a1a;
  }
  .bot-b {
    background: #ffffff;
    border: 1px solid rgba(16, 24, 40, 0.06);
    min-width: 300px;
  }
  .msg-meta {
    font-size: 11px;
    opacity: 0.55;
    margin-bottom: 6px;
  }
  .msg-text {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    max-height: 220px;
    overflow-y: auto;
  }
  .file-chip {
    margin-bottom: 6px;
  }
  .bot-status {
    display: flex;
    align-items: center;
    color: #555;
    .muted {
      color: #98a2b3;
      font-size: 12px;
    }
  }
  .mini-steps {
    margin-top: 8px;
    border-top: 1px dashed rgba(16, 24, 40, 0.08);
    padding-top: 6px;
  }
  .mini-step {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 12px;
    line-height: 1.8;
    .dot {
      flex: none;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #18a058;
      &.hit {
        background: #d03050;
      }
      &.error {
        background: #f0a020;
      }
      &.skip {
        background: #c2c8d0;
      }
    }
    .mini-name {
      flex: none;
      color: #344054;
      font-weight: 500;
    }
    .mini-detail {
      color: #98a2b3;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
  }
  .verdict {
    font-size: 13px;
    word-break: break-all;
  }
  .composer {
    position: relative;
    padding-top: 12px;
  }
  .composer-box {
    border: 1px solid rgba(45, 140, 240, 0.22);
    border-radius: 14px;
    background: rgba(255, 255, 255, 0.85);
    backdrop-filter: blur(6px);
    box-shadow: 0 4px 16px rgba(16, 24, 40, 0.08);
    padding: 10px 12px 8px;
    transition: border-color 0.2s, box-shadow 0.2s;
    &:focus-within {
      border-color: rgba(45, 140, 240, 0.55);
      box-shadow: 0 4px 20px rgba(45, 140, 240, 0.15);
    }
    &.has-file {
      border-style: dashed;
    }
  }
  .file-pill {
    display: inline-flex;
    align-items: center;
    background: rgba(45, 140, 240, 0.08);
    border: 1px solid rgba(45, 140, 240, 0.25);
    border-radius: 8px;
    padding: 4px 10px;
    margin-bottom: 8px;
    font-size: 12px;
    max-width: 100%;
    .file-name {
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 360px;
    }
    .file-size {
      color: #98a2b3;
      margin-left: 8px;
      flex: none;
    }
    .file-close {
      margin-left: 8px;
      cursor: pointer;
      color: #98a2b3;
      flex: none;
      &:hover {
        color: #d03050;
      }
    }
  }
  .composer-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 6px;
  }
  .drop-mask {
    position: absolute;
    inset: 0;
    z-index: 10;
    background: rgba(45, 140, 240, 0.08);
    backdrop-filter: blur(2px);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .drop-box {
    border: 2px dashed rgba(45, 140, 240, 0.6);
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.9);
    padding: 36px 64px;
    text-align: center;
    .drop-title {
      font-size: 16px;
      font-weight: 600;
      margin-top: 10px;
    }
    .drop-desc {
      font-size: 12px;
      color: #98a2b3;
      margin-top: 4px;
    }
  }
  .fade-enter-active,
  .fade-leave-active {
    transition: opacity 0.15s;
  }
  .fade-enter-from,
  .fade-leave-to {
    opacity: 0;
  }
</style>
