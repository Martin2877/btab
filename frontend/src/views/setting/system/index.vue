<template>
  <div>
    <n-card :bordered="false" class="proCard" title="系统设置">
      <n-alert
        v-if="loaded && tshark.ok"
        type="success"
        :show-icon="true"
        style="margin-bottom: 16px"
      >
        tshark 可用：{{ tshark.resolved }}
      </n-alert>
      <n-alert v-else-if="loaded" type="warning" :show-icon="true" style="margin-bottom: 16px">
        {{ tshark.error || '未检测到可用的 tshark' }}，请在下方配置正确的 tshark 路径，或将
        tshark 加入 PATH 后点击「自动检测」。
      </n-alert>

      <n-form :label-width="140" label-placement="left" style="max-width: 720px">
        <n-divider title-placement="left">流量检测</n-divider>

        <n-form-item label="tshark 路径">
          <n-input-group>
            <n-select
              v-model:value="form.tsharkPath"
              :options="tsharkOptions"
              filterable
              tag
              clearable
              placeholder="如 C:\Program Files\Wireshark\tshark.exe，或填 tshark 走 PATH 查找"
            />
            <n-button :loading="detecting" @click="detectTshark">自动检测</n-button>
          </n-input-group>
        </n-form-item>
        <n-form-item label="tshark 超时(秒)">
          <n-input-number v-model:value="form.tsharkTimeout" :min="1" :max="3600" />
        </n-form-item>

        <n-divider title-placement="left">网络</n-divider>

        <n-form-item label="HTTP 代理">
          <n-input
            v-model:value="form.proxy"
            placeholder="留空不使用代理，如 socks5://127.0.0.1:3210"
          />
        </n-form-item>

        <n-divider title-placement="left">系统</n-divider>

        <n-form-item label="启动时打开浏览器">
          <n-switch v-model:value="form.open_browser" />
        </n-form-item>

        <n-form-item label=" ">
          <n-space>
            <n-button type="primary" :loading="saving" @click="save">保存配置</n-button>
            <n-button @click="load">重新加载</n-button>
          </n-space>
        </n-form-item>
      </n-form>

      <n-text depth="3" v-if="configFile">配置文件：{{ configFile }}</n-text>
    </n-card>
  </div>
</template>

<script lang="ts" setup>
  import { computed, reactive, ref } from 'vue';
  import { useMessage } from 'naive-ui';
  import { getSystemConfig, updateSystemConfig, getTsharkStatus } from '@/api/system/system';

  const message = useMessage();

  const loaded = ref(false);
  const saving = ref(false);
  const detecting = ref(false);
  const configFile = ref('');
  const tshark = ref<any>({ ok: true, resolved: '', error: '', candidates: [] });

  const form = reactive({
    tsharkPath: '',
    tsharkTimeout: 120,
    proxy: '',
    open_browser: false,
  });

  const tsharkOptions = computed(() => {
    const set = new Set<string>();
    (tshark.value.candidates || []).forEach((p: string) => set.add(p));
    if (form.tsharkPath) set.add(form.tsharkPath);
    return Array.from(set).map((p) => ({ label: p, value: p }));
  });

  function applyConfig(resp) {
    const cfg = resp.config || {};
    form.tsharkPath = cfg['pcapAnalyseConfig.tsharkPath'] || '';
    form.tsharkTimeout = cfg['pcapAnalyseConfig.tsharkTimeout'] || 120;
    form.proxy = cfg['httpConfig.proxy'] || '';
    form.open_browser = cfg['serverConfig.open_browser'] === true;
    tshark.value = resp.tshark || tshark.value;
    configFile.value = resp.config_file || '';
    loaded.value = true;
  }

  function load() {
    getSystemConfig()
      .then(applyConfig)
      .catch(() => message.error('获取系统配置失败'));
  }

  function detectTshark() {
    detecting.value = true;
    getTsharkStatus()
      .then((resp) => {
        tshark.value = resp;
        if (resp && resp.ok && resp.resolved) {
          form.tsharkPath = resp.resolved;
          message.success('已检测到 tshark：' + resp.resolved);
        } else {
          message.warning('未检测到 tshark，请安装 Wireshark 后手动填写路径');
        }
      })
      .catch(() => message.error('探测失败'))
      .finally(() => (detecting.value = false));
  }

  function save() {
    saving.value = true;
    updateSystemConfig({
      'pcapAnalyseConfig.tsharkPath': form.tsharkPath,
      'pcapAnalyseConfig.tsharkTimeout': form.tsharkTimeout,
      'httpConfig.proxy': form.proxy,
      'serverConfig.open_browser': form.open_browser,
    })
      .then((resp) => {
        if (resp && resp.code === 200) {
          message.success('配置已保存并生效');
          if (resp.result) applyConfig(resp.result);
        } else {
          message.error((resp && resp.message) || '保存失败');
        }
      })
      .catch((e) => message.error('保存失败: ' + e))
      .finally(() => (saving.value = false));
  }

  load();
</script>

<style lang="less" scoped></style>
