<template>
  <n-form :model="form" label-placement="left" label-width="150" style="max-width: 760px">
    <n-divider title-placement="left">通用</n-divider>
    <n-form-item label="最低严重级别">
      <n-select v-model:value="form.min_severity" :options="severityOptions" clearable placeholder="不限制（调用方可单独指定）" style="width: 240px" />
    </n-form-item>
    <n-form-item label="仅使用标签">
      <n-dynamic-tags v-model:value="form.include_tags" />
    </n-form-item>
    <n-form-item label="排除标签">
      <n-dynamic-tags v-model:value="form.exclude_tags" />
    </n-form-item>
    <n-form-item label="排除模板 ID">
      <n-dynamic-tags v-model:value="form.exclude_ids" />
    </n-form-item>
    <n-form-item label="导入后默认启用">
      <n-radio-group v-model:value="form.default_enable">
        <n-space>
          <n-radio value="all">全部可用模板</n-radio>
          <n-radio value="high">仅 high / critical</n-radio>
          <n-radio value="none">全部不启用</n-radio>
        </n-space>
      </n-radio-group>
    </n-form-item>

    <n-divider title-placement="left">被动检测</n-divider>
    <n-form-item label="展开 payloads">
      <n-switch v-model:value="form.expand_payloads" />
      <n-text depth="3" style="margin-left: 12px">把 payloads / variables 的取值展开为具体请求特征，降低误报；关闭则变量一律按通配符</n-text>
    </n-form-item>
    <n-form-item label="单变量取值上限">
      <n-input-number v-model:value="form.expand_limit" :min="1" :max="1000" />
      <n-text depth="3" style="margin-left: 12px">取值数超过该值的字典（如大型密码本）退化为通配符</n-text>
    </n-form-item>

    <n-form-item label=" ">
      <n-space>
        <n-button type="primary" :loading="saving" @click="save">保存配置</n-button>
        <n-text depth="3">保存后立即生效（模板将按新配置重新编译）</n-text>
      </n-space>
    </n-form-item>
  </n-form>
</template>

<script lang="ts" setup>
import { reactive, ref, onMounted } from 'vue';
import { useMessage } from 'naive-ui';
import { getVulnSettings, saveVulnSettings } from '@/api/engine/vuln';
import { severityOptions } from './yaml';

const message = useMessage();
const saving = ref(false);
const form = reactive<any>({
  min_severity: null, include_tags: [], exclude_tags: [], exclude_ids: [],
  default_enable: 'all', expand_payloads: true, expand_limit: 100,
});

function fill(s: any) {
  Object.assign(form, s, {
    min_severity: s.min_severity || null,
    include_tags: s.include_tags || [], exclude_tags: s.exclude_tags || [], exclude_ids: s.exclude_ids || [],
  });
}
onMounted(() => getVulnSettings().then(fill));
function save() {
  saving.value = true;
  saveVulnSettings({ ...form, min_severity: form.min_severity || '' })
    .then((s) => { fill(s); message.success('已保存'); })
    .finally(() => (saving.value = false));
}
</script>
