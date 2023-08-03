<template>
  <div>
    <div class="n-layout-page-header">
      <n-card :bordered="false" title="关于">
        {{ name }} (Blue Team Analyisis Box)
        是一个蓝队分析工具箱，专注于攻击特征分析。可以辅助安全运营人员的流量包分析、木马分析等场景，目前已集成流量包检测、SQL注入检测、Webshell
        检测、bash命令执行检测，以及解码序列化等工具。
      </n-card>
    </div>
    <n-card
      :bordered="false"
      title="项目信息"
      class="mt-4 proCard"
      size="small"
      :segmented="{ content: true }"
    >
      <n-descriptions bordered label-placement="left" class="py-2">
        <n-descriptions-item label="项目名称">
          <n-tag type="info"> BTAB (Blue Team Analyisis Box) 蓝队分析工具 </n-tag>
        </n-descriptions-item>

        <n-descriptions-item label="版本">
          <n-tag type="info"> {{ data.version }} </n-tag>
        </n-descriptions-item>

        <n-descriptions-item label="认证到期时间">
          <n-tag type="error"> {{ data.dateline }} </n-tag>
        </n-descriptions-item>

        <n-descriptions-item label="最后编译时间">
          <n-tag type="info"> {{ lastBuildTime }} </n-tag>
        </n-descriptions-item>

        <n-descriptions-item label="作者">
          <n-tag type="info"> Ali0th </n-tag>
        </n-descriptions-item>

        <n-descriptions-item label="联系">
          <div class="flex items-center">bWFydGluMjg3N0Bmb3htYWlsLmNvbQ==</div>
        </n-descriptions-item>
        <n-descriptions-item label="github">
          <div class="flex items-center">
            <a href="https://github.com/Martin2877" class="py-2" target="_blank"
              >点击查看 github
            </a>
          </div>
        </n-descriptions-item>
        <!-- <n-descriptions-item label="博客">
          <div class="flex items-center">
            <a href="https://blog.tophant.ai/" class="py-2" target="_blank"
              >点击查看博客</a
            >
          </div>
        </n-descriptions-item> -->
      </n-descriptions>
    </n-card>

    <!-- <n-card
      :bordered="false"
      title="开发环境依赖"
      class="mt-4 proCard"
      size="small"
      :segmented="{ content: true }"
    >
      <n-descriptions bordered label-placement="left" class="py-2">
        <n-descriptions-item v-for="item in devSchema" :key="item.field" :label="item.field">
          {{ item.label }}
        </n-descriptions-item>
      </n-descriptions>
    </n-card>

    <n-card
      :bordered="false"
      title="生产环境依赖"
      class="mt-4 proCard"
      size="small"
      :segmented="{ content: true }"
    >
      <n-descriptions bordered label-placement="left" class="py-2">
        <n-descriptions-item v-for="item in schema" :key="item.field" :label="item.field">
          {{ item.label }}
        </n-descriptions-item>
      </n-descriptions>
    </n-card> -->
  </div>
</template>

<script lang="ts" setup>
export interface schemaItem {
  field: string;
  label: string;
}

import { getLicenseDateline, getSystemVersion } from "@/api/system/system";
import { ref, onMounted } from "vue";

const data = ref({
  dateline: "",
  version: "",
});

const dogetLicenseDateline = async () => {
  return await getLicenseDateline();
};

const dogetSystemVersion = async () => {
  return await getSystemVersion();
};

onMounted(() => {
  dogetLicenseDateline().then((resp) => {
    data.value.dateline = resp;
  });

  dogetSystemVersion().then((resp) => {
    data.value.version = resp;
  });
});

const { pkg, lastBuildTime } = __APP_INFO__;
const { dependencies, devDependencies, name, version } = pkg;

const schema: schemaItem[] = [];
const devSchema: schemaItem[] = [];

Object.keys(dependencies).forEach((key) => {
  schema.push({ field: key, label: dependencies[key] });
});

Object.keys(devDependencies).forEach((key) => {
  devSchema.push({ field: key, label: devDependencies[key] });
});
</script>

<style lang="less" scoped></style>
