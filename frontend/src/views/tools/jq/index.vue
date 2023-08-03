<template>

<n-form
  :model="textValue"
  ref="formRef"
  label-placement="left"
  class="py-8"
>
  <n-space vertical>
    <n-input
      placeholder="填写 json 内容"
      type="textarea"
      size="medium"
      :autosize="{
        minRows: 4,
        maxRows: 10
      }"
      show-count clearable
      v-model:value="textValue.payloads.content"
      @change="textSubmit"
    />
    <n-input
      placeholder="jq 过滤语句"
      show-count clearable
      v-model:value="textValue.payloads.filter"
      @blur="textSubmit"
    />
    <n-space>
      <n-button type="primary" :loading="formBtnLoading" @click="textSubmit">提交</n-button>
      <n-button @click="resetForm">重置</n-button>
    </n-space>

    <n-tabs type="line" animated>
      <n-tab-pane name="PLAIN" tab="PLAIN">
        <n-input
          placeholder="获取结果"
          type="textarea"
          size="medium"
          :autosize="{
            minRows: 10,
            maxRows: 30
          }"
          v-model:value="retParams.result"
        />
      </n-tab-pane>
      <n-tab-pane name="JSON" tab="JSON">
        <pre>{{ JSON.stringify(retParams.resultJson, null, 2) }}</pre>
      </n-tab-pane>
    </n-tabs>
  </n-space>
</n-form>

</template>

<script lang="ts" setup>
import { reactive, ref } from 'vue';
import { useMessage } from 'naive-ui';
import { addOnceToolsPluginList} from '@/api/table/list';



const formRef: any = ref(null);
const message = useMessage();
const formBtnLoading = ref(false);

const initialState = {
  plugin: 'jq',
  payloads: {
    filter : ".foo.bar",
    content: "{ \"foo\": { \"bar\": { \"baz\": 123 } } , \"boo\":\"123\"}"
  },
};

const initialState2 = {
  result : "",
  resultJson : reactive({}),
};

const textValue = reactive({ ...initialState });

const retParams = reactive({ ...initialState2 });


const addOnceDataTable = async (res) => {
  return await addOnceToolsPluginList({ ...res});
};


// 即时检测 formSubmit

function textSubmit(e) {
    e.preventDefault();
    formBtnLoading.value = true;
    formRef.value.validate((errors) => {
      if (!errors) {
        addOnceDataTable(textValue).then((resp)=>{
          if (resp.result.code == 20000){
            retParams.result = resp.result.result;
            retParams.resultJson = JSON.parse(resp.result.result);
          }else{
            message.error(resp.result.message);
          }
        });
      } else {
        message.error('请填写完整信息');
      }
      formBtnLoading.value = false;
    });
  }

function resetForm(){
  textValue.payloads.content = "";
  textValue.payloads.filter = "";
  retParams.result = "";
}

</script>

<style lang="less" scoped>
  .light-green {
    display: flex;
    align-items: center;
    justify-content: center;
    // height: 200px;
    // background-color: rgba(0, 128, 0, 0.12);
  }
</style>
