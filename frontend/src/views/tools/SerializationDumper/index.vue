<template>

<n-form
  :model="textValue"
  ref="formRef"
  label-placement="left"
  class="py-8"
>
  <n-space vertical>
    <n-input
      placeholder="填写序列化内容，如： aced0005740004414243447071007e0000"
      type="textarea"
      size="medium"
      :autosize="{
        minRows: 4,
        maxRows: 10
      }"
      show-count clearable
      v-model:value="textValue.payloads.content"
    />
  </n-space>
  <n-space>
      <n-button type="primary" :loading="formBtnLoading" @click="textSubmit">提交</n-button>
      <n-button @click="resetForm">重置</n-button>
    </n-space>

    <n-space vertical>
    <n-input
      placeholder="序列化解析结果"
      type="textarea"
      size="medium"
      :autosize="{
        minRows: 10,
        maxRows: 30
      }"
      v-model:value="retParams.result"
    />
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
  plugin: 'SerializationDumper',
  payloads: {
    content : "aced0005740004414243447071007e0000",
  },
};

const initialState2 = {
  result : ""
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
