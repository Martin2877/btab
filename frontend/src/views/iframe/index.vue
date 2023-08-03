<template>
  <n-card>
    <n-card :bordered="false" class="proCard">
     <BasicForm @register="register" @submit="jumpSubmit">
        <template #statusSlot="{ model, field }">
          <n-input v-model:value="model[field]" @keyup="inputJumpSubmit" />
        </template>

     </BasicForm>
  
    </n-card>
    
    <n-button v-on:submit="submit">SQL注入分析</n-button>
    <n-button v-on:submit="submit">命令执行分析</n-button>
    <n-button v-on:submit="submit">webshell分析</n-button>
    <n-button v-on:submit="submit">DNS分析</n-button>
    <n-button v-on:submit="submit">挖矿分析</n-button>


  </n-card>
  <n-card id="card1"></n-card>
  <n-spin :show="loading">
    <div class="frame">
      <iframe :src="frameSrc" id="myiframe" class="frame-iframe" ref="frameRef"></iframe>
    </div>
  </n-spin>
</template>
<script lang="ts" setup>
  import { useMessage } from 'naive-ui';
  import { ref, unref, onMounted, nextTick } from 'vue';
  import { useRoute } from 'vue-router';
  import { BasicForm, FormSchema, useForm } from '@/components/Form/index';

  const currentRoute = useRoute();
  const loading = ref(false);
  const frameRef = ref<HTMLFrameElement | null>(null);
  const frameSrc = ref<string>('');


  const message = useMessage();

  const schemas: FormSchema[] = [
    {
      field: 'address',
      labelMessage: '需要分析的地址',
      component: 'NInput',
      label: '分析目标',
      componentProps: {
        placeholder: '请输入要分析的风险详情地址',
        // onInput: (e: any) => {
        //   console.log(e);
        // },
        // onkeyup: (e: any) => {
        //   inputJumpSubmit(e);
        // },
      },
      rules: [{ required: true, message: '输入以供分析', trigger: ['blur'] }],
    },
    ]
  const [register, {}] = useForm({
    gridProps: { cols: '1 s:1 m:2 l:3 xl:4 2xl:4' },
    labelWidth: 90,
    schemas,
  });
  // const x = ref({cookie: document.getElementById('card1') });

  function inputJumpSubmit(record: any){
    frameSrc.value = record;
    message.info(frameSrc.value);
  }


  function jumpSubmit(record: Recordable){
    frameSrc.value = record.address;
    message.info(frameSrc.value);
  }


  if (unref(currentRoute.meta)?.frameSrc) {
    frameSrc.value = unref(currentRoute.meta)?.frameSrc as string;
  }

  function hideLoading() {
    loading.value = false;
  }

  function submit(){
    // message.info(x.value.cookie);
  }

  function init() {
    nextTick(() => {
      const iframe = unref(frameRef);
      if (!iframe) return;
      const _frame = iframe as any;
      if (_frame.attachEvent) {
        _frame.attachEvent('onload', () => {
          hideLoading();
        });
      } else {
        iframe.onload = () => {
          hideLoading();
        };
      }
    });
  }

  onMounted(() => {
    loading.value = true;
    init();
  });
</script>

<style lang="less" scoped>
  .frame {
    width: 100%;
    height: 100vh;

    &-iframe {
      width: 100%;
      height: 100%;
      overflow: hidden;
      border: 0;
      box-sizing: border-box;
    }
  }
</style>
