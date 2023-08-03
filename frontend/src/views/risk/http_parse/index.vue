<template>
  <div>
    <n-form :model="textValue" ref="formRef" label-placement="left" class="py-8">
      <n-grid
        class="mt-0 py-0"
        cols="2 s:1 m:1 l:2 xl:2 2xl:2"
        responsive="screen"
        :x-gap="0"
        :y-gap="20"
      >
        <n-gi>
          <n-card
            title="请求"
            :segmented="{ content: true }"
            :bordered="false"
            size="small"
            class="mt-0"
          >
            <n-input
              placeholder="请填入请求头信息
若请求中包含文件上传，建议复制原始十六进制数据到此处，例如使用WireShark，追踪流，选择'右下角show data as 原始数据'将请求部分粘贴此处"
              type="textarea"
              size="medium"
              class="py-0"
              maxlength="7000"
              show-count
              :autosize="{
                minRows: 15,
                maxRows: 15,
              }"
              v-model:value="textValue.req_data"
            />
          </n-card>
        </n-gi>
        <n-gi>
          <n-card
            title="响应"
            :segmented="{ content: true }"
            :bordered="false"
            size="small"
            class="mt-0"
          >
            <n-input
              placeholder="请填入响应头信息
若有文件下载的情况，建议将原始十六进制数据粘贴此处"
              type="textarea"
              size="medium"
              class="py-0"
              show-count
              :autosize="{
                minRows: 15,
                maxRows: 15,
              }"
              v-model:value="textValue.res_data"
            />
          </n-card>
        </n-gi>
      </n-grid>

      <n-button type="primary" :loading="formBtnLoading" @click="textSubmit">提交检测</n-button>
      <n-button @click="resetForm">一键清空上述内容</n-button>
    </n-form>

    <n-card :bordered="true" class="proCard">
      <n-layout>
        <n-layout has-sider>
          <n-layout-content sider-placement="right">
            URL类型: <n-tag type="success"> {{ textValue.url_type }} </n-tag> 请求Content-Type:
            <n-tag type="success"> {{ textValue.req_content_type }} </n-tag> 请求体类型: <n-tag type="success"> {{ textValue.req_client_type }} </n-tag>
          </n-layout-content>
          <n-layout-content sider-placement="right">
            响应Content-Type: <n-tag type="success"> {{ textValue.res_content_type }} </n-tag> 响应体类型:
            <n-tag type="success"> {{ textValue.res_client_type }} </n-tag>
          </n-layout-content>
        </n-layout>
        <n-layout-footer position="absolute" style="margin-bottom: 34px" />
      </n-layout>

      <n-data-table
        remote
        ref="table"
        :columns="columns"
        :data="textValue.table_data"
        :loading="textValue.loading"
        :row-key="rowKey"
      />
    </n-card>
    <n-card :bordered="true" title=">>详细数据<<" class="mt-0">
      <n-input
        placeholder="解析结果"
        type="textarea"
        size="medium"
        :autosize="{
          minRows: 4,
          maxRows: 10,
        }"
        show-count
        clearable
        v-model:value="textValue.result"
      />
    </n-card>
  </div>
</template>

<script lang="ts" setup>
  import { reactive, ref, onMounted } from 'vue';
  import { useMessage } from 'naive-ui';
  import { getRiskHttpParseTips } from '@/api/table/list';
  import { columns } from './columns';

  const formBtnLoading = ref(false);
  const formRef: any = ref(null);
  const message = useMessage();

  function rowKey(rowData) {
    return rowData.column1;
  }
  onMounted(() => {
    textValue.loading = false;
  });

  // const data = Array.apply(null, { length: 10 }).map((_, index) => {
  //   return {
  //     id: index,
  //     arg: '123',
  //     value: 'a' + index,
  //   };
  // });

  const initialState = {
    req_data: `POST /index.php?id=1&key=test HTTP/1.1
Host: 192.168.6.129
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

cmd=ls -all`,
    res_data: `HTTP/1.1 200 OK
Server: SimpleHTTP/0.6 Python/2.7.18
Date: Thu, 07 Jul 2022 03:31:22 GMT
Connection: close
Content-Type: text/html

<head>
<title>网页管理系统</title>
</head>
<body>
# ls -al
total 84
drwxr-xr-x  2 root root  4096 Mar  9 10:49 .
drwxr-xr-x 16 root root  4096 Mar  8 19:15 ..
-rw-r--r--  1 root root 15632 Mar  8 20:30 redis_auth_info.pcapng
-rw-r--r--  1 root root  5424 Mar  9 09:58 redis_info.pcapng
-rw-r--r--  1 root root 38404 Mar  8 20:27 redis_unauth_info.pcapng
</body>`,

    result: '暂未解析，请提交检测，以获取请求响应相关内容特征',
    table_data: [],
    loading: true,
    url_type: '未知',
    req_content_type: '未知',
    req_client_type: '未知',
    res_content_type: '未知',
    res_client_type: '未知',
  };

  const textValue = reactive({ ...initialState });

  // 即时检测 formSubmit
  function textSubmit(e) {
    textValue.loading = true;
    e.preventDefault();
    formBtnLoading.value = true;
    formRef.value.validate((errors) => {
      if (!errors) {
        getRiskHttpParseTips(textValue).then((resp) => {
          message.success(resp.result.message);
          textValue.result = JSON.stringify(resp.result.result); // 直接显示json
          textValue.table_data.splice(0);
          get_args(resp.result.result);
        });
      } else {
        message.error('请填写完整信息');
      }
      formBtnLoading.value = false;
    });
    textValue.loading = false;
  }

  // 解析检测结果，将参数及参数值显示
  function get_args(result: { [x: string]: string }) {
    var arg_name;
    var flag = true;
    var step = 1;
    for (var val in result) {
      if (val == 'req_url_type' && result[val] != '') {
        textValue.url_type = result[val];
      }
      if (val == 'req_content_type' && result[val] != '') {
        textValue.req_content_type = result[val];
      }
      if (val == 'req_client_body_type' && result[val] != '') {
        textValue.req_content_type = result[val];
      }
      if (val == 'res_content_type' && result[val] != '') {
        textValue.res_content_type = result[val];
      }
      if (val == 'res_client_body_type' && result[val] != '') {
        textValue.res_client_type = result[val];
      }
      if (val.indexOf('cba_') != -1) {
        arg_name = val.split('cba_');
        change_data(flag, step, arg_name[1], result[val]['value'], result[val]['type']);
        flag = false;
        step++;
      }
      if (val.indexOf('url_arg_') != -1) {
        arg_name = val.split('url_arg_');
        change_data(flag, step, arg_name[1], result[val]['value'], result[val]['type']);
        flag = false;
        step++;
      }
    }
    flag = true;
    console.log(textValue.table_data);
  }

  // 修改data数据
  function change_data(flag, step, arg_name, arg_value, first_judge) {
    var computer_price = { id: 1, arg: 'test', value: 'test', first_judge: '111' };
    if (flag) {
      console.log('te');
    }
    computer_price['id'] = step;
    computer_price['arg'] = arg_name;
    computer_price['value'] = arg_value;
    computer_price['first_judge'] = first_judge;
    // computer_price['other'] = DropMenu;
    // computer_price['action'] = '';
    textValue.table_data.push(computer_price);
  }

  function resetForm() {
    textValue.req_data = '';
    textValue.res_data = '';
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
