<template>
  <div>
    <!-- 输入区 -->
    <n-card :bordered="false" class="proCard" size="small">
      <template #header>
        <n-space align="center" :size="8">
          <span class="page-title">HTTP 深度解析</span>
          <n-tag size="small" type="info" :bordered="false">原始报文</n-tag>
          <n-tag size="small" type="info" :bordered="false">httpstream</n-tag>
          <n-tag size="small" type="info" :bordered="false">hex</n-tag>
        </n-space>
      </template>
      <n-form :model="textValue" ref="formRef" label-placement="left">
        <n-grid cols="1 m:2" responsive="screen" :x-gap="14" :y-gap="10">
          <n-gi>
            <div class="io-label">请求<span class="io-label-sub">Request / HTTP流 httpstream</span></div>
            <n-input
              placeholder="粘贴 HTTP 请求原文；也可直接粘贴 Wireshark「追踪 HTTP 流 / TCP 流」导出的完整 httpstream 文本（含多个请求/响应对，自动拆分）；文件上传场景可粘贴原始十六进制数据"
              type="textarea"
              size="medium"
              maxlength="500000"
              show-count
              :autosize="{ minRows: 13, maxRows: 22 }"
              v-model:value="textValue.req_data"
            />
          </n-gi>
          <n-gi>
            <div class="io-label">响应<span class="io-label-sub">Response</span></div>
            <n-input
              placeholder="粘贴 HTTP 响应原文；粘贴了完整 httpstream 时可留空（响应框单独粘贴 httpstream 同样支持）；文件下载场景可粘贴原始十六进制数据"
              type="textarea"
              size="medium"
              show-count
              maxlength="500000"
              :autosize="{ minRows: 13, maxRows: 22 }"
              v-model:value="textValue.res_data"
            />
          </n-gi>
        </n-grid>
        <div class="action-bar">
          <n-space align="center" :wrap="true">
            <n-button type="primary" :loading="formBtnLoading" @click="textSubmit">
              解析并检测
            </n-button>
            <n-button @click="openGenModal">合成流量包(.pcap)</n-button>
            <n-dropdown trigger="click" :options="sampleOptions" @select="fillSample">
              <n-button>示例</n-button>
            </n-dropdown>
            <n-button @click="resetForm">清空</n-button>
          </n-space>
        </div>
      </n-form>
    </n-card>

    <!-- 综合风险判定 -->
    <n-card v-if="risk" :bordered="false" class="proCard" size="small">
      <template #header>
        <n-space align="center" :size="8">
          <span>风险判定</span>
          <n-tag
            :type="risk.success ? 'error' : risk.found ? 'warning' : 'default'"
            :bordered="false"
            size="small"
          >
            {{ risk.success ? '攻击成功' : risk.found ? '发现攻击特征' : '未发现攻击' }}
          </n-tag>
          <n-tag v-if="exchangeCount > 1" type="info" size="small" :bordered="false">
            httpstream × {{ exchangeCount }}
          </n-tag>
        </n-space>
      </template>
      <div class="verdict">
        <span class="verdict-title">{{ risk.title }}</span>
        <span class="verdict-sub">{{ risk.verdict }}</span>
      </div>

      <!-- nuclei 模板引擎命中 -->
      <div v-if="risk.nuclei && risk.nuclei.length" class="risk-block">
        <div class="risk-block-title">
          <n-tag size="small" type="info" :bordered="false">nuclei 模板引擎</n-tag>
          <span>请求与响应均命中模板规则（可确认攻击成功）</span>
        </div>
        <div v-for="(f, i) in risk.nuclei" :key="'n' + i" class="risk-item">
          <div class="risk-line">
            <n-tag size="small" :type="sevType(f.severity)" :bordered="false">
              {{ f.severity }}
            </n-tag>
            <span class="risk-line-title">{{ f.name }}</span>
            <n-tag
              size="tiny"
              :bordered="false"
              class="rule-tag rule-link"
              title="点击查看检测规则"
              @click="openRule(f)"
            >
              规则 {{ f.template_id }}
            </n-tag>
            <n-tag v-if="f.req_frame" size="tiny" type="info" :bordered="false">
              #{{ f.req_frame }}
            </n-tag>
            <span class="risk-line-sub">{{ f.method }} {{ f.uri }}</span>
          </div>
          <div class="risk-detail">
            <template v-if="f.matchers && f.matchers.length">
              命中 matcher: {{ f.matchers.join(', ') }}
            </template>
            <template v-if="f.evidence && f.evidence.length">
              {{ f.matchers && f.matchers.length ? '｜' : '' }}证据:
              {{ f.evidence.join(' | ') }}
            </template>
          </div>
        </div>
      </div>

      <!-- 本地特征引擎检出 -->
      <div v-if="risk.items && risk.items.length" class="risk-block">
        <div class="risk-block-title">
          <n-tag size="small" type="warning" :bordered="false">本地特征引擎</n-tag>
          <span>请求载荷特征检出</span>
        </div>
        <div v-for="(it, i) in risk.items" :key="'i' + i" class="risk-item">
          <div class="risk-line">
            <n-tag size="small" :type="sevType(it.severity)" :bordered="false">
              {{ it.severity || it.title }}
            </n-tag>
            <span class="risk-line-title">{{ it.title }}</span>
            <n-tag size="tiny" :bordered="false" class="engine-tag">{{ it.engine }}</n-tag>
            <n-tag
              size="tiny"
              :bordered="false"
              class="rule-tag rule-link"
              title="点击查看检测规则"
              @click="openRule(it)"
            >
              查看规则
            </n-tag>
            <n-tag v-if="it.frame" size="tiny" type="info" :bordered="false">
              #{{ it.frame }}
            </n-tag>
          </div>
          <div class="risk-detail">
            <template v-if="it.uri">{{ it.method }} {{ it.uri }} ｜</template>
            <template v-if="it.rule">规则: {{ it.rule }}</template>
            <template v-if="it.detail">{{ it.rule ? ' ｜ ' : '' }}{{ it.detail }}</template>
          </div>
        </div>
      </div>

      <!-- 跨会话分析引擎 -->
      <div v-if="risk.session && risk.session.length" class="risk-block">
        <div class="risk-block-title">
          <n-tag size="small" type="success" :bordered="false">session 跨会话分析引擎</n-tag>
          <span>多请求关联分析（webshell 密钥协商 / 加密通信还原）</span>
        </div>
        <div v-for="(f, i) in risk.session" :key="'s' + i" class="risk-item">
          <div class="risk-line">
            <n-tag size="small" type="error" :bordered="false">{{ f.severity }}</n-tag>
            <span class="risk-line-title">{{ f.title }}</span>
            <n-tag size="tiny" :bordered="false" class="engine-tag">{{ f.engine }}</n-tag>
            <n-tag
              size="tiny"
              type="info"
              :bordered="false"
              class="rule-tag rule-link"
              title="点击查看检测规则"
              @click="openRule(f)"
            >
              规则 {{ f.type }}
            </n-tag>
          </div>
          <div class="risk-detail">
            {{ f.detail }}
            <template v-if="f.frames && f.frames.length"> ｜关联请求 #{{ f.frames.join(', #') }}</template>
            <template v-if="f.password"> ｜口令 {{ f.password }}</template>
            <template v-if="f.key"> ｜密钥 {{ f.key }}</template>
          </div>
          <div v-for="(d, j) in (f.decoded || []).slice(0, 4)" :key="'sd' + j" class="decoded-line">
            <span class="decoded-meta">#{{ d.frame }} {{ d.direction }} · {{ d.chain }}</span>
            <pre class="decoded-plain">{{ d.plain }}</pre>
          </div>
        </div>
      </div>

      <!-- nuclei 疑似模板（仅请求特征） -->
      <div v-if="risk.signature && risk.signature.length" class="risk-block">
        <div class="risk-block-title">
          <n-tag size="small" type="info" :bordered="false">nuclei 模板引擎</n-tag>
          <span>疑似对应模板（仅请求侧强特征匹配，通用弱特征已过滤，响应未验证）</span>
        </div>
        <div v-for="(f, i) in risk.signature" :key="'g' + i" class="risk-line">
          <n-tag size="small" :type="sevType(f.severity)" :bordered="false">
            {{ f.severity }}
          </n-tag>
          <span class="risk-line-title">{{ f.name }}</span>
          <n-tag
            size="tiny"
            :bordered="false"
            class="rule-tag rule-link"
            title="点击查看检测规则"
            @click="openRule(f)"
          >
            规则 {{ f.template_id }}
          </n-tag>
          <span class="risk-line-sub">命中特征: {{ sigLiteralText(f) }}</span>
        </div>
      </div>
    </n-card>

    <!-- httpstream 各请求摘要 -->
    <n-card
      v-if="exchangeSummaries.length > 1"
      :bordered="false"
      class="proCard"
      size="small"
      title="请求/响应对"
    >
      <n-data-table
        size="small"
        :columns="streamColumns"
        :data="exchangeSummaries"
        :row-key="(row) => row.index"
        :row-props="streamRowProps"
        :row-class-name="streamRowClass"
        :pagination="{ pageSize: 10 }"
      />
      <div class="table-hint">点击某一行，可在下方「详细数据」中查看该请求/响应的完整解析</div>
    </n-card>

    <!-- 参数解析 -->
    <n-card v-if="parsed" :bordered="false" class="proCard" size="small" title="参数解析">
      <n-data-table
        v-if="paramRows.length"
        size="small"
        :columns="paramColumns"
        :data="paramRows"
        :pagination="{ pageSize: 15 }"
      />
      <n-empty v-else description="未解析到请求参数" style="padding: 24px 0" />
    </n-card>

    <!-- 详细数据：按请求/响应对可视化展示 -->
    <n-card v-if="details.length" :bordered="false" class="proCard" size="small" title="详细数据">
      <n-tabs
        v-if="details.length > 1"
        v-model:value="activeDetailIdx"
        type="card"
        size="small"
        class="ex-tabs"
      >
        <n-tab v-for="d in details" :key="d.index" :name="d.index">
          #{{ d.index }} {{ d.method || '-' }} {{ shortUri(d.uri) }}
        </n-tab>
      </n-tabs>

      <div v-if="currentDetail" class="detail-body">
        <n-grid cols="1 l:2" responsive="screen" :x-gap="18" :y-gap="14">
          <!-- 请求 -->
          <n-gi>
            <div class="det-title">请求</div>
            <n-descriptions
              bordered
              size="small"
              :column="1"
              label-placement="left"
              class="det-desc"
            >
              <n-descriptions-item label="请求行">
                <span class="mono">{{ reqLine(currentDetail) }}</span>
              </n-descriptions-item>
              <n-descriptions-item label="Host">{{ currentDetail.host || '-' }}</n-descriptions-item>
              <n-descriptions-item label="URL 类型">
                <n-tag size="small" type="success" :bordered="false">
                  {{ currentDetail.req_url_type || '未知' }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item label="Content-Type">
                <n-tag size="small" type="success" :bordered="false">
                  {{ currentDetail.req_content_type || '未知' }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item label="请求体类型">
                <n-tag size="small" type="success" :bordered="false">
                  {{ currentDetail.req_body_type || '未知' }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item label="UA 识别">
                <n-tag
                  size="small"
                  :type="uaTagType(currentDetail.req_ua_type)"
                  :bordered="false"
                >
                  {{ currentDetail.req_ua_type || '未知' }}
                </n-tag>
              </n-descriptions-item>
            </n-descriptions>
            <div class="det-sub">请求头 · {{ (currentDetail.req_headers || []).length }}</div>
            <n-data-table
              v-if="(currentDetail.req_headers || []).length"
              size="small"
              :columns="headerColumns"
              :data="currentDetail.req_headers"
              :pagination="false"
              :max-height="240"
            />
            <div v-else class="det-none">无</div>
            <div class="det-sub">请求体</div>
            <pre class="body-view">{{ prettyBody(currentDetail.req_body) }}</pre>
          </n-gi>

          <!-- 响应 -->
          <n-gi>
            <div class="det-title">响应</div>
            <template v-if="currentDetail.has_resp">
              <n-descriptions
                bordered
                size="small"
                :column="1"
                label-placement="left"
                class="det-desc"
              >
                <n-descriptions-item label="状态行">
                  <span class="mono">{{ respLine(currentDetail) }}</span>
                  <n-tag
                    size="small"
                    :type="statusTagType(currentDetail.status)"
                    :bordered="false"
                    style="margin-left: 8px"
                  >
                    {{ statusText(currentDetail.status) }}
                  </n-tag>
                </n-descriptions-item>
                <n-descriptions-item label="Content-Type">
                  <n-tag size="small" type="success" :bordered="false">
                    {{ currentDetail.res_content_type || '未知' }}
                  </n-tag>
                </n-descriptions-item>
                <n-descriptions-item label="响应体类型">
                  <n-tag size="small" type="success" :bordered="false">
                    {{ currentDetail.res_body_type || '未知' }}
                  </n-tag>
                </n-descriptions-item>
              </n-descriptions>
              <div class="det-sub">响应头 · {{ (currentDetail.resp_headers || []).length }}</div>
              <n-data-table
                v-if="(currentDetail.resp_headers || []).length"
                size="small"
                :columns="headerColumns"
                :data="currentDetail.resp_headers"
                :pagination="false"
                :max-height="240"
              />
              <div v-else class="det-none">无</div>
              <div class="det-sub">响应体</div>
              <pre class="body-view">{{ prettyBody(currentDetail.resp_body) }}</pre>
            </template>
            <n-empty v-else description="无响应数据" style="padding: 40px 0" />
          </n-gi>
        </n-grid>

        <n-collapse class="det-raw">
          <n-collapse-item title="原始解析数据（JSON）" name="raw">
            <pre class="body-view">{{ JSON.stringify(currentDetail.parsed, null, 2) }}</pre>
          </n-collapse-item>
        </n-collapse>
      </div>
    </n-card>

    <!-- 合成流量包 -->
    <n-modal
      v-model:show="showGenModal"
      :show-icon="false"
      preset="dialog"
      title="合成流量包(.pcap)"
      :style="{ width: '560px' }"
    >
      <n-form label-placement="left" :label-width="90" class="py-4">
        <n-form-item label="源IP">
          <n-input placeholder="默认 192.168.1.100" v-model:value="genParams.src_ip" />
        </n-form-item>
        <n-form-item label="目标IP">
          <n-input placeholder="默认 192.168.1.200" v-model:value="genParams.dst_ip" />
        </n-form-item>
        <n-form-item label="目标端口">
          <n-input-number
            :min="1"
            :max="65535"
            placeholder="默认 80"
            v-model:value="genParams.dst_port"
            style="width: 100%"
          />
        </n-form-item>
        <n-form-item label="文件名">
          <n-input placeholder="默认 btab_http_session" v-model:value="genParams.filename">
            <template #suffix>.pcap</template>
          </n-input>
        </n-form-item>
      </n-form>
      <n-alert :show-icon="false" type="info" style="font-size: 12px">
        使用上方请求/响应内容合成包含 TCP 三次握手、数据传输与挥手的完整会话 pcap 文件，可直接用
        Wireshark 打开。httpstream 多会话输入时取第一对会话生成。
      </n-alert>
      <template #action>
        <n-space>
          <n-button @click="() => (showGenModal = false)">取消</n-button>
          <n-button type="info" :loading="genBtnLoading" @click="doGenPcap">生成并下载</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 检测规则查看 -->
    <n-modal
      v-model:show="showRuleModal"
      :show-icon="false"
      preset="card"
      :style="{ width: '860px' }"
      :title="ruleView.name || ruleView.title || '检测规则'"
    >
      <n-space align="center" :size="8" style="margin-bottom: 10px" :wrap="true">
        <n-tag
          v-if="ruleView.severity"
          :type="sevType(ruleView.severity)"
          :bordered="false"
          size="small"
        >
          {{ ruleView.severity }}
        </n-tag>
        <n-tag v-if="ruleView.engine" size="small" :bordered="false">{{ ruleView.engine }}</n-tag>
        <n-tag v-if="ruleView.template" size="small" :bordered="false" class="mono">
          {{ ruleView.template }}
        </n-tag>
      </n-space>
      <template v-if="isNucleiRule">
        <n-spin :show="ruleLoading">
          <div v-if="ruleYaml" class="yaml-view" v-html="ruleYamlHtml"></div>
          <n-empty
            v-else-if="!ruleLoading"
            description="未找到规则原文（模板可能已删除或不在规则库中）"
            style="padding: 24px 0"
          />
        </n-spin>
        <div class="table-hint">
          请求符合规则的请求定义且响应命中 matchers 时判定攻击成功；仅请求特征命中列为疑似
        </div>
      </template>
      <template v-else>
        <n-descriptions bordered size="small" :column="1" label-placement="left">
          <n-descriptions-item label="检测引擎">{{ ruleView.engine || '-' }}</n-descriptions-item>
          <n-descriptions-item label="命中特征">
            {{ ruleView.rule || ruleView.type || '-' }}
          </n-descriptions-item>
          <n-descriptions-item v-if="ruleView.detail" label="判定说明">
            {{ ruleView.detail }}
          </n-descriptions-item>
          <n-descriptions-item v-if="ruleDescText" label="规则原理">
            {{ ruleDescText }}
          </n-descriptions-item>
        </n-descriptions>
      </template>
      <template #footer>
        <n-space justify="end">
          <n-button v-if="isNucleiRule" type="primary" size="small" @click="gotoTemplate">
            在规则库中查看
          </n-button>
          <n-button size="small" @click="showRuleModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script lang="ts" setup>
  import { reactive, ref, computed } from 'vue';
  import { useMessage } from 'naive-ui';
  import { useRouter } from 'vue-router';
  import { getRiskHttpParseTips, genHttpPcap } from '@/api/table/list';
  import { getVulnTemplateContent } from '@/api/engine/vuln';
  import { highlightYaml } from '@/views/engine/vuln/yaml';
  import { paramColumns, headerColumns } from './columns';

  const formBtnLoading = ref(false);
  const formRef: any = ref(null);
  const message = useMessage();
  const router = useRouter();

  const risk = ref<any>(null);
  const parsed = ref<any>(null);
  const exchangeCount = ref(0);
  const exchangeSummaries = ref<any[]>([]);
  const details = ref<any[]>([]);
  const paramRows = ref<any[]>([]);
  const activeDetailIdx = ref(1);

  const showGenModal = ref(false);
  const genBtnLoading = ref(false);
  const genParams = reactive({ src_ip: '', dst_ip: '', dst_port: 80, filename: '' });

  const streamColumns = [
    { title: '#', key: 'index', width: 48 },
    { title: '方法', key: 'method', width: 76 },
    { title: 'URI', key: 'uri' },
    { title: 'Host', key: 'host', width: 170 },
    {
      title: '状态码',
      key: 'status',
      width: 80,
      render: (row) => (row.has_resp ? row.status : '无响应'),
    },
  ];

  const textValue = reactive({ req_data: '', res_data: '' });

  const currentDetail = computed(
    () => details.value.find((d) => d.index === activeDetailIdx.value) || details.value[0] || null
  );

  // ---------- 检测规则查看 ----------
  const showRuleModal = ref(false);
  const ruleLoading = ref(false);
  const ruleView = ref<any>({});
  const ruleYaml = ref('');
  const ruleYamlHtml = computed(() => highlightYaml(ruleYaml.value));
  const isNucleiRule = computed(() => !!(ruleView.value.template || ruleView.value.template_id));

  // 内置引擎规则说明（本地引擎规则内置于代码，无模板原文可看）
  const ruleDescMap: Record<string, string> = {
    webshell:
      '对请求 URI 与 Body 做多级解码还原（base64 / hex / gzinflate / 异或等），还原结果命中内置 webshell 特征规则库并累计评分判定。',
    bash: '对载荷做反混淆与规范化后，匹配内置 bash/shell 命令、反弹 shell 等特征规则。',
    log4j2: '解析 ${jndi:...} 等 lookup 表达式，协议为 ldap/rmi/dns 等可利用类型即判定为 JNDI 注入。',
    sqli: '基于 libinjection 的 SQL 词法指纹检测。',
    xss: '基于 libinjection 的 XSS 词法检测。',
    'webshell-behinder':
      '冰蝎 webshell：提取前置会话协商的 16 位密钥（或内置默认密钥），对后续加密请求/响应做 AES-128-ECB（含 base64、xor 变种）解密还原，能解出有效载荷即确认通信信道。',
    'webshell-form':
      '口令型 webshell（蚁剑/菜刀/一句话）：表单参数中携带可执行代码，其余参数经 base64 解码还原为实际命令。',
  };
  const ruleDescText = computed(() => ruleDescMap[ruleView.value.type] || '');

  function openRule(item: any) {
    ruleView.value = item;
    ruleYaml.value = '';
    showRuleModal.value = true;
    const key = item.template || item.template_id;
    if (key) {
      ruleLoading.value = true;
      getVulnTemplateContent({ path: key })
        .then((c: any) => {
          if (typeof c === 'string') {
            ruleYaml.value = c;
          }
        })
        .catch(() => {})
        .finally(() => (ruleLoading.value = false));
    }
  }

  function gotoTemplate() {
    router.push({
      name: 'engine-vuln',
      query: { tab: 'templates', search: ruleView.value.template_id || ruleView.value.template },
    });
  }

  function sigLiteralText(f: any) {
    const lits = f.literals && f.literals.length ? f.literals : [f.literal];
    return lits.filter(Boolean).join(', ');
  }

  // ---------- 示例 ----------
  const sampleReq = `POST /index.php?id=1&key=test HTTP/1.1
Host: 192.168.6.129
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

cmd=ls -all`;

  const sampleRes = `HTTP/1.1 200 OK
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
drwxr-xr-x 16 root root  4096 Mar  8 20:30 redis_auth_info.pcapng
drwxr-xr-x  2 root root  4096 Mar  9 10:49 .
-rw-r--r--  1 root root  5424 Mar  9 09:58 redis_info.pcapng
-rw-r--r--  1 root root 38404 Mar  8 20:27 redis_unauth_info.pcapng
</body>`;

  const sampleStream = `POST /login HTTP/1.1
Host: 106.15.106.246:13333
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/80.0.3987.122 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

a=\${jndi:ldap://127.0.0.1:1111/faad}
HTTP/1.1 200
Content-Type: text/html;charset=UTF-8
Content-Language: en
Connection: close

<!doctype html>
<html lang="en"><body>Login Page</body></html>`;

  const sampleOptions = [
    { label: '请求 + 响应', key: 'pair' },
    { label: 'httpstream（log4j2）', key: 'stream' },
  ];

  function fillSample(key: string) {
    if (key === 'stream') {
      textValue.req_data = sampleStream;
      textValue.res_data = '';
    } else {
      textValue.req_data = sampleReq;
      textValue.res_data = sampleRes;
    }
    textSubmit();
  }

  // ---------- 展示辅助 ----------
  function sevType(s: string) {
    const m: Record<string, string> = {
      critical: 'error',
      high: 'error',
      medium: 'warning',
      low: 'default',
      info: 'info',
    };
    return m[(s || '').toLowerCase()] || 'default';
  }

  function uaTagType(t: string) {
    if (!t || t === '未识别到漏扫工具') return 'default';
    return 'error';
  }

  function statusTagType(status: number) {
    if (!status) return 'default';
    if (status >= 500) return 'error';
    if (status >= 400) return 'warning';
    if (status >= 300) return 'info';
    return 'success';
  }

  function statusText(status: number) {
    const m: Record<number, string> = { 200: '正常', 301: '跳转', 302: '跳转', 404: '不存在', 403: '禁止访问', 401: '未授权', 500: '服务器错误' };
    return m[status] || '';
  }

  function reqLine(d: any) {
    return `${d.method || ''} ${d.uri || ''} ${d.version || ''}`.trim() || '-';
  }

  function respLine(d: any) {
    return `${d.resp_version || ''} ${d.status || ''} ${d.phrase || ''}`.trim() || '-';
  }

  function shortUri(uri: string) {
    if (!uri) return '';
    return uri.length > 34 ? uri.slice(0, 34) + '…' : uri;
  }

  function prettyBody(body: string) {
    if (!body) return '(空)';
    const t = body.trim();
    if (t.startsWith('{') || t.startsWith('[')) {
      try {
        return JSON.stringify(JSON.parse(t), null, 2);
      } catch (e) {}
    }
    return body;
  }

  function streamRowProps(row) {
    return {
      style: 'cursor: pointer',
      onClick: () => (activeDetailIdx.value = row.index),
    };
  }

  function streamRowClass(row) {
    return row.index === activeDetailIdx.value ? 'row-active' : '';
  }

  // ---------- 提交解析 ----------
  function textSubmit(e?: Event) {
    e?.preventDefault();
    if (!textValue.req_data && !textValue.res_data) {
      message.error('请填写请求或响应内容');
      return;
    }
    formBtnLoading.value = true;
    getRiskHttpParseTips(textValue)
      .then((resp) => {
        message.success(resp.result.message);
        const r = resp.result.result;
        parsed.value = r;
        risk.value = r.risk || null;
        exchangeCount.value = r.stream_exchanges || 0;
        exchangeSummaries.value = r.exchange_summaries || [];
        details.value = r.exchanges || [];
        paramRows.value = (r.params || []).map((p, i) => ({ ...p, _key: i }));
        if (details.value.length) {
          activeDetailIdx.value = details.value[0].index;
        }
      })
      .catch(() => message.error('解析请求失败'))
      .finally(() => (formBtnLoading.value = false));
  }

  function openGenModal() {
    if (!textValue.req_data && !textValue.res_data) {
      message.error('请先填写请求或响应内容');
      return;
    }
    showGenModal.value = true;
  }

  function doGenPcap() {
    genBtnLoading.value = true;
    genHttpPcap({
      ...genParams,
      req_data: textValue.req_data,
      res_data: textValue.res_data,
    })
      .then((res) => {
        const blob = new Blob([res.data], { type: 'application/octet-stream' });
        const dispo = res.headers['content-disposition'] || '';
        const m = dispo.match(/filename="?([^";]+)"?/);
        const name = m ? m[1] : (genParams.filename || 'btab_http_session') + '.pcap';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
        message.success('pcap 已生成并下载');
        showGenModal.value = false;
      })
      .catch(() => message.error('生成失败'))
      .finally(() => (genBtnLoading.value = false));
  }

  function resetForm() {
    textValue.req_data = '';
    textValue.res_data = '';
    risk.value = null;
    parsed.value = null;
    exchangeCount.value = 0;
    exchangeSummaries.value = [];
    details.value = [];
    paramRows.value = [];
  }
</script>

<style lang="less" scoped>
  .page-title {
    font-weight: 600;
  }
  .io-label {
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 6px;
  }
  .io-label-sub {
    margin-left: 6px;
    font-weight: 400;
    font-size: 12px;
    color: #999;
  }
  .action-bar {
    margin-top: 14px;
  }

  .verdict {
    display: flex;
    align-items: baseline;
    gap: 10px;
    flex-wrap: wrap;
  }
  .verdict-title {
    font-size: 15px;
    font-weight: 600;
  }
  .verdict-sub {
    color: #666;
    font-size: 12px;
  }

  .risk-block {
    margin-top: 12px;
  }
  .risk-block-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #999;
    margin-bottom: 4px;
  }
  .risk-item {
    padding: 2px 0;
  }
  .risk-line {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 3px 0;
    font-size: 13px;
    flex-wrap: wrap;
  }
  .risk-line-title {
    font-weight: 500;
  }
  .risk-line-sub {
    color: #999;
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 60%;
  }
  .rule-tag,
  .engine-tag {
    font-family: monospace;
  }
  .rule-link {
    cursor: pointer;
    &:hover {
      opacity: 0.75;
    }
  }
  .risk-detail {
    font-size: 12px;
    color: #888;
    padding: 0 0 4px 4px;
    word-break: break-all;
  }
  .decoded-line {
    margin: 4px 0 4px 4px;
  }
  .decoded-meta {
    font-size: 12px;
    color: #999;
  }
  .decoded-plain {
    margin: 2px 0 0;
    padding: 6px 8px;
    background: rgba(128, 128, 128, 0.08);
    border-radius: 4px;
    font-size: 12px;
    max-height: 120px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .table-hint {
    margin-top: 8px;
    font-size: 12px;
    color: #999;
  }
  :deep(.row-active td) {
    background: rgba(32, 128, 240, 0.08) !important;
  }

  .ex-tabs {
    margin-bottom: 12px;
  }
  .detail-body {
    margin-top: 4px;
  }
  .det-title {
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 8px;
  }
  .det-sub {
    font-size: 12px;
    font-weight: 600;
    color: #666;
    margin: 12px 0 6px;
  }
  .det-none {
    font-size: 12px;
    color: #bbb;
    padding: 8px;
    border: 1px dashed rgba(128, 128, 128, 0.3);
    border-radius: 4px;
    text-align: center;
  }
  .det-desc {
    :deep(.n-descriptions-table-content) {
      word-break: break-all;
    }
  }
  .mono {
    font-family: monospace;
    word-break: break-all;
  }
  .body-view {
    margin: 0;
    padding: 8px 10px;
    background: rgba(128, 128, 128, 0.08);
    border: 1px solid rgba(128, 128, 128, 0.15);
    border-radius: 4px;
    font-size: 12px;
    max-height: 320px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .det-raw {
    margin-top: 14px;
  }

  .yaml-view {
    background: #0d1117;
    color: #c9d1d9;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.5;
    border-radius: 6px;
    padding: 12px 14px;
    overflow: auto;
    max-height: 55vh;
    white-space: pre;
  }
  :deep(.yk-k) {
    color: #79c0ff;
  }
  :deep(.yk-c) {
    color: #8b949e;
  }
  :deep(.yk-t) {
    color: #ffa657;
    font-weight: 600;
  }
</style>
