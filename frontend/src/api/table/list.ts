import { http } from '@/utils/http/axios';


export interface BasicResponseModel<T = any> {
  code: number;
  message: string;
  result: T;
}

export interface BasicPageParams {
  pageNumber: number;
  pageSize: number;
  total: number;
}




//获取table
export function getTableList(params) {
  return http.request({
    url: '/table/list',
    method: 'get',
    params,
  });
}




// ====================================
//    API
// ====================================

//获取 table
export function getTableAPIList(params) {
  return http.request({
    url: '/table/api/list',
    method: 'get',
    params,
  });
}

/**
 * @description: API 添加
 */
 export function addTableAPIList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/table/api/add',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: API 更新
 */
export function updateTableAPIList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/table/api/update',
      method: 'post',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

// 删除 api table 项
export function delTableAPIList(params) {
  return http.request({
    url: '/table/api/del',
    method: 'get',
    params,
  });
}

// ====================================
//    PCAP
// ====================================


// 上传
export function uploadDataReq(params) {
  const headers = { 'Content-Type': 'multipart/form-data' };
  return http.request({
    url: '/stores/pcap/upload',
    method: 'post',
    params,
    headers
  });
}


//获取 table
export function getPcapTableList(params) {
  return http.request({
    url: '/stores/pcap/list',
    method: 'get',
    params,
  });
}

// 删除项
export function delPcapTableList(params) {
  return http.request({
    url: '/stores/pcap/del',
    method: 'get',
    params,
  });
}


// ====================================
//   Payload
// ====================================


// 上传
export function uploadPayloadDataReq(params) {
  const headers = { 'Content-Type': 'multipart/form-data' };
  return http.request({
    url: '/stores/payload/upload',
    method: 'post',
    params,
    headers
  });
}


//获取 table
export function getPayloadTableList(params) {
  return http.request({
    url: '/stores/payload/list',
    method: 'get',
    params,
  });
}

// 删除项
export function delPayloadTableList(params) {
  return http.request({
    url: '/stores/payload/del',
    method: 'get',
    params,
  });
}


//获取 table
export function getPayloadDetailTableList(params) {
  return http.request({
    url: '/stores/payload/detail',
    method: 'get',
    params,
  });
}



// ====================================
//   Webshell
// ====================================


// 上传
export function uploadWebshellDataReq(params) {
  const headers = { 'Content-Type': 'multipart/form-data' };
  return http.request({
    url: '/stores/webshell/upload',
    method: 'post',
    params,
    headers
  });
}


//获取 table
export function getWebshellTableList(params) {
  return http.request({
    url: '/stores/webshell/list',
    method: 'get',
    params,
  });
}

// 删除项
export function delWebshellTableList(params) {
  return http.request({
    url: '/stores/webshell/del',
    method: 'get',
    params,
  });
}


//获取 table
export function getWebshellDetailTableList(params) {
  return http.request({
    url: '/stores/webshell/detail',
    method: 'get',
    params,
  });
}


// ====================================
//   Weblog（web 访问日志）
// ====================================

// 上传
export function uploadWeblogDataReq(params) {
  const headers = { 'Content-Type': 'multipart/form-data' };
  return http.request({
    url: '/stores/weblog/upload',
    method: 'post',
    params,
    headers
  });
}

//获取 table
export function getWeblogTableList(params) {
  return http.request({
    url: '/stores/weblog/list',
    method: 'get',
    params,
  });
}

// 删除项
export function delWeblogTableList(params) {
  return http.request({
    url: '/stores/weblog/del',
    method: 'get',
    params,
  });
}

//获取日志内容（按 id）
export function getWeblogDetailTableList(params) {
  return http.request({
    url: '/stores/weblog/detail',
    method: 'get',
    params,
  });
}


// ====================================
//   Nuclei 模板
// 上传
export function uploadNucleiDataReq(params) {
  const headers = { 'Content-Type': 'multipart/form-data' };
  return http.request({
    url: '/stores/nuclei/upload',
    method: 'post',
    params,
    headers
  });
}

//获取 table
export function getNucleiTableList(params) {
  return http.request({
    url: '/stores/nuclei/list',
    method: 'get',
    params,
  });
}

// 删除项
export function delNucleiTableList(params) {
  return http.request({
    url: '/stores/nuclei/del',
    method: 'get',
    params,
  });
}

//获取详情
export function getNucleiDetailTableList(params) {
  return http.request({
    url: '/stores/nuclei/detail',
    method: 'get',
    params,
  });
}

// 启用/停用
export function setNucleiEnable(params) {
  return http.request({
    url: '/stores/nuclei/enable',
    method: 'get',
    params,
  });
}


// ====================================
//   Risk
// ====================================



//获取 sec_type
export function getSecTypeTableList(params) {
  return http.request({
    url: '/risk/sec_type',
    method: 'get',
    params,
  });
}


//获取 sec_type
export function getStrategyTableList(params) {
  return http.request({
    url: '/risk/strategy',
    method: 'get',
    params,
  });
}



// ====================================
//   PA
// ====================================

//获取 table
export function getPATableList(params) {
  return http.request({
    url: '/risk/pa/list',
    method: 'get',
    params,
  });
}

/**
 * @description: 提交任务
 */
 export function submitPATask(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/pa/submit',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: 查询检测进度与实时结果
 */
export function getPAProgress(params) {
  return http.request({
    url: '/risk/pa/progress',
    method: 'get',
    params,
  });
}




// ====================================
//   Risk Webshell
// ====================================

//获取 table
export function getTableRiskWebshellList(params) {
  return http.request({
    url: '/risk/webshell/list',
    method: 'get',
    params,
  });
}


/**
 * @description: 提交任务
 */
 export function addTableRiskWebshellList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/webshell/submit',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 提交即时任务
 */
 export function addOnceRiskWebshellList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/webshell/submit_once',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 删除项
 */
 export function delTableRiskWebshellList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/webshell/del',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


// ====================================
//   Risk Sqli
// ====================================

//获取 table
export function getTableRiskSqliList(params) {
  return http.request({
    url: '/risk/sqli/list',
    method: 'get',
    params,
  });
}


/**
 * @description: 提交任务
 */
 export function addTableRiskSqliList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/sqli/submit',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 提交即时任务
 */
 export function addOnceRiskSqliList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/sqli/submit_once',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 删除项
 */
 export function delTableRiskSqliList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/sqli/del',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: 统一载荷识别：自动分类 + 各引擎检测
 */
export function riskDetectOnce(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/detect',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

// ====================================
//   HTTP 深度解析
// ====================================

// 获取提示
export function getRiskHttpParseTips(params){
  return http.request<BasicResponseModel>({
    url:'/risk/http_parse/submit',
    method:'POST',
    params,
  },
  {
    isTransformResponse: false,
  });
}

// 合成流量包：将请求/响应合成含 TCP 会话的 pcap 下载
export function genHttpPcap(params){
  return http.request({
    url:'/risk/http_parse/genpcap',
    method:'POST',
    params,
    responseType:'blob',
  },
  {
    isReturnNativeResponse: true,
    isTransformResponse: false,
  });
}

// ====================================
//   Risk XSS
// ====================================

//获取 table
export function getTableRiskXSSList(params) {
  return http.request({
    url: '/risk/xss/list',
    method: 'get',
    params,
  });
}


/**
 * @description: 提交任务
 */
 export function addTableRiskXSSList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/xss/submit',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 提交即时任务
 */
 export function addOnceRiskXSSList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/xss/submit_once',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 删除项
 */
 export function delTableRiskXSSList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/xss/del',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


// ====================================
//   Risk BASH
// ====================================

//获取 table
export function getTableRiskBASHList(params) {
  return http.request({
    url: '/risk/bash/list',
    method: 'get',
    params,
  });
}


/**
 * @description: 提交任务
 */
 export function addTableRiskBASHList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/bash/submit',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 提交即时任务
 */
 export function addOnceRiskBASHList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/bash/submit_once',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: 删除项
 */
 export function delTableRiskBASHList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/risk/bash/del',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


// ====================================
//   Tools Plugin
// ====================================

/**
 * @description: 提交即时任务
 */
 export function addOnceToolsPluginList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/plugin/submit_once',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


// ====================================
//  BlueTeamTools (纯Go实现)
// ====================================

/**
 * @description: 冰蝎流量解密
 */
export function bttBehinderDecrypt(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/btt/behinder',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: 哥斯拉流量解密
 */
export function bttGodzillaDecrypt(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/btt/godzilla',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: Shiro rememberMe 密钥检测
 */
export function bttShiroCheck(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/btt/shiro',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: Log4j2 lookup 解析
 */
export function bttLog4j2Parse(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/btt/log4j2/parse',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: Log4j2 payload 生成
 */
export function bttLog4j2Generate(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/btt/log4j2/gen',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: 获取各蓝队工具示例数据
 */
export function bttSamples() {
  return http.request<BasicResponseModel>(
    {
      url: '/tools/btt/samples',
      method: 'GET',
    },
    {
      isTransformResponse: false,
    }
  );
}

// ====================================
//  Investigation Search
// ====================================

/**
 * @description: search
 */
 export function submitInvestigationSearch(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/search/submit',
      method: 'POST',
      params,
      timeout:60000,
    },
    {
      isTransformResponse: false,
    }
  );
}



/**
 * @description: search add
 */
 export function addSearchTableList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/search/add',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: search get
 */
 export function getSearchTableList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/search/list',
      method: 'GET',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: search save
 */
 export function delSearchTableList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/search/del',
      method: 'GET',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}




// ====================================
//  Fusion Compression
// ====================================

/**
 * @description: search
 */
 export function submitFusionCompression(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/fusion/compression/submit',
      method: 'POST',
      params,
      timeout:60000,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: search
 */
export function submitFusionCompressionByURL(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/fusion/compression/submit_url',
      method: 'POST',
      params,
      timeout:60000,
    },
    {
      isTransformResponse: false,
    }
  );
}



/**
 * @description: search get
 */
 export function getFusionCompression(params) {
  return http.request(
    {
      url: '/fusion/compression/list',
      method: 'GET',
      params,
    }
  );
}



/**
 * @description: search get
 */
export function deleteFusionCompression(params) {
  return http.request(
    {
      url: '/fusion/compression/del',
      method: 'GET',
      params,
    }
  );
}

/**
 * @description: search get
 */
export function getFusionCompressionNames(params) {
  return http.request(
    {
      url: '/fusion/compression/list_names',
      method: 'GET',
      params,
    }
  );
}

/**
 * @description: search get total
 */
export function getFusionCompressionTotal(params) {
  return http.request(
    {
      url: '/fusion/compression/total',
      method: 'GET',
      params,
    }
  );
}

/**
 * @description: search get
 */
 export function getFusionCompressionSignature(params) {
  return http.request(
    {
      url: '/fusion/compression/signature/list',
      method: 'GET',
      params,
    }
  );
}

/**
 * @description: search refrsh
 */
 export function refreshSignatureDetail(params) {
  return http.request(
    {
      url: '/fusion/compression/signature/refresh',
      method: 'GET',
      params,
    }
  );
}


/**
 * @description: search refrsh highlight
 */
export function refreshSignatureHighlight(params) {
  return http.request(
    {
      url: '/fusion/compression/refresh_highlight',
      method: 'POST',
      params,
    }
  );
}


// /**
//  * @description: search refrsh highlight
//  */
// export function refreshSignatureHighlight(params) {
//   return http.request(
//     {
//       url: '/fusion/compression/refresh_highlight',
//       method: 'POST',
//       params,
//     }
//   );
// }



// ====================================
//  Fusion Correlation
// ====================================


/**
 * @description: search refrsh
 */
 export function findFusionCorrelation(params) {
  return http.request(
    {
      url: '/fusion/correlation/find',
      method: 'GET',
      params,
    }
  );
}


// ====================================
//  Hunting
// ====================================

/**
 * @description: hunting get_dir
 */
export function getDirList(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/hunting/get_dir',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: hunting get_file
 */
export function getFile(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/hunting/get_file',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}


/**
 * @description: hunting save_file
 */
export function saveFile(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/hunting/save',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: hunting run_file
 */
export function runFile(params) {
  return http.request<BasicResponseModel>(
    {
      url: '/investigation/hunting/run',
      method: 'POST',
      params,
    },
    {
      isTransformResponse: false,
    }
  );
}