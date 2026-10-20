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

/**
 * @description: 获取系统版本
 */
export function getSystemVersion() {
  return http.request({
    url: '/system/version',
    method: 'get',
  });
}

/**
 * @description: 获取认证日期
 */
export function getLicenseDateline() {
    return http.request({
      url: '/license/dateline',
      method: 'get',
    });
  }

/**
 * @description: 获取系统配置（含 tshark 探测状态）
 */
export function getSystemConfig() {
  return http.request({
    url: '/system/config',
    method: 'get',
  });
}

/**
 * @description: 在线更新系统配置，body 为 { "yaml路径": 值 }
 */
export function updateSystemConfig(data) {
  return http.request<BasicResponseModel>(
    {
      url: '/system/config',
      method: 'post',
      data,
    },
    {
      isTransformResponse: false,
    }
  );
}

/**
 * @description: 探测 tshark 可用性与候选路径
 */
export function getTsharkStatus() {
  return http.request({
    url: '/system/tshark',
    method: 'get',
  });
}
