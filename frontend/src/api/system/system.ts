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
