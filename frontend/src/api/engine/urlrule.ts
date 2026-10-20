import { http } from '@/utils/http/axios';

const base = '/engine/urlrule';

export const getUrlRuleOverview = () =>
  http.request({ url: `${base}/overview`, method: 'get' });

export const getUrlRuleList = (params) =>
  http.request({ url: `${base}/rules`, method: 'get', params });

export const getUrlRuleDetail = (params) =>
  http.request({ url: `${base}/rules/content`, method: 'get', params });

export const saveUrlRule = (params) =>
  http.request({ url: `${base}/rules/save`, method: 'post', params });

export const validateUrlRule = (params) =>
  http.request({ url: `${base}/rules/validate`, method: 'post', params });

export const enableUrlRule = (params) =>
  http.request({ url: `${base}/rules/enable`, method: 'post', params });

export const batchUrlRule = (params) =>
  http.request({ url: `${base}/rules/batch`, method: 'post', params });

export const delUrlRule = (params) =>
  http.request({ url: `${base}/rules/del`, method: 'get', params });

export function uploadUrlRuleYaml(formData: FormData) {
  return http.request({
    url: `${base}/rules/upload`,
    method: 'post',
    params: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
  });
}

export const debugUrlRule = (params) =>
  http.request({ url: `${base}/debug`, method: 'post', params });
