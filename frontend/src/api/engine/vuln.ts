import { http } from '@/utils/http/axios';

const base = '/engine/vuln';

export const getVulnOverview = () => http.request({ url: `${base}/overview`, method: 'get' });

export const getVulnTemplates = (params) =>
  http.request({ url: `${base}/templates`, method: 'get', params });

export const getVulnTemplateContent = (params) =>
  http.request({ url: `${base}/templates/content`, method: 'get', params });

export function uploadVulnFile(formData: FormData) {
  return http.request({
    url: `${base}/templates/upload`,
    method: 'post',
    params: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 10 * 60 * 1000,
  });
}

export const saveVulnTemplate = (params) =>
  http.request({ url: `${base}/templates/save`, method: 'post', params });

export const validateVulnTemplate = (params) =>
  http.request({ url: `${base}/templates/validate`, method: 'post', params });

export const batchVulnTemplates = (params) =>
  http.request({ url: `${base}/templates/batch`, method: 'post', params });

export const delVulnTemplate = (params) =>
  http.request({ url: `${base}/templates/del`, method: 'get', params });

export const enableVulnTemplate = (params) =>
  http.request({ url: `${base}/templates/enable`, method: 'get', params });

export const getVulnResources = (params) =>
  http.request({ url: `${base}/resources`, method: 'get', params });

export const getVulnResourceContent = (params) =>
  http.request({ url: `${base}/resources/content`, method: 'get', params });

export const delVulnResource = (params) =>
  http.request({ url: `${base}/resources/del`, method: 'get', params });

export const getVulnSettings = () => http.request({ url: `${base}/settings`, method: 'get' });

export const saveVulnSettings = (params) =>
  http.request({ url: `${base}/settings`, method: 'post', params });

export const debugVuln = (params) =>
  http.request({ url: `${base}/debug`, method: 'post', params });
