import { http } from '@/utils/http/axios';

const base = '/engine/logic';

export const getLogicOverview = () => http.request({ url: `${base}/overview`, method: 'get' });

export const getLogicScripts = (params) =>
  http.request({ url: `${base}/scripts`, method: 'get', params });

export const getLogicScriptContent = (params) =>
  http.request({ url: `${base}/scripts/content`, method: 'get', params });

export function uploadLogicFile(formData: FormData) {
  return http.request({
    url: `${base}/scripts/upload`,
    method: 'post',
    params: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60 * 1000,
  });
}

export const saveLogicScript = (params) =>
  http.request({ url: `${base}/scripts/save`, method: 'post', params });

export const validateLogicScript = (params) =>
  http.request({ url: `${base}/scripts/validate`, method: 'post', params });

export const delLogicScript = (params) =>
  http.request({ url: `${base}/scripts/del`, method: 'get', params });

export const setLogicScriptEnabled = (params: { id: string; enable: boolean }) =>
  http.request({ url: `${base}/scripts/enable`, method: 'post', params });

export const debugLogic = (params) =>
  http.request({ url: `${base}/debug`, method: 'post', params, timeout: 10 * 60 * 1000 });

export function debugLogicUpload(formData: FormData) {
  return http.request({
    url: `${base}/debug`,
    method: 'post',
    params: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 10 * 60 * 1000,
  });
}
