import { http } from '@/utils/http/axios';

const base = '/analyze';

export const getAnalyzeMethods = () => http.request({ url: `${base}/task/methods`, method: 'get' });

export const submitAnalyzeTask = (params) =>
  http.request({ url: `${base}/task/submit`, method: 'post', params, timeout: 60 * 1000 });

export function submitAnalyzeFile(formData: FormData) {
  return http.request({
    url: `${base}/task/submit`,
    method: 'post',
    params: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 10 * 60 * 1000,
  });
}

export const getAnalyzeTasks = (params) =>
  http.request({ url: `${base}/tasks`, method: 'get', params });

export const getAnalyzeTask = (params) =>
  http.request({ url: `${base}/task`, method: 'get', params });

export const delAnalyzeTask = (params) =>
  http.request({ url: `${base}/task/del`, method: 'post', params });
