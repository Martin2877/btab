import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { SecurityScanOutlined } from '@vicons/antd';
import { renderIcon,renderOnline } from '@/utils/index';

/**
 * @param name 路由名称, 必须设置,且不能重名
 * @param meta 路由元信息（路由附带扩展信息）
 * @param redirect 重定向地址, 访问这个路由时,自定进行重定向
 * @param meta.disabled 禁用整个菜单
 * @param meta.title 菜单名称
 * @param meta.icon 菜单图标
 * @param meta.keepAlive 缓存该路由
 * @param meta.sort 排序越小越排前
 *
 * */
const routes: Array<RouteRecordRaw> = [
  {
    path: '/risk',
    name: 'Risk',
    redirect: '/risk/paonline',
    component: Layout,
    meta: {
      title: '风险检测',
      icon: renderIcon(SecurityScanOutlined),
      sort: 2,
    },
    children: [
      {
        path: 'paonline',
        name: 'paonline',
        meta: {
          title: '流量包检测',
        },
        component: () => import('@/views/risk/paonline/index.vue'),
      },
      {
        path: 'http_parse',
        name: 'http_parse',
        meta: {
          title: 'HTTP深度解析',
        },
        component: () => import('@/views/risk/http_parse/index.vue'),
      },
      // {
      //   path: 'paonline-info/:id?',
      //   name: 'paonline-info',
      //   meta: {
      //     title: '风险详情',
      //     hidden: true,
      //     activeMenu: 'paonline',
      //   },
      //   component: () => import('@/views/risk/paonline/info.vue'),
      // },
      {
        path: 'sqli',
        name: 'sqli',
        meta: {
          title: 'SQLi检测',
        },
        component: () => import('@/views/risk/sqli/index.vue'),
      },
      {
        path: 'xss',
        name: 'xss',
        meta: {
          title: 'XSS检测',
        },
        component: () => import('@/views/risk/xss/index.vue'),
      },
      {
        path: 'webshell',
        name: 'webshell',
        meta: {
          title: 'Webshell检测',
          // extra: renderOnline(),
        },
        component: () => import('@/views/risk/webshell/index.vue'),
      },
      {
        path: 'bash',
        name: 'bash',
        meta: {
          title: 'bash命令检测',
          extra: renderOnline(),
        },
        component: () => import('@/views/risk/bash/index.vue'),
      },
    ],
  },
];

export default routes;
