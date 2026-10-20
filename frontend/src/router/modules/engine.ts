import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { ApiOutlined } from '@vicons/antd';
import { renderIcon } from '@/utils/index';

const routes: Array<RouteRecordRaw> = [
  {
    path: '/engine',
    name: 'Engine',
    redirect: '/engine/vuln',
    component: Layout,
    meta: {
      title: '检测引擎',
      icon: renderIcon(ApiOutlined),
      sort: 2.5,
      alwaysShow: true,
    },
    children: [
      {
        path: 'vuln',
        name: 'engine-vuln',
        meta: {
          title: '漏洞检测引擎',
        },
        component: () => import('@/views/engine/vuln/index.vue'),
      },
      {
        path: 'logic',
        name: 'engine-logic',
        meta: {
          title: '行为检测引擎',
        },
        component: () => import('@/views/engine/logic/index.vue'),
      },
      {
        path: 'urlrule',
        name: 'engine-urlrule',
        meta: {
          title: 'URL检测引擎',
        },
        component: () => import('@/views/engine/urlrule/index.vue'),
      },
    ],
  },
];

export default routes;
