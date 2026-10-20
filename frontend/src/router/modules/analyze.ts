import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { ThunderboltOutlined } from '@vicons/antd';
import { renderIcon } from '@/utils/index';

const routes: Array<RouteRecordRaw> = [
  {
    path: '/analyze',
    name: 'Analyze',
    redirect: '/analyze/home',
    component: Layout,
    meta: {
      title: '一键分析',
      icon: renderIcon(ThunderboltOutlined),
      sort: 0,
      alwaysShow: true,
    },
    children: [
      {
        path: 'home',
        name: 'analyze-home',
        meta: {
          title: '统一分析入口',
        },
        component: () => import('@/views/analyze/index.vue'),
      },
      {
        path: 'tasks',
        name: 'analyze-tasks',
        meta: {
          title: '分析任务',
        },
        component: () => import('@/views/analyze/tasks.vue'),
      },
      {
        path: 'report',
        name: 'analyze-report',
        meta: {
          title: '分析报告',
          hidden: true,
          activeMenu: 'analyze-tasks',
        },
        component: () => import('@/views/analyze/report.vue'),
      },
    ],
  },
];

export default routes;
