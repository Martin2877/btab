import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { DesktopOutline } from '@vicons/ionicons5';
import { renderIcon } from '@/utils/index';

const IFrame = () => import('@/views/iframe/index.vue');

const routes: Array<RouteRecordRaw> = [
  // {
  //   path: '/frame',
  //   name: 'Frame',
  //   redirect: '/frame/docs',
  //   component: Layout,
  //   meta: {
  //     title: '外部页面',
  //     sort: 8,
  //     icon: renderIcon(DesktopOutline),
  //   },
  //   children: [
  //     {
  //       path: 'naive-admin',
  //       name: 'naive-admin',
  //       meta: {
  //         title: 'NaiveAdmin',
  //         frameSrc: 'https://www.naiveadmin.com',
  //       },
  //       component: IFrame,
  //     },
  //     {
  //       path: 'docs',
  //       name: 'frame-docs',
  //       meta: {
  //         title: '项目文档(内嵌)',
  //         frameSrc: 'https://10.0.95.98/',
  //       },
  //       component: IFrame,
  //     },
  //     {
  //       path: 'regex',
  //       name: 'frame-regex',
  //       meta: {
  //         title: '正则1(内嵌)',
  //         frameSrc: 'https://regex101.com/',
  //       },
  //       component: IFrame,
  //     },
  //     {
  //       path: 'decode',
  //       name: 'frame-decode',
  //       meta: {
  //         title: '转码(内嵌)',
  //         frameSrc: 'https://gchq.github.io/CyberChef/',
  //       },
  //       component: IFrame,
  //     },
  //     {
  //       path: 'naive',
  //       name: 'frame-naive',
  //       meta: {
  //         title: 'NaiveUi(内嵌)',
  //         frameSrc: 'https://www.naiveui.com',
  //       },
  //       component: IFrame,
  //     },
  //   ],
  // },
];

export default routes;
