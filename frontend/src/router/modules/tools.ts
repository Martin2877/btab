import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { AppstoreAddOutlined } from '@vicons/antd';
import { renderIcon,renderOnline,renderJump } from '@/utils/index';

const IFrame = () => import('@/views/tools/index.vue');

const routes: Array<RouteRecordRaw> = [
  {
    path: '/tools',
    name: 'Tools',
    redirect: '/tools/cyberchef',
    component: Layout,
    meta: {
      title: '辅助工具',
      sort: 3,
      icon: renderIcon(AppstoreAddOutlined),
    },
    children: [
      // {
      //   path: 'tshark',
      //   name: 'tshark',
      //   meta: {
      //     title: 'tshark',
      //     activeMenu: 'tshark',
      //     sort: -1,
      //   },
      //   component: () => import('@/views/tools/tshark/index.vue'),
      // },
      {
        path: 'jq',
        name: 'jq',
        meta: {
          title: 'jq',
          activeMenu: 'jq',
          sort: 0,
        },
        component: () => import('@/views/tools/jq/index.vue'),
      },
      {
        path: 'SerializationDumper',
        name: 'SerializationDumper',
        meta: {
          title: 'SerializationDumper',
          activeMenu: 'SerializationDumper',
          sort: 1,
        },
        component: () => import('@/views/tools/SerializationDumper/index.vue'),
      },
      // {
      //   path: '/BlueTeamTools',
      //   name: 'BlueTeamTools',
      //   meta: {
      //     title: 'BlueTeamTools(ABC_123)',
      //     extra: renderJump(),
      //     sort: 2,
      //   },
      //   component: IFrame,
      // },
      // {
      //   path: 'cyberchef',
      //   name: 'frame-cyberchef',
      //   meta: {
      //     title: 'CyberChef',
      //     sort: 3,
      //     // frameSrc: 'https://gchq.github.io/CyberChef/',
      //     frameSrc: '/ui/assets/cyberchef/index.html',
      //   },
      //   component: IFrame,
      // },
      // {
      //   path: '/regex101',
      //   name: 'https://regex101.com/',
      //   meta: {
      //     title: 'Regex101',
      //     extra: renderJump(),
      //     sort: 8,
      //   },
      //   component: IFrame,
      // },
      // {
      //   path: 'sandbox-freebuf',
      //   name: 'frame-sandbox-freebuf',
      //   meta: {
      //     title: '大圣云沙箱',
      //     extra: renderOnline(),
      //     frameSrc: 'https://sandbox.freebuf.com/detect',
      //   },
      //   component: IFrame,
      // },
    ],
  },
];

export default routes;
