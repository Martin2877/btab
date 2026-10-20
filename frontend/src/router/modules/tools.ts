import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { AppstoreAddOutlined } from '@vicons/antd';
import { renderIcon,renderOnline,renderJump } from '@/utils/index';

const IFrame = () => import('@/views/tools/index.vue');

const routes: Array<RouteRecordRaw> = [
  {
    path: '/tools',
    name: 'Tools',
    redirect: '/tools/jq',
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
      {
        path: 'behinder',
        name: 'behinder',
        meta: {
          title: '冰蝎流量解密',
          activeMenu: 'behinder',
          sort: 2,
          tab: 'behinder',
        },
        component: () => import('@/views/tools/btt/index.vue'),
      },
      {
        path: 'godzilla',
        name: 'godzilla',
        meta: {
          title: '哥斯拉流量解密',
          activeMenu: 'godzilla',
          sort: 3,
          tab: 'godzilla',
        },
        component: () => import('@/views/tools/btt/index.vue'),
      },
      {
        path: 'shiro',
        name: 'shiro',
        meta: {
          title: 'Shiro密钥检测',
          activeMenu: 'shiro',
          sort: 4,
          tab: 'shiro',
        },
        component: () => import('@/views/tools/btt/index.vue'),
      },
      {
        path: 'log4j2',
        name: 'log4j2',
        meta: {
          title: 'Log4j2',
          activeMenu: 'log4j2',
          sort: 5,
          tab: 'log4j2',
        },
        component: () => import('@/views/tools/btt/index.vue'),
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
