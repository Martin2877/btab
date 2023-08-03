import { RouteRecordRaw } from 'vue-router';
import { Layout } from '@/router/constant';
import { TableOutlined } from '@vicons/antd';
import { renderIcon } from '@/utils/index';

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
    path: '/stores',
    name: 'Stores',
    redirect: '/stores/pcap-list',
    component: Layout,
    meta: {
      title: '威胁仓库',
      icon: renderIcon(TableOutlined),
      sort: 1,
    },
    children: [
      {
        path: 'pcap-list',
        name: 'pcap-list',
        meta: {
          title: '流量包列表',
        },
        component: () => import('@/views/stores/pcapList/index.vue'),
      },
      {
        path: 'payload-list',
        name: 'payload-list',
        meta: {
          title: 'payload列表',
        },
        component: () => import('@/views/stores/payloadList/index.vue'),
      },
      {
        path: 'webshell-list',
        name: 'webshell-list',
        meta: {
          title: 'webshell列表',
        },
        component: () => import('@/views/stores/webshellList/index.vue'),
      },
    ],
  },
];

export default routes;
