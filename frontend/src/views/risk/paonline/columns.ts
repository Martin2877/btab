import { h } from 'vue';
import { NTag, NSpace, NIcon } from 'naive-ui';
import { LoadingOutlined } from '@vicons/antd';
import { formatDate } from '@/utils/dateUtil';

// 任务状态
export const PA_STATE = {
  0: { text: '空闲', type: 'default' },
  1: { text: '检测中', type: 'info' },
  2: { text: '暂停', type: 'warning' },
  3: { text: '停止', type: 'warning' },
  4: { text: '完成', type: 'success' },
  5: { text: '失败', type: 'error' },
};

// 事件中的失败占位名称（后端聚合错误时使用）
export const ERR_EVENT_NAMES = ['策略执行失败', '检测失败'];

export function parseResultEvents(row): any[] {
  try {
    const evs = JSON.parse(row.result || '[]');
    return Array.isArray(evs) ? evs : [];
  } catch (e) {
    return [];
  }
}

// 事件是否为错误占位（非真实检出）
export function isErrEvent(ev): boolean {
  return !ev || ERR_EVENT_NAMES.includes(ev.name) || !!ev.error;
}

export const columns = [
  {
    title: 'id',
    key: 'id',
    width: 30,
  },
  {
    title: '任务名称',
    key: 'name',
    width: 60,
  },
  {
    title: '流量包',
    key: 'ForeignPcap.name',
    width: 80,
    render(row) {
      if (row.ForeignPcap != null) {
        return row.ForeignPcap.name;
      }
      return '-';
    },
  },
  {
    title: '检测项',
    key: 'item',
    width: 110,
    ellipsis: { tooltip: true },
    render(row) {
      if (row.ForeignStrategy != null && row.ForeignStrategy.name) {
        return row.ForeignStrategy.name;
      }
      if (row.ForeignSecType != null && row.ForeignSecType.name) {
        return row.ForeignSecType.name;
      }
      // 多策略任务：description 保存了全部策略名；为空表示未指定策略（即全部策略）
      return row.description || '全部策略';
    },
  },
  {
    title: '检出情况',
    key: 'result',
    width: 90,
    render(row) {
      if (row.state === 1) {
        return h(
          NTag,
          { type: 'info', size: 'small' },
          {
            default: () => '检测中',
            icon: () => h(NIcon, null, { default: () => h(LoadingOutlined) }),
          }
        );
      }
      const evs = parseResultEvents(row);
      const hits = evs.filter((e) => !isErrEvent(e)).length;
      const fails = evs.length - hits;
      const tags = [];
      if (hits > 0) {
        tags.push(
          h(NTag, { type: 'error', size: 'small' }, { default: () => `检出 ${hits}` })
        );
      } else {
        tags.push(
          h(NTag, { type: 'success', size: 'small' }, { default: () => '未检出' })
        );
      }
      if (fails > 0) {
        tags.push(
          h(NTag, { type: 'warning', size: 'small' }, { default: () => `${fails} 项异常` })
        );
      }
      return h(NSpace, { size: 4 }, { default: () => tags });
    },
  },
  {
    title: '检测时间',
    key: 'CreatedAt',
    width: 110,
    render(row) {
      if (!row.CreatedAt) return '-';
      return formatDate(new Date(row.CreatedAt));
    },
  },
  {
    title: '状态',
    key: 'state',
    width: 60,
    render(row) {
      const st = PA_STATE[row.state] || PA_STATE[0];
      return h(
        NTag,
        { type: st.type, size: 'small' },
        { default: () => st.text }
      );
    },
  },
];
