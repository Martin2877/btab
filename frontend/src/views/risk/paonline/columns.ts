import { h } from 'vue';
import { NTag } from 'naive-ui';
// import { formatDate } from '@/utils/dateUtil'

export const columns = [
  {
    type: 'expand',
    expandable: (rowData) => rowData.result !== '[]',
    renderExpand: (rowData) => {
      return `${rowData.result}`
    }
  },
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
  // {
  //   title: 'uuid',
  //   key: 'uuid',
  //   width: 60,
  // },
  {
    title: '流量包',
    key: 'ForeignPcap.name',
    width: 80,
    render(row) {
      if (row.ForeignPcap != null){
        return row.ForeignPcap.name;
      }
    }
  },
  {
    title: '检测项',
    key: 'item',
    width: 80,
    render(row) {
      var item;
      if (row.ForeignSecType != null && row.ForeignStrategy != null){
        if (row.ForeignSecType.name != "" ){
          item = row.ForeignSecType.name
        }else if (row.ForeignStrategy.name != ""){
          item = row.ForeignStrategy.name
        }
      }
      return item;
    }
  }, 
  {
    title: '检出情况',
    key: 'result',
    width: 80,
  }, 
  {
    title: '检测时间',
    key: 'CreatedAt',
    width: 100,
  },
  {
    title: '状态',
    key: 'state',
    width: 50,
    render(row) {
      var state;
      switch(row.state) { 
        case 0: { 
            state = "空闲";
            break; 
        } 
        case 1: { 
            state = "运行";
            break; 
        } 
        case 2: { 
          state = "暂停";
          break; 
        }
         case 3: {
          state = "停止";
          break; 
        }
        case 4: {
          state = "完成";
          break; 
        }
        default: { 
            state = "空闲";
            break; 
        } 
       } 
      return h(
        NTag,
        {
          type: state,
        },
        {
          default: () => (state),
        }
      );
    },
  },
];


