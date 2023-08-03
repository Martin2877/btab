import { h } from 'vue';
import { NTag } from 'naive-ui';

export const columns = [
  {
    type: 'expand',
    expandable: (rowData) => rowData.code !== '',
    renderExpand: (rowData) => {
      return `${rowData.code}`
    }
  },
  {
    title: 'id',
    key: 'id',
    width: 30,
  },
  {
    title: 'webshell',
    key: 'name',
    width: 80,
    render(row) {
      if (row.ForeignWebshell != null){
        return row.ForeignWebshell.name;
      }
    }
  },
  {
    title: '检出情况',
    key: 'result',
    width: 80,
  }, 
  {
    title: '去混淆代码',
    key: 'code',
    width: 80,
  }, 
  {
    title: '调用链',
    key: 'chain',
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

