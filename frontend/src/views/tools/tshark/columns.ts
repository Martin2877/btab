import { h } from 'vue';
import { NTag } from 'naive-ui';


export const columns = [
  {
    title: 'id',
    key: 'id',
    width: 30,
  },
  {
    title: '文件名称',
    key: 'name',
    width: 40,
    render(row) {
      if (row.ForeignPayload != null){
        return row.ForeignPayload.name;
      }
    }
  },
  // {
  //   title: '结果',
  //   key: 'risk',
  //   width: 80,
  //   render(row) {
  //     var risk;
  //     switch(row.found) { 

  //     }
  //   }
  // }, 
  {
    title: '详情',
    key: 'result',
    width: 100,
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


