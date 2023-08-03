
export const columns = [
  {
    title: 'id',
    key: 'id',
    width: 30,
  },
  {
    title: '名称',
    key: 'name',
    width: 100,
  },
  // {
  //   title: '描述',
  //   key: 'description',
  //   width: 100,
  // },
  {
    title: 'sha-1',
    key: 'sha_1',
    width: 150,
  },
  {
    title: '大小',
    key: 'size',
    width: 100,
    render(row) {
      return (row.size / 1000).toFixed(1) + "KB";
    }
  },
  {
    title: '上传时间',
    key: 'CreatedAt',
    width: 150,
  },
];
