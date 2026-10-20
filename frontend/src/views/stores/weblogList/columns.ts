export const columns = [
  {
    title: 'id',
    key: 'id',
    width: 40,
  },
  {
    title: '名称',
    key: 'name',
    width: 180,
  },
  {
    title: '行数',
    key: 'lines',
    width: 80,
  },
  {
    title: '大小',
    key: 'size',
    width: 90,
    render(row) {
      return (row.size / 1000).toFixed(1) + 'KB';
    },
  },
  {
    title: 'sha-1',
    key: 'sha_1',
    width: 160,
  },
  {
    title: '上传时间',
    key: 'CreatedAt',
    width: 170,
  },
];
