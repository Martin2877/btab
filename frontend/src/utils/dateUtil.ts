import { format } from 'date-fns';

const DATE_TIME_FORMAT = 'yyyy-MM-dd hh:mm';
const DATE_FORMAT = 'YYYY-MM-dd ';
const DATE_TIME_FORMAT2 = 'yyyy-MM-dd hh:mm:ss';

export function formatToDateTime(date, formatStr = DATE_TIME_FORMAT): string {
  return format(date, formatStr);
}

export function formatToDate(date, formatStr = DATE_FORMAT): string {
  return format(date, formatStr);
}



function padLeftZero (str) {
  return ('00' + str).substr(str.length);
};


export function formatDate (date, fmt = DATE_TIME_FORMAT2): string {
  if (/(y+)/.test(fmt)) {
    fmt = fmt.replace(RegExp.$1, (date.getFullYear() + '').substr(4 - RegExp.$1.length));
  }
  let o = {
    'M+': date.getMonth() + 1,
    'd+': date.getDate(),
    'h+': date.getHours(),
    'm+': date.getMinutes(),
    's+': date.getSeconds()
  };
  for (let k in o) {
    if (new RegExp(`(${k})`).test(fmt)) {
      let str = o[k] + '';
      fmt = fmt.replace(RegExp.$1, (RegExp.$1.length === 1) ? str : padLeftZero(str));
    }
  }
  return fmt;
};

