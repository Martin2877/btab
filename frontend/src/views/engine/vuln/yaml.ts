export function highlightYaml(src: string): string {
  const esc = (x: string) => x.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return src
    .split('\n')
    .map((line) => {
      let l = esc(line);
      if (/^\s*#/.test(line)) return `<span class="yk-c">${l}</span>`;
      l = l.replace(/^(\s*-?\s*)([\w.-]+)(\s*:)/, '$1<span class="yk-k">$2</span>$3');
      l = l.replace(/(\{\{[^}]+\}\})/g, '<span class="yk-t">$1</span>');
      return l;
    })
    .join('\n');
}

export function sevType(s: string) {
  const m: Record<string, string> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'success',
    info: 'info',
  };
  return (m[(s || '').toLowerCase()] || 'default') as any;
}

export const severityOptions = ['critical', 'high', 'medium', 'low', 'info'].map((v) => ({
  label: v,
  value: v,
}));
