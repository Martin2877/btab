package sqli

import "testing"

func TestCheckSignatures(t *testing.T) {
	hits := []string{
		// libinjection 词法
		`' or 1=1--`,
		`admin' and '1'='1`,
		// 结构签名
		`exec master..xp_cmdshell 'ipconfig /all'`,
		`'; exec master..xp_cmdshell 'dir' --`,
		`select @@version`,
		`1;SELECT *`,
		`' union (select @@version) --`,
		`or benchmark(10000000,MD5(1))`,
		`waitfor delay '0:0:10'`,
		`1' and sleep(5)--`,
		`and 1=(select count(*) from information_schema.tables)`,
		`declare @q nvarchar(200) exec(@q)`,
		`';drop table users--`,
		`'||UTL_HTTP.REQUEST('x')||'`,
		`or 2 > 1`,
		`or 'text' > 't'`,
		`) or (a=a`,
		`'sqlattempt1`,
		`1'`,
		// 归一化：URL 编码
		`%27%20or%201=1`,
		`1;SELECT%20*`,
		// 归一化：/**/ 注释混淆（分割与拼接两种）
		`uni/**/on sel/**/ect`,
		`/**/or/**/1/**/=/**/1`,
		// 归一化：0x hex（含 UTF-16LE）
		`0x77616974666F722064656C61792027303A303A313027`,
		`0x770061006900740066006F0072002000640065006C0061007900`,
		// 归一化：\xHH
		`\x27UNION SELECT 1`,
	}
	for _, s := range hits {
		if ok, d := Check(s); !ok {
			t.Errorf("应命中未命中: %q", s)
		} else {
			t.Logf("%q -> %s", s, d)
		}
	}
}

func TestCheckBenign(t *testing.T) {
	benign := []string{
		`admin`,
		`hello world`,
		`select the best option`,
		`please update your profile`,
		`order by date`,
		`work or play`,
		`<html><body>welcome user</body></html>`,
		`{"name":"test","value":123}`,
		`path/to/file.txt`,
		`user@example.com`,
	}
	for _, s := range benign {
		if ok, d := Check(s); ok {
			t.Errorf("误报: %q -> %s", s, d)
		}
	}
}
