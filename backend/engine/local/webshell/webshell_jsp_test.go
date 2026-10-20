package webshell

import "testing"

// JSP 声明块 + Servlet API + Runtime.exec：<%! 包裹的 Java 代码
// 不得被 <% 回退误判为 ASP，需识别为 jsp 并命中 jsp.runtime.exec 检出
const jspWebshellSample = `<%
    g(request,"a");
%>
<%!
    static String g(HttpServletRequest request,String a)throws Exception{
        B b = new B(request);
        Runtime.getRuntime().exec(b.g());
        return null;
    }
    static class B{
        HttpServletRequest r;
        B(HttpServletRequest r){ this.r=r; }
        String g(){ return r.getParameter("x"); }
    }
%>`

func TestCheckJspDeclaration(t *testing.T) {
	res := Check([]byte(jspWebshellSample))
	if res.Lang != "jsp" {
		t.Fatalf("语言识别错误: got %q, want jsp", res.Lang)
	}
	if !res.Webshell {
		t.Fatalf("JSP webshell 未检出: score=%d hits=%v", res.Score, res.Hits)
	}
	t.Logf("score=%d hits=%v", res.Score, res.Hits)
}

// ASP/VBScript 用 <% 包裹时仍应识别为 asp，不受 JSP 特征影响
func TestDetectLangAspNotJsp(t *testing.T) {
	asp := `<% Response.Write(Request.QueryString("x")) %>`
	if lang := detectLang([]byte(asp)); lang != "asp" {
		t.Fatalf("语言识别错误: got %q, want asp", lang)
	}
}

// 纯 Java 文件（无 <% 包裹）不进入 jsp 语言规则
func TestDetectLangPlainJava(t *testing.T) {
	java := `class Foo { void bar(HttpServletRequest r) { Runtime.getRuntime().exec("id"); } }`
	if lang := detectLang([]byte(java)); lang == "jsp" {
		t.Fatalf("纯 Java 文件不应识别为 jsp")
	}
}
