package routers

import (
	"github.com/Martin2877/blue-team-box/web"
	"github.com/gin-gonic/gin"
	"net/http"
)

// RegisterWebStatick register web static assets route
func RegisterWebStatick(e *gin.Engine) {
	routeWebStatic(e, "/ui/ui", "/index.html", "/favicon.ico", "/logo.png", "/sw.js", "/manifest.json", "/assets/*filepath")
}

func routeWebStatic(e *gin.Engine, paths ...string) {
	staticHandler := http.FileServer(web.NewFileSystem())
	handler := func(c *gin.Context) {
		staticHandler.ServeHTTP(c.Writer, c.Request)
	}
	for _, path := range paths {
		e.GET(path, handler)
		e.HEAD(path, handler)
	}
}
