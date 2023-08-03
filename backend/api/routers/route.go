package routers

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/api/middleware/license"
	"github.com/Martin2877/blue-team-box/api/routers/v2/risk"
	"github.com/Martin2877/blue-team-box/api/routers/v2/system"
	"net/http"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	riskbash "github.com/Martin2877/blue-team-box/api/routers/v2/risk/bash"
	"github.com/Martin2877/blue-team-box/api/routers/v2/risk/http_parse"
	"github.com/Martin2877/blue-team-box/api/routers/v2/risk/pcapanalyse"
	risksqli "github.com/Martin2877/blue-team-box/api/routers/v2/risk/sqli"
	riskwebshell "github.com/Martin2877/blue-team-box/api/routers/v2/risk/webshell"
	riskxss "github.com/Martin2877/blue-team-box/api/routers/v2/risk/xss"
	"github.com/Martin2877/blue-team-box/api/routers/v2/tools/plugin"
	utils "github.com/Martin2877/blue-team-box/pkg/util"

	"github.com/Martin2877/blue-team-box/api/routers/v2/stores/payload"
	"github.com/Martin2877/blue-team-box/api/routers/v2/stores/pcap"
	"github.com/Martin2877/blue-team-box/api/routers/v2/stores/webshell"
	//_ "github.com/Martin2877/blue-team-box/docs" // docs is generated by Swag CLI, you have to import it.
	"github.com/Martin2877/blue-team-box/pkg/conf"
	log "github.com/Martin2877/blue-team-box/pkg/logging"
	"github.com/gin-gonic/gin"

	gs "github.com/swaggo/gin-swagger"

	"github.com/pkg/browser"
	swaggerFiles "github.com/swaggo/files"
)

func Setup() {
	// gin 的【运行模式】运行时就已经确定 无法做到热加载
	gin.SetMode(conf.GlobalConfig.ServerConfig.RunMode)
}

func InitRouter(port string) {
	router := gin.Default()

	// debug 模式下 开启 swagger
	if conf.GlobalConfig.ServerConfig.RunMode == "debug" {
		router.GET("/swagger/*any", gs.WrapHandler(swaggerFiles.Handler))
	}

	// ui
	router.Use(func(c *gin.Context) {
		if strings.Contains(c.Request.RequestURI, ".js") {
			fmt.Println(c.Request.RequestURI)
			c.Writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		}
	})

	router.StaticFS("/ui", BinaryFileSystem("web/dist"))
	//RegisterWebStatick(router)

	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, "/ui")
	})

	router.GET("/__vite_ping", func(c *gin.Context) {
		msg.ResultSuccess(c, "")
	})

	router.GET("/assets/:file", func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("/ui/%s", c.Request.RequestURI))
	})
	router.GET("/:file", func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("/ui/%s", c.Request.RequestURI))
	})

	router.Any("/api/login", func(c *gin.Context) {
		var newValues = make(map[string]interface{})
		newValues["token"] = utils.RandStr(32)
		msg.ResultSuccess(c, newValues)
		return
	})

	//v2 := router.Group("/api/v2")
	v2 := router.Group("/api")
	v2.Use(license.License())
	{
		// 认证功能
		v2.GET("/admin_info", func(c *gin.Context) {
			//t := c.Params.ByName("_t")
			//fmt.Println(t)
			msg.ResultSuccess(c, Admininfo)
		})
		// 获取认证有效日期
		LicenseRoutes := v2.Group("/license")
		{
			LicenseRoutes.GET("/dateline", license.GetDateLine)
		}

		// 系统相关内容
		SystemRoutes := v2.Group("/system")
		{
			SystemRoutes.GET("/version", system.GetVersion)
		}

		// 威胁仓库
		ListRoutes := v2.Group("/stores")
		PCAPListRoutes := ListRoutes.Group("/pcap")
		{
			PCAPListRoutes.POST("/upload", pcap.Upload)
			PCAPListRoutes.GET("/dir", pcap.GetDir)
			PCAPListRoutes.GET("/list", pcap.Get)
			PCAPListRoutes.GET("/del", pcap.Delete)
		}

		PayloadListRoutes := ListRoutes.Group("/payload")
		{
			PayloadListRoutes.POST("/upload", payload.Upload)
			PayloadListRoutes.GET("/dir", payload.GetDir)
			PayloadListRoutes.GET("/list", payload.Get)
			PayloadListRoutes.GET("/del", payload.Delete)
			PayloadListRoutes.GET("/detail", payload.Detail)
		}

		WebshellListRoutes := ListRoutes.Group("/webshell")
		{
			WebshellListRoutes.POST("/upload", webshell.Upload)
			WebshellListRoutes.GET("/dir", webshell.GetDir)
			WebshellListRoutes.GET("/list", webshell.Get)
			WebshellListRoutes.GET("/del", webshell.Delete)
			WebshellListRoutes.GET("/detail", webshell.Detail)
		}

		// 风险检测
		RiskRoutes := v2.Group("/risk")
		{
			RiskRoutes.GET("/sec_type", risk.GetSecType)  // 获取列表
			RiskRoutes.GET("/strategy", risk.GetStrategy) // 获取策略列表
		}

		PARiskRoutes := RiskRoutes.Group("/pa")
		{
			PARiskRoutes.POST("/submit", pcapanalyse.Submit) // 提交任务 返回唯一ID
			PARiskRoutes.GET("/list", pcapanalyse.Get)
			PARiskRoutes.POST("/del", pcapanalyse.Delete)
		}

		WebshellRiskRoutes := RiskRoutes.Group("/webshell")
		{
			WebshellRiskRoutes.POST("/submit", riskwebshell.Submit)          // 提交任务 返回唯一ID
			WebshellRiskRoutes.POST("/submit_once", riskwebshell.SubmitOnce) // 提交任务 返回唯一ID
			WebshellRiskRoutes.GET("/list", riskwebshell.Get)
			WebshellRiskRoutes.POST("/del", riskwebshell.Delete)
		}

		SqliRiskRoutes := RiskRoutes.Group("/sqli")
		{
			SqliRiskRoutes.POST("/submit", risksqli.Submit)          // 提交任务 返回唯一ID
			SqliRiskRoutes.POST("/submit_once", risksqli.SubmitOnce) // 提交任务 返回唯一ID
			SqliRiskRoutes.GET("/list", risksqli.Get)
			SqliRiskRoutes.POST("/del", risksqli.Delete)
		}

		Http_ParseRoutes := RiskRoutes.Group("/http_parse")
		{
			Http_ParseRoutes.POST("/submit", http_parse.Get_Tips) //获取请求和响应特征
		}

		XSSRiskRoutes := RiskRoutes.Group("/xss")
		{
			XSSRiskRoutes.POST("/submit", riskxss.Submit)          // 提交任务 返回唯一ID
			XSSRiskRoutes.POST("/submit_once", riskxss.SubmitOnce) // 提交任务 返回唯一ID
			XSSRiskRoutes.GET("/list", riskxss.Get)
			XSSRiskRoutes.POST("/del", riskxss.Delete)
		}

		BashRiskRoutes := RiskRoutes.Group("/bash")
		{
			BashRiskRoutes.POST("/submit", riskbash.Submit)          // 提交任务 返回唯一ID
			BashRiskRoutes.POST("/submit_once", riskbash.SubmitOnce) // 提交任务 返回唯一ID
			BashRiskRoutes.GET("/list", riskbash.Get)
			BashRiskRoutes.POST("/del", riskbash.Delete)
		}

		// 辅助工具
		ToolsRoutes := v2.Group("/tools")
		SerializationDumperToolsRoutes := ToolsRoutes.Group("/plugin")
		{
			SerializationDumperToolsRoutes.POST("/submit_once", plugin.SubmitOnce) // 提交任务 返回唯一ID
		}

	}

	// 浏览器打开

	var err error

	address := "http://localhost" + ":" + port

	if conf.GlobalConfig.ServerConfig.OpenBrowser {
		err = browser.OpenURL(address)
		if err != nil {
			log.Error("浏览器打开失败：", err)
		}
	}

	fmt.Println("server start at port:", port)
	fmt.Println("查看 web 可通过访问：", address)
	err = router.Run(":" + port)
	if err != nil {
		log.Panic("服务启动失败：", err)
		return
	}
}