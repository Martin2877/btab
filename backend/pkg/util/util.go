package util

import (
	"crypto/tls"
	conf2 "github.com/Martin2877/blue-team-box/pkg/conf"
	log "github.com/Martin2877/blue-team-box/pkg/logging"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

func Setup() {
	// fasthttp client 初始化
	DownProxy := conf2.GlobalConfig.HttpConfig.Proxy
	client := &fasthttp.Client{
		// If InsecureSkipVerify is true, TLS accepts any certificate
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		NoDefaultUserAgentHeader: true,
		DisablePathNormalizing:   true,
	}
	if DownProxy != "" {
		log.Info("[fasthttp client use proxy ]", DownProxy)
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(DownProxy)
	}

	// jwt secret 初始化
	jwtSecret = []byte(conf2.GlobalConfig.ServerConfig.JwtSecret)
}