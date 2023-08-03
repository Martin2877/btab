package util

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// SetupCloseHandler 在一个新的 goroutine 上创建一个监听器。
// 如果接收到了一个 interrupt 信号，就会立即通知程序，做一些清理工作并退出
func SetupCloseHandler() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		os.Exit(0)
	}()
}
