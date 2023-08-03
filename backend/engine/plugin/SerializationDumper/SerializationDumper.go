package SerializationDumper

import (
	"bytes"
	"errors"
	"github.com/Martin2877/blue-team-box/lib"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"log"
	"os/exec"
	"runtime"
)

type SerializationDumper struct {
	State       int    `json:"state"`        // 任务进度
	FinalStatus int    `json:"final_status"` // 执行结果
	Content     string `json:"content"`
	Result      string `json:"result"`
}

func (plugin *SerializationDumper) Init() {
	plugin.State = db.StateFree
}

func (plugin *SerializationDumper) Set(key string, value interface{}) {
	switch key {
	case "content":
		plugin.Content = value.(string)
	}
}

func (plugin *SerializationDumper) Check() error {
	if plugin.Content == "" {
		return errors.New("参数检查不通过, content 为空")
	}
	return nil
}

func (plugin *SerializationDumper) Exec() error {
	var err error
	var runner string
	plugin.State = db.StateRunning
	if runtime.GOOS == "windows" {
		// windows系统
		//runner = path.Join(file.GetCurrentAbPathByExecutable(),"lib","javaw.exe")
		runner = "java"
	} else {
		// LINUX系统
		runner = "java"
	}
	library := lib.Library{}
	jar, err := library.GetSerializationDumperJar()
	if err != nil {
		return err
	}
	//fmt.Println("执行命令：", runner, "-jar", jar, plugin.Content)
	cmd := exec.Command(runner, "-jar", jar, plugin.Content)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		log.Fatalf("failed to call Run(): %v", err)
		return err
	}
	library.Cleanup()
	plugin.State = db.StateFinish
	plugin.FinalStatus = db.FinalStatusSuccess
	plugin.Result = stdout.String()
	return nil
}

func (plugin *SerializationDumper) GetState() int {
	return plugin.State
}

func (plugin *SerializationDumper) GetFinalStatus() int {
	return plugin.FinalStatus
}

func (plugin *SerializationDumper) GetResult() string {
	return plugin.Result
}
