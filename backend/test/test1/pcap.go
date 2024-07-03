package main

import (
	"bytes"
	"fmt"
	"log"

	"os/exec"
)

func main() {
	f := "1.cap"
	tsharkPath := "F:\\1_program\\60_wireshark\\Wireshark\\tshark.exe"
	args := []string{"-r", f, "-T", "json"}

	cmd := exec.Command(tsharkPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // 标准输出
	cmd.Stderr = &stderr // 标准错误
	err := cmd.Run()
	outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
	fmt.Printf("out:\n%s\nerr:\n%s\n", outStr, errStr)
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}
