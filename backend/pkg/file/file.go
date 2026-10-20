package file

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ReadingLines Reading file and return content as []string
func ReadingLines(filename string) []string {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	return SplitLines(data)
}

// SplitLines 按行拆分字节内容，跳过空行（与 ReadingLines 行为一致）
func SplitLines(data []byte) []string {
	var result []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// 单行最长支持 10MB，避免大 payload 被默认 64KB 截断
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		val := scanner.Text()
		if val == "" {
			continue
		}
		result = append(result, val)
	}
	return result
}

// GzipBytes gzip 压缩字节内容，用于将文件内容存入数据库 BLOB
func GzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GunzipBytes 解压 gzip 字节内容
func GunzipBytes(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func UploadTargetsPath(extstring string) string {
	// 生成文件名
	fileNameInt := time.Now().Unix()
	fileNameStr := strconv.FormatInt(fileNameInt, 10)
	fileName := fileNameStr + extstring
	// 格式化当前时间
	folderName := time.Now().Format("2006/01/02")
	folderPath := filepath.Join("upload", folderName)
	// 创建多层级目录
	os.MkdirAll(folderPath, os.ModePerm)

	filePath := filepath.Join(folderPath, fileName)
	return filePath
}

// 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// GetCurrentAbPathByExecutable 获取当前执行程序所在的绝对路径
func GetCurrentAbPathByExecutable() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
	return res
}

func FindFile(root string, name string) (bingo string) {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if err != nil {

			fmt.Println(err)
			return nil
		}

		if !info.IsDir() && filepath.Base(path) == name {
			bingo = path
			return nil
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
	return
}

func WriteFile(content string, filePath string, append bool) error {
	var file *os.File
	var err error
	if append {
		file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	} else {
		file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	}
	if err != nil {
		return err
	}
	//及时关闭file句柄
	defer file.Close()
	//写入文件时，使用带缓存的 *Writer
	write := bufio.NewWriter(file)
	_, err = write.WriteString("\n" + content)
	if err != nil {
		return err
	}
	//Flush将缓存的文件真正写入到文件中
	err = write.Flush()
	if err != nil {
		return err
	}
	return nil
}

func WriteFileBinary(content []byte, filePath string, append bool) error {
	var file *os.File
	var err error
	if err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return err
	}
	if append {
		file, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
	} else {
		file, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
	}
	if err != nil {
		return err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	if _, err = write.Write(content); err != nil {
		return err
	}
	return write.Flush()
}

func ReadFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("read file fail", err)
		return "", err
	}
	defer f.Close()
	//defer func(f *os.File) {
	//	err := f.Close()
	//	if err != nil {
	//	}
	//}(f)

	fd, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println("read to fd fail", err)
		return "", err
	}

	return string(fd), nil
}

func IsFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false // Path likely doesn't exist
	}
	return !info.IsDir()
}

func GetFiles(path string) (fs []string) {
	if IsFile(path) {
		return []string{path}
	}
	files, _ := ioutil.ReadDir(path)
	for _, f := range files {
		fs = append(fs, filepath.Join(path, f.Name()))
	}
	return
}

// SafeFileName 校验文件名，防止路径穿越（如 ../../xxx）。
// 返回纯文件名；非法文件名返回空串。
func SafeFileName(name string) string {
	if name == "" {
		return ""
	}
	base := filepath.Base(name)
	if base != name || base == "." || base == ".." ||
		strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return ""
	}
	return base
}
