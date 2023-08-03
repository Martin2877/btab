package file

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ReadingLines Reading file and return content as []string
func ReadingLines(filename string) []string {
	var result []string
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		val := scanner.Text()
		if val == "" {
			continue
		}
		result = append(result, val)
	}

	if err := scanner.Err(); err != nil {
		return result
	}
	return result
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

func WriteFileBinary(content []byte, filePath string, append bool) {
	var file *os.File
	var err error
	if append {
		file, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o777)
	} else {
		file, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o777)
	}
	if err != nil {
		fmt.Println("文件打开失败", err)
		return
	}
	//及时关闭file句柄
	file.Sync()
	defer func(file *os.File) {
		err2 := file.Close()
		if err2 != nil {
			log.Fatal(err2.Error())
		}
	}(file)
	//defer file.Close()
	//写入文件时，使用带缓存的 *Writer
	write := bufio.NewWriter(file)
	write.Write(content)
	//Flush将缓存的文件真正写入到文件中
	write.Flush()
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

func GetFiles(path string) (fs []string) {
	files, _ := ioutil.ReadDir(path)
	for _, f := range files {
		fs = append(fs, filepath.Join(path, f.Name()))
	}
	return
}
