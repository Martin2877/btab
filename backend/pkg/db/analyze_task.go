package db

import "gorm.io/gorm"

// AnalyzeTask 统一入口的一键分析任务：输入文本/文件 → 各引擎分析 → 报告
type AnalyzeTask struct {
	gorm.Model
	Id        int    `gorm:"primary_key" json:"id"`
	Uuid      string `json:"uuid"`
	Name      string `gorm:"column:name" json:"name"` // 任务名称（默认取输入摘要）
	InputType string `json:"input_type"`              // text | pcap
	InputName string `json:"input_name"`              // 上传文件名或"粘贴文本"
	InputSize int    `json:"input_size"`              // 输入字节数
	Preview   string `json:"preview"`                 // 输入预览（截断文本）
	Methods   string `json:"methods"`                 // 选择的检测方式，逗号分隔；空=自动
	State     int    `json:"state"`                   // 复用 PAState* 常量
	Risk      bool   `json:"risk"`                    // 是否检出风险
	Verdict   string `json:"verdict"`                 // 结论摘要
	Report    string `json:"report"`                  // JSON 报告全文

	Progress interface{} `gorm:"-" json:"progress,omitempty"` // 运行中任务的实时进度（非持久化）
}

type AnalyzeTaskSearchField struct {
	Search string
}

func GetAnalyzeTask(id int) (t AnalyzeTask) {
	GlobalDB.Model(&AnalyzeTask{}).Where("id = ?", id).First(&t)
	return
}

func CreateAnalyzeTask(t *AnalyzeTask) bool {
	GlobalDB.Create(t)
	return true
}

func EditAnalyzeTask(id int, t AnalyzeTask) bool {
	GlobalDB.Model(&AnalyzeTask{}).Where("id = ?", id).Updates(t)
	return true
}

func DeleteAnalyzeTask(id int) bool {
	GlobalDB.Model(&AnalyzeTask{}).Where("id = ?", id).Delete(&AnalyzeTask{})
	return true
}

func ExistAnalyzeTaskById(id int) bool {
	var t AnalyzeTask
	GlobalDB.Model(&AnalyzeTask{}).Where("id = ?", id).First(&t)
	return t.Id > 0
}

func GetAnalyzeTasks(page int, pageSize int, field *AnalyzeTaskSearchField) (tasks []AnalyzeTask) {
	db := GlobalDB.Model(&AnalyzeTask{})
	if field.Search != "" {
		db = db.Where(GlobalDB.Where("name like ?", "%"+field.Search+"%").Or("preview like ?", "%"+field.Search+"%"))
	}
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id desc").Limit(pageSize).Find(&tasks)
	}
	return
}

// InterruptStaleAnalyzeTasks 服务启动时清理残留的"分析中"任务（进程重启后 goroutine 必然已终止）
func InterruptStaleAnalyzeTasks() {
	GlobalDB.Model(&AnalyzeTask{}).Where("state = ?", PAStateRunning).
		Updates(map[string]interface{}{"state": PAStateFailed, "verdict": "任务中断（服务重启）"})
}

func GetAnalyzeTaskTotal(field *AnalyzeTaskSearchField) (total int64) {
	db := GlobalDB.Model(&AnalyzeTask{})
	if field.Search != "" {
		db = db.Where(GlobalDB.Where("name like ?", "%"+field.Search+"%").Or("preview like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}
