// models/user.go
// 用户模型定义
// 包含用户账户的核心数据结构，基于 GORM 进行数据库映射。
// 设计要点：
// - 密码字段使用 json:"-" 标记，序列化时自动隐藏，防止泄漏到前端
// - 支持软删除（gorm.Model 内嵌 deleted_at 字段）
// - 角色字段保留给账户管理和前端展示；当前部署按单用户可信模型处理
// - 状态分为 active（激活）与 disabled（禁用），用于账户管理
// - must_change_password 标记首次登录的用户必须修改默认密码
package models

import (
	"gorm.io/gorm"
)

// User 用户模型
type User struct {
	gorm.Model
	Username           string `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Password           string `gorm:"type:varchar(255);not null" json:"-"` // 不返回给前端
	Email              string `gorm:"type:varchar(100)" json:"email"`
	RealName           string `gorm:"type:varchar(50)" json:"realName"`
	Avatar             string `gorm:"type:varchar(255)" json:"avatar"`
	Role               string `gorm:"type:varchar(20);default:'user'" json:"role"`     // admin, user
	Status             string `gorm:"type:varchar(20);default:'active'" json:"status"` // active, disabled
	MustChangePassword bool   `gorm:"default:true" json:"mustChangePassword"`          // 首次登录必须修改密码
}

// TableName 指定数据库表名
// 重写 gorm.Model 的默认表名，将表名指定为 "users"
// 如果不重写，GORM 默认会使用结构体名的复数形式（即 "user" + "s" → "users"，但在某些规则下可能不一致）
func (User) TableName() string {
	return "users"
}
