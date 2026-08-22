// backend/logger/formatter.go
// 日志格式化器模块
// 提供 gologger 框架的日志格式化器实现，用于控制第三方库的日志输出格式。
// 设计要点：
// - PlainFormatter 实现 formatter.Formatter 接口，供 projectdiscovery/gologger 使用
// - 输出纯文本消息，去除所有标签、颜色码、时间戳和元数据
// - 编译时接口验证：var _ formatter.Formatter = &PlainFormatter{}
//
// 使用场景：
// - 第三方库（如 nuclei、gologger）产生的日志通过此 formatter 统一格式化
package logger

import (
	"github.com/projectdiscovery/gologger/formatter"
)

// PlainFormatter 纯文本日志格式化器
// 实现 gologger 的 formatter.Formatter 接口
// 仅输出消息原文，不含任何格式修饰（标签、颜色码、时间戳）
type PlainFormatter struct{}

// 编译时接口合规性检查：确保 PlainFormatter 实现了 formatter.Formatter
var _ formatter.Formatter = &PlainFormatter{}

// Format 格式化日志事件为纯文本消息
// 参数：event - gologger 的日志事件，包含消息、级别、元数据等
// 返回值：纯文本消息字节切片（不含任何格式修饰）
func (p *PlainFormatter) Format(event *formatter.LogEvent) ([]byte, error) {
	// 只返回消息内容，不包含任何标签、颜色码或元数据
	return []byte(event.Message), nil
}

// NewPlainFormatter 创建一个新的纯文本格式化器实例
func NewPlainFormatter() *PlainFormatter {
	return &PlainFormatter{}
}
