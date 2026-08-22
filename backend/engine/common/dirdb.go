// ========================================
// 目录字典加载模块（Directory Dictionary Loader）
//
// 功能概述：
//
//	从数据库读取主动指纹规则，解析其中的路径列表，构建"路径→产品名称"的索引映射。
//	该映射供目录爆破模块使用：当发现某路径存在时，触发对应的产品指纹匹配。
//	替代了原来从本地 YAML 文件读取字典的方式，改为从数据库动态加载。
//
// 数据结构：
//
//	structs.DirDB: map[string][]string
//	  - Key: 字典路径（如 "/admin/login"）
//	  - Value: 关联的产品名称列表（如 ["Tomcat", "SpringBoot"]）
//	  - 同一个路径可能对应多个产品，同一个产品也可能出现在多个路径中
//
// 集成关系：
//   - 被 http 包中的 DirBruteCallBack 使用，用于主动指纹识别
//   - 数据源为 database 包的 active_fingerprints 表
//   - 结果存储于 core/structs 包的 DirDB 全局变量
//
// ========================================
package common

import (
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"

	"gopkg.in/yaml.v3"
)

// ReadDirDBFromDatabase 从数据库读取目录字典并构建路径到产品的索引
//
// 功能说明：
//
//	查询 active_fingerprints 表中所有启用且未黑名单的主动指纹记录，
//	解析每条记录的 YAML 格式路径列表（rules 字段），
//	构建全局的路径→产品名称映射（structs.DirDB）。
//
// 处理流程：
//  1. 初始化 structs.DirDB 为空映射
//  2. 查询数据库：SELECT name, rules FROM active_fingerprints WHERE is_enabled=1 AND is_blacklisted=0
//  3. 遍历结果行，将 rules YAML 解析为路径字符串数组
//  4. 对每个路径，建立或追加其对应的产品名称列表
//  5. 对重复的产品名称进行去重
//
// 输出：
//   - 日志输出加载的产品数量和路径总数
//   - 结果存入 structs.DirDB 供后续目录爆破模块使用
//
// 注意事项：
//   - 函数在扫描启动前调用一次，完成字典的初始化
//   - 若数据库查询失败，仅记录警告日志，不会中断程序
func ReadDirDBFromDatabase() {
	structs.DirDB = make(map[string][]string)

	// 查询所有启用的主动指纹
	rows, err := database.DB.Query(`
		SELECT name, rules 
		FROM active_fingerprints 
		WHERE is_enabled = 1 AND is_blacklisted = 0
	`)
	if err != nil {
		logger.Warn("从数据库读取主动指纹失败: %v", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var name string
		var rulesYAML string

		if err := rows.Scan(&name, &rulesYAML); err != nil {
			logger.Warn("扫描主动指纹行失败: %v", err)
			continue
		}

		// 解析 rules YAML（格式为路径数组）
		var paths []string
		if err := yaml.Unmarshal([]byte(rulesYAML), &paths); err != nil {
			logger.Warn("解析主动指纹 %s 的规则失败: %v", name, err)
			continue
		}

		// 构建路径到产品名称的映射
		for _, path := range paths {
			if path == "" {
				continue
			}
			if _, ok := structs.DirDB[path]; ok {
				// 路径已存在，追加产品名称
				structs.DirDB[path] = append(structs.DirDB[path], name)
				// 去重
				structs.DirDB[path] = removeDuplicateStrings(structs.DirDB[path])
			} else {
				// 新路径
				structs.DirDB[path] = []string{name}
			}
		}
		count++
	}

	if err := rows.Err(); err != nil {
		logger.Warn("遍历主动指纹行时出错: %v", err)
	}

	logger.Info("从数据库加载主动指纹字典完成，共 %d 个产品，%d 条路径", count, len(structs.DirDB))
}

// removeDuplicateStrings 去除字符串切片中的重复项
//
// 功能说明：
//
//	使用 map 记录已出现的字符串，遍历输入切片，仅保留首次出现的元素，
//	返回去重后的新切片，保持原有先后顺序。
//
// 参数：
//   - slice: 待去重的字符串切片
//
// 返回值：
//   - 去重后的字符串切片（保持原有顺序）
//
// 使用场景：
//   - 在构建目录字典时，同一路径可能被多个指纹记录关联，
//     需要确保产品名称列表中没有重复项
func removeDuplicateStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}
