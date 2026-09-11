// api/service_token.go
//
// 服务账号令牌（Service Token）
//
// 用途：供外部智能体（如 DeepSeek Harness / fusionweb-tools 插件）以**最小权限**调用 FusionWeb，
// 而不需要走“用户名密码 + SM2 + JWT”的人类登录流程。
//
// 设计要点：
//   - 令牌仅存 sha256 哈希，明文只在创建时返回一次；
//   - 按 scope 授权（tasks:read / tasks:write / results:read），并为不同接口指定所需 scope；
//   - 服务账号注入与 JWT 完全相同的上下文键（userId/username/role），因此可直接复用现有处理器；
//   - 独立的 /api/v1/svc/* 路由组，不进入 JWT 中间件，避免影响既有鉴权链路。
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"FusionWeb/backend/database"

	"github.com/gin-gonic/gin"
)

// ServiceTokenPrefix 服务账号令牌前缀，便于识别与轮换。
const ServiceTokenPrefix = "fwsvc_"

// allowedServiceTokenScopes 允许授权的权限范围白名单。
var allowedServiceTokenScopes = map[string]bool{
	"tasks:read":    true,
	"tasks:write":   true,
	"results:read":  true,
	"notify:send":   true,
	"confirm:write": true,
	"confirm:read":  true,
}

type serviceTokenRow struct {
	ID        int
	Name      string
	Scopes    string
	UserID    uint
	Enabled   int
	ExpiresAt *time.Time
}

func hashServiceToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func bearerToken(c *gin.Context) string {
	raw := strings.TrimSpace(c.GetHeader("Authorization"))
	if raw == "" {
		raw = strings.TrimSpace(c.GetHeader("X-Service-Token"))
	}
	return strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
}

func serviceTokenHasScope(scopes, want string) bool {
	for _, item := range strings.Split(scopes, ",") {
		item = strings.TrimSpace(item)
		if item == "*" || (want != "" && item == want) {
			return true
		}
	}
	return false
}

// ServiceTokenAuthMiddleware 校验服务账号令牌，并按最小权限检查所需 scope。
func ServiceTokenAuthMiddleware(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" || !strings.HasPrefix(token, ServiceTokenPrefix) {
			abortUnauthorized(c, "缺少服务账号令牌")
			return
		}

		var row serviceTokenRow
		err := database.DB.QueryRow(
			`SELECT id,name,scopes,user_id,enabled,expires_at FROM service_tokens WHERE token_hash=?`,
			hashServiceToken(token),
		).Scan(&row.ID, &row.Name, &row.Scopes, &row.UserID, &row.Enabled, &row.ExpiresAt)
		if err != nil {
			abortUnauthorized(c, "服务账号令牌无效")
			return
		}
		if row.Enabled != 1 {
			abortUnauthorized(c, "服务账号令牌已停用")
			return
		}
		if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now()) {
			abortUnauthorized(c, "服务账号令牌已过期")
			return
		}
		if requiredScope != "" && !serviceTokenHasScope(row.Scopes, requiredScope) {
			ForbiddenResponse(c, "服务账号缺少权限："+requiredScope)
			return
		}

		// 注入与 JWT 相同的上下文键，使既有处理器可原样复用
		c.Set("userId", row.UserID)
		c.Set("username", "service:"+row.Name)
		c.Set("role", "service")

		_, _ = database.DB.Exec(`UPDATE service_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=?`, row.ID)
		c.Next()
	}
}

// aliasServiceTaskIDParam 让只认 :taskId 的既有处理器在 /svc 路由（使用 :id）下也能工作。
func aliasServiceTaskIDParam(c *gin.Context) {
	if c.Param("taskId") == "" {
		if id := c.Param("id"); id != "" {
			c.Params = append(c.Params, gin.Param{Key: "taskId", Value: id})
		}
	}
	c.Next()
}

// HandleCreateServiceToken 创建服务账号令牌（明文令牌仅本次返回）。
// 请求体：{"name":"dsh","scopes":"tasks:read,tasks:write,results:read","expiresInDays":0}
func HandleCreateServiceToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		var req struct {
			Name          string `json:"name"`
			Scopes        string `json:"scopes"`
			ExpiresInDays int    `json:"expiresInDays"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			req.Name = "dsh"
		}
		req.Scopes = strings.TrimSpace(req.Scopes)
		if req.Scopes == "" {
			req.Scopes = "tasks:read,tasks:write,results:read,notify:send,confirm:read,confirm:write"
		}
		normalized := make([]string, 0, 3)
		for _, item := range strings.Split(req.Scopes, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !allowedServiceTokenScopes[item] {
				BadRequestResponse(c, "未知权限范围："+item, nil)
				return
			}
			normalized = append(normalized, item)
		}
		if len(normalized) == 0 {
			BadRequestResponse(c, "至少需要一个权限范围", nil)
			return
		}

		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			InternalServerErrorResponse(c, "生成令牌失败", err)
			return
		}
		plain := ServiceTokenPrefix + hex.EncodeToString(buf)

		var expiresAt interface{}
		var expiresAtText string
		if req.ExpiresInDays > 0 {
			exp := time.Now().AddDate(0, 0, req.ExpiresInDays)
			expiresAt = exp
			expiresAtText = exp.Format("2006-01-02 15:04:05")
		}

		id, err := database.InsertAndReturnID(
			`INSERT INTO service_tokens (name,token_hash,scopes,user_id,enabled,expires_at,created_at,updated_at) VALUES (?,?,?,?,1,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
			req.Name, hashServiceToken(plain), strings.Join(normalized, ","), currentUserIDValue(c), expiresAt,
		)
		if err != nil {
			InternalServerErrorResponse(c, "保存服务账号令牌失败", err)
			return
		}

		SuccessResponse(c, gin.H{
			"id":        id,
			"name":      req.Name,
			"scopes":    strings.Join(normalized, ","),
			"token":     plain,
			"expiresAt": expiresAtText,
			"hint":      "令牌仅显示一次，请立即保存。",
		})
	}
}

// HandleListServiceTokens 列出服务账号令牌（只返回元信息，不含明文）。
func HandleListServiceTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		rows, err := database.DB.Query(`SELECT id,name,scopes,user_id,enabled,expires_at,last_used_at,created_at FROM service_tokens ORDER BY id DESC`)
		if err != nil {
			InternalServerErrorResponse(c, "查询服务账号令牌失败", err)
			return
		}
		defer rows.Close()
		items := make([]gin.H, 0)
		for rows.Next() {
			var id, userID, enabled int
			var name, scopes string
			var expiresAt, lastUsedAt, createdAt *time.Time
			if err := rows.Scan(&id, &name, &scopes, &userID, &enabled, &expiresAt, &lastUsedAt, &createdAt); err != nil {
				continue
			}
			item := gin.H{"id": id, "name": name, "scopes": scopes, "userId": userID, "enabled": enabled == 1}
			if expiresAt != nil {
				item["expiresAt"] = expiresAt.Format("2006-01-02 15:04:05")
			}
			if lastUsedAt != nil {
				item["lastUsedAt"] = lastUsedAt.Format("2006-01-02 15:04:05")
			}
			if createdAt != nil {
				item["createdAt"] = createdAt.Format("2006-01-02 15:04:05")
			}
			items = append(items, item)
		}
		SuccessResponse(c, items)
	}
}

// HandleDeleteServiceToken 删除（吊销）服务账号令牌。
func HandleDeleteServiceToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			BadRequestResponse(c, "缺少令牌 ID", nil)
			return
		}
		result, err := database.DB.Exec(`DELETE FROM service_tokens WHERE id=?`, id)
		if err != nil {
			InternalServerErrorResponse(c, "删除服务账号令牌失败", err)
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"code": 1, "message": "服务账号令牌不存在"})
			return
		}
		SuccessResponse(c, gin.H{"id": id})
	}
}
