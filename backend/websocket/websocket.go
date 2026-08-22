// WebSocket 模块：负责后端到前端的实时事件推送
//
// 设计要点：
// - 使用 Hub 管理所有连接、注册/注销与广播通道
// - 通过 goroutine 分离读/写，避免读阻塞导致写超时
// - 心跳与清理：定时向客户端发送 ping/heartbeat 并清理不可用连接
// - 订阅机制：客户端可选择订阅部分事件类型；未订阅视为接收全部
// - 背压处理：发送队列满时主动移除连接，确保系统不被慢消费者拖垮
//
// 事件类型支持：
// - task.progress: 任务进度更新（阶段、百分比、消息）
// - task.log: 任务日志（级别、文本）
// - task.status: 任务状态变化（running/paused/completed/failed）
// - vuln.found: 漏洞发现通知（实时推送新漏洞）
// - fingerprint.found: 指纹识别通知
// - recon.found: 资产发现通知
//
// 架构说明：
// Hub（中心）→ Client 1, Client 2, ... Client N
// 每个 Client 拥有独立的 send channel（256 缓冲）和 readPump/writePump goroutine
// 广播事件先进入 Hub.broadcast channel（256 缓冲），再由 Hub 事件循环分发给订阅的 Client
package websocket

import (
	"FusionWeb/backend/utils"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// EventType WebSocket 事件类型（字符串枚举）
// 前端通过该类型进行不同频道的事件分发
type EventType string

const (
	EventTaskProgress     EventType = "task.progress"     // 任务进度更新（阶段、百分比、消息）
	EventTaskLog          EventType = "task.log"          // 任务日志（级别、文本）
	EventTaskStatus       EventType = "task.status"       // 任务状态变化（running/paused/...）
	EventVulnFound        EventType = "vuln.found"        // 漏洞发现事件
	EventFingerprintFound EventType = "fingerprint.found" // 指纹识别事件
	EventReconFound       EventType = "recon.found"       // 资产发现事件
)

// Event WebSocket 事件结构
// - Type：事件类型（用于前端进行路由/分发）
// - Timestamp：事件生成时间（RFC3339）
// - Data：事件负载（各类型自定义字段）
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Client WebSocket 客户端
// - conn：底层连接
// - send：待发送事件的有缓冲队列（慢消费者会被移除）
// - hub：所属 Hub
// - subscribed：订阅的事件类型集合（为空表示接收全部）
// - mu：保护订阅集合与并发读写
type Client struct {
	conn       *websocket.Conn
	send       chan *Event
	hub        *Hub
	subscribed map[EventType]bool
	mu         sync.RWMutex
}

// Hub WebSocket 连接管理中心
// - clients：活跃客户端集合
// - broadcast：广播通道，来自业务的事件统一进入此通道
// - register/unregister：连接的注册/注销通道
// - mu：保护 clients 集合
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan *Event
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// 允许所有来源（开发环境）
			// 生产环境建议按需校验 Origin 以防跨站连接
			return true
		},
	}

	globalHub *Hub
	once      sync.Once
)

// NewHub 创建新的 Hub 实例（不自动运行事件循环）
// 返回值：Hub 指针，需调用 Run() 启动事件循环
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan *Event, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// GetHub 获取全局 Hub 实例（单例）
// 首次调用会创建并启动 Hub 的事件循环
func GetHub() *Hub {
	once.Do(func() {
		globalHub = NewHub()
		go globalHub.Run()
	})
	return globalHub
}

// Run 运行 Hub（事件循环）
// - 处理连接注册/注销
// - 广播事件到订阅的客户端（慢消费者被清理）
// - 定时心跳，检测不可用连接并移除
func (h *Hub) Run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			// 连接/断开日志改为Debug级别，减少日志冗余
			// log.Printf("WebSocket: 新客户端连接，当前连接数: %d", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			// 连接/断开日志改为Debug级别，减少日志冗余
			// log.Printf("WebSocket: 客户端断开连接，当前连接数: %d", len(h.clients))

		case event := <-h.broadcast:
			// 遍历时只读锁收集失活客户端，避免在读锁下修改 map
			h.mu.RLock()
			toDrop := make([]*Client, 0)
			for client := range h.clients {
				if client.IsSubscribed(event.Type) {
					select {
					case client.send <- event:
					default:
						toDrop = append(toDrop, client)
					}
				}
			}
			h.mu.RUnlock()

			if len(toDrop) > 0 {
				h.mu.Lock()
				for _, client := range toDrop {
					if _, ok := h.clients[client]; ok {
						delete(h.clients, client)
						close(client.send)
					}
				}
				h.mu.Unlock()
			}

		case <-ticker.C:
			// 心跳检测，清理无法接收消息的客户端
			h.mu.RLock()
			toDrop := make([]*Client, 0)
			for client := range h.clients {
				select {
				case client.send <- &Event{
					Type:      "heartbeat",
					Timestamp: utils.GetCurrentTimeString(),
					Data:      map[string]interface{}{"message": "ping"},
				}:
				default:
					toDrop = append(toDrop, client)
				}
			}
			h.mu.RUnlock()

			if len(toDrop) > 0 {
				h.mu.Lock()
				for _, client := range toDrop {
					if _, ok := h.clients[client]; ok {
						delete(h.clients, client)
						close(client.send)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// Broadcast 广播事件到所有客户端
// 通过 Hub 的内部队列异步处理；队列满时丢弃事件并记录日志
func (h *Hub) Broadcast(eventType EventType, data map[string]interface{}) {
	event := &Event{
		Type:      eventType,
		Timestamp: utils.GetCurrentTimeString(),
		Data:      data,
	}

	select {
	case h.broadcast <- event:
	default:
		log.Printf("WebSocket: 广播队列已满，丢弃事件: %s", eventType)
	}
}

// Subscribe 订阅事件类型
// 空订阅集合表示接收全部事件；一旦添加具体类型则只接收这些类型
func (c *Client) Subscribe(eventType EventType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subscribed[eventType] = true
}

// Unsubscribe 取消订阅事件类型
func (c *Client) Unsubscribe(eventType EventType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.subscribed, eventType)
}

// IsSubscribed 检查是否订阅了事件类型
// 未订阅任何类型时返回 true（默认接收全部）
func (c *Client) IsSubscribed(eventType EventType) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 如果没有订阅任何事件，则接收所有事件
	if len(c.subscribed) == 0 {
		return true
	}

	return c.subscribed[eventType]
}

// readPump 读取客户端消息（订阅/取消订阅）
// 协议：
// {"action":"subscribe","events":["task.progress","task.log"]}
// {"action":"unsubscribe","events":["task.log"]}
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket 读取错误: %v", err)
			}
			break
		}

		// 解析客户端消息（订阅控制）
		var msg struct {
			Action string   `json:"action"` // subscribe / unsubscribe
			Events []string `json:"events"` // 事件类型列表
		}

		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("WebSocket 消息解析错误: %v", err)
			continue
		}

		// 处理订阅/取消订阅
		for _, eventStr := range msg.Events {
			eventType := EventType(eventStr)
			if msg.Action == "subscribe" {
				c.Subscribe(eventType)
				// 订阅事件日志改为Debug级别，减少日志冗余
				// log.Printf("客户端订阅事件: %s", eventType)
				// log.Printf("客户端当前订阅数量: %d", len(c.subscribed))
			} else if msg.Action == "unsubscribe" {
				c.Unsubscribe(eventType)
				// 取消订阅事件日志改为Debug级别，减少日志冗余
				// log.Printf("客户端取消订阅事件: %s", eventType)
				// log.Printf("客户端当前订阅数量: %d", len(c.subscribed))
			}
		}
	}
}

// writePump 向客户端发送消息
// 定时发送 ping 保持连接；写队列阻塞或写失败时终止连接
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case event, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				// Hub 关闭了 send channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// 发送 JSON 消息
			if err := c.conn.WriteJSON(event); err != nil {
				log.Printf("WebSocket 写入错误: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ServeWS 处理 WebSocket 连接
// - HTTP 升级为 WebSocket
// - 注册客户端并在独立 goroutine 中运行读/写循环
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket 升级失败: %v", err)
		return
	}

	client := &Client{
		conn:       conn,
		send:       make(chan *Event, 256),
		hub:        hub,
		subscribed: make(map[EventType]bool),
	}

	client.hub.register <- client

	// 在单独的 goroutine 中运行读写
	go client.writePump()
	go client.readPump()
}

// ============================================================
// 辅助函数：快速广播不同类型的事件
// 统一封装任务进度、日志、状态与结果的推送格式
// 业务代码直接调用这些函数即可，无需手动构造 Event 结构体
// ============================================================

// BroadcastProgress 广播任务进度更新事件
// 参数：
//   - taskID: 任务唯一标识
//   - stage: 当前阶段名称（如 recon/fingerprint/vuln）
//   - percentage: 进度百分比（0.0 - 100.0）
//   - message: 进度描述信息
func BroadcastProgress(taskID string, stage string, percentage float64, message string) {
	GetHub().Broadcast(EventTaskProgress, map[string]interface{}{
		"taskID":     taskID,
		"stage":      stage,
		"percentage": percentage,
		"message":    message,
	})
}

// BroadcastLog 广播任务日志消息
// 参数：
//   - taskID: 任务唯一标识
//   - level: 日志级别（DEBUG/INFO/SUCCESS/WARNING/ERROR）
//   - message: 日志内容
func BroadcastLog(taskID string, level string, message string) {
	GetHub().Broadcast(EventTaskLog, map[string]interface{}{
		"taskID":  taskID,
		"level":   level,
		"message": message,
	})
}

// BroadcastStatus 广播任务状态变更事件
// 参数：
//   - taskID: 任务唯一标识
//   - status: 新状态（pending/running/completed/failed/paused/cancelled）
//   - message: 状态变更说明
func BroadcastStatus(taskID string, status string, message string) {
	GetHub().Broadcast(EventTaskStatus, map[string]interface{}{
		"taskID":  taskID,
		"status":  status,
		"message": message,
	})
}

// BroadcastVuln 广播漏洞发现事件
// 参数：
//   - taskID: 任务唯一标识
//   - target: 受影响的 URL 或 IP
//   - templateID: POC 模板 ID
//   - severity: 漏洞严重等级（critical/high/medium/low/info）
func BroadcastVuln(taskID string, target string, templateID string, severity string) {
	GetHub().Broadcast(EventVulnFound, map[string]interface{}{
		"taskID":     taskID,
		"target":     target,
		"templateID": templateID,
		"severity":   severity,
	})
}

// BroadcastFingerprint 广播指纹识别事件
// 参数：
//   - taskID: 任务唯一标识
//   - target: 被识别的 URL
//   - fingerprintName: 识别到的指纹名称（如 Apache、Nginx、Spring Boot 等）
func BroadcastFingerprint(taskID string, target string, fingerprintName string) {
	GetHub().Broadcast(EventFingerprintFound, map[string]interface{}{
		"taskID":          taskID,
		"target":          target,
		"fingerprintName": fingerprintName,
	})
}

// BroadcastRecon 广播资产发现事件
// 参数：
//   - taskID: 任务唯一标识
//   - resultType: 结果类型（port/url/protocol）
//   - target: 被发现的目标（IP:Port 或 URL）
//   - source: 发现来源（如端口扫描、子域名爆破等）
func BroadcastRecon(taskID string, resultType string, target string, source string) {
	GetHub().Broadcast(EventReconFound, map[string]interface{}{
		"taskID":     taskID,
		"resultType": resultType,
		"target":     target,
		"source":     source,
	})
}
