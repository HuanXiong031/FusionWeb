package scheduler

import (
	"FusionWeb/backend/models"
	"context"
	"fmt"
	"sync/atomic"
)

// TaskExecutor runs Stream tasks synchronously so messages are ACKed only after execution finishes.
type TaskExecutor struct {
	scheduler *TaskScheduler
	name      string
	sequence  atomic.Int64
}

func NewTaskExecutor(parent context.Context, name string) *TaskExecutor {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	s := &TaskScheduler{maxConcurrent: 1, taskQueue: make(chan *models.TaskConfig, 1), tasks: make(map[string]*TaskContext), ctx: ctx, cancel: cancel}
	return &TaskExecutor{scheduler: s, name: name}
}
func (e *TaskExecutor) Execute(ctx context.Context, task *models.TaskConfig) error {
	if task == nil {
		return fmt.Errorf("任务配置不能为空")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	id := int(e.sequence.Add(1))
	w := &Worker{id: id, name: e.name, scheduler: e.scheduler, taskChan: make(chan *models.TaskConfig)}
	return w.executeTask(task)
}
func (e *TaskExecutor) Close() {
	if e != nil && e.scheduler != nil {
		e.scheduler.cancel()
	}
}
