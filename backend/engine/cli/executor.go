package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type LogFunc func(level, format string, args ...interface{})

type ExecuteOptions struct {
	Timeout time.Duration
	Stdin   string
	Logf    LogFunc
}

type ExecuteResult struct {
	Tool     string
	Path     string
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
}

func Execute(ctx context.Context, tool string, args []string, options ExecuteOptions) (ExecuteResult, error) {
	path, err := ResolveTool(tool)
	result := ExecuteResult{
		Tool:     tool,
		Path:     path,
		Args:     append([]string(nil), args...),
		ExitCode: -1,
	}
	if err != nil {
		return result, err
	}

	// 工具由统一工具镜像（toolkit）提供时，转发远程执行
	if strings.HasPrefix(path, toolkitPathPrefix) {
		return executeViaToolkit(ctx, tool, args, options)
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	if options.Logf != nil {
		options.Logf("DEBUG", "[CLI] %s %s", path, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if options.Stdin != "" {
		cmd.Stdin = strings.NewReader(options.Stdin)
	}

	err = cmd.Run()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, fmt.Errorf("%s 执行超时或被取消: %w", tool, ctxErr)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return result, fmt.Errorf("%s 执行失败，退出码 %d: %s", tool, result.ExitCode, strings.TrimSpace(result.Stderr))
		}
		return result, fmt.Errorf("%s 执行失败: %w", tool, err)
	}

	return result, nil
}
