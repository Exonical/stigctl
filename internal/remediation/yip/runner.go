//go:build linux

package yip

import (
	"bytes"
	"context"
	"fmt"

	"github.com/Exonical/stigctl/internal/remediation"
	yipconsole "github.com/mudler/yip/pkg/console"
	yipexecutor "github.com/mudler/yip/pkg/executor"
	"github.com/sirupsen/logrus"
	"github.com/twpayne/go-vfs/v5"
)

type Runner struct{}

func New() Runner {
	return Runner{}
}

func (Runner) Apply(ctx context.Context, req remediation.Request) (remediation.Result, error) {
	stage := req.Stage
	if stage == "" {
		stage = "stig"
	}
	if len(req.Files) == 0 {
		return remediation.Result{}, fmt.Errorf("no Yip remediation files supplied")
	}
	if err := ctx.Err(); err != nil {
		return remediation.Result{}, err
	}

	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true, DisableColors: true})

	console := yipconsole.NewStandardConsole(yipconsole.WithLogger(logger))
	runner := yipexecutor.NewExecutor(yipexecutor.WithLogger(logger))

	err := runner.Run(stage, vfs.OSFS, console, req.Files...)
	result := remediation.Result{
		Files:  append([]string(nil), req.Files...),
		Stdout: logs.String(),
	}
	if err != nil {
		return result, fmt.Errorf("embedded Yip remediation failed: %w", err)
	}
	return result, nil
}
