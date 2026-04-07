package operations

import (
	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

func DefaultRegistry(exec remediation.Executor, opsCfg *config.OperationsConfig) *Registry {
	s := StepExec{Exec: exec}

	var handlers []Handler
	handlers = append(handlers, ServiceHandlers(s)...)
	handlers = append(handlers, PackageHandlers(s)...)
	handlers = append(handlers, CheckHandlers()...)
	handlers = append(handlers, CommandHandlers(s, opsCfg)...)

	return NewRegistry(handlers...)
}
