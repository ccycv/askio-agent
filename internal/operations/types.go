package operations

type ExecutionMode string

const (
	ExecutionModeLive   ExecutionMode = "live"
	ExecutionModeDryRun ExecutionMode = "dry_run"
)

func (m ExecutionMode) IsDryRun() bool { return m == ExecutionModeDryRun }
