package operations

import "context"

type HandlerResult struct {
	Status   string // success|failed|skipped
	Output   string
	Changed  bool
	Error    error
}

type Handler interface {
	ID() string
	Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult
}

type Registry struct {
	m map[string]Handler
}

func NewRegistry(handlers ...Handler) *Registry {
	m := map[string]Handler{}
	for _, h := range handlers {
		m[h.ID()] = h
	}
	return &Registry{m: m}
}

func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.m))
	for id := range r.m {
		ids = append(ids, id)
	}
	return ids
}

func (r *Registry) Get(id string) (Handler, bool) {
	h, ok := r.m[id]
	return h, ok
}
