package config

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/api"
	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/store"
)

const (
	bucketConfig = "config"
	keyRemote    = "remote_config_v1"
)

type RemoteConfigManager struct {
	api   *api.Client
	store store.Store
}

func NewRemoteConfigManager(apiClient *api.Client, st store.Store) *RemoteConfigManager {
	return &RemoteConfigManager{api: apiClient, store: st}
}

func (m *RemoteConfigManager) LoadCached(ctx context.Context) (model.RemoteConfig, bool, error) {
	b, ok, err := m.store.Get(ctx, bucketConfig, keyRemote)
	if err != nil {
		return model.RemoteConfig{}, false, err
	}
	if !ok {
		return model.RemoteConfig{}, false, nil
	}
	var rc model.RemoteConfig
	if err := json.Unmarshal(b, &rc); err != nil {
		return model.RemoteConfig{}, false, err
	}
	return rc, true, nil
}

func (m *RemoteConfigManager) SaveCached(ctx context.Context, rc model.RemoteConfig) error {
	b, err := json.Marshal(rc)
	if err != nil {
		return err
	}
	return m.store.Put(ctx, bucketConfig, keyRemote, b)
}

func (m *RemoteConfigManager) SaveCachedNoCommand(ctx context.Context, rc model.RemoteConfig) error {
	// IMPORTANT: do not persist "pending_command" to cache.
	// If we cache it, a restart could re-trigger the same command.
	cp := rc
	cp.PendingCommand = model.PendingCommandOrString{}
	cp.CommandID = ""
	return m.SaveCached(ctx, cp)
}

// PollOnce fetches remote config from backend.
//
// Returns the full remote config (including pending_command), but only caches
// the config with command fields stripped.
func (m *RemoteConfigManager) PollOnce(ctx context.Context, serverID string) (model.RemoteConfig, error) {
	var resp model.RemoteConfig
	if err := m.api.GetConfig(ctx, serverID, &resp); err != nil {
		return model.RemoteConfig{}, err
	}
	if resp.FetchedAt.IsZero() {
		resp.FetchedAt = time.Now().UTC()
	}
	// IMPORTANT: do not persist "pending_action" to cache.
	// If we cache it, a restart could re-trigger the same action.
	toCache := resp
	toCache.PendingAction = nil

	if err := m.SaveCachedNoCommand(ctx, toCache); err != nil {
		return model.RemoteConfig{}, fmt.Errorf("save cached remote config: %w", err)
	}
	return resp, nil
}
