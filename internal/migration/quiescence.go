package migration

import (
	"context"
	"errors"
	"math"
	"time"
)

type brokerVerificationResult struct {
	response BrokerResponse
	err      error
}

type sourceDatabaseObservation struct {
	ManifestDigest string
	DatabaseBytes  int64
}

type sourceDatabaseObserver struct {
	engine  string
	inspect func(context.Context) (sourceDatabaseObservation, error)
	close   func()
}

func (e *NativeExecutor) newSourceDatabaseObserver(ctx context.Context, task TaskEnvelope, inputs map[string]any) (sourceDatabaseObserver, error) {
	engine, err := stringInput(inputs, "database_engine")
	if err != nil {
		return sourceDatabaseObserver{}, err
	}
	switch engine {
	case "postgresql":
		bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
		if err != nil {
			return sourceDatabaseObserver{}, err
		}
		if binding.Mode != "source" {
			binding.clear()
			return sourceDatabaseObserver{}, errors.New("source observation requires a source PostgreSQL binding")
		}
		return sourceDatabaseObserver{
			engine: engine, close: binding.clear,
			inspect: func(sampleContext context.Context) (sourceDatabaseObservation, error) {
				inspection, inspectErr := e.inspectPostgres(sampleContext, bindingID, binding)
				if inspectErr != nil {
					return sourceDatabaseObservation{}, inspectErr
				}
				if !inspection.Exists || inspection.NonDefaultTablespaceCount > 0 {
					return sourceDatabaseObservation{}, errors.New("source PostgreSQL database is missing or unsupported")
				}
				return sourceDatabaseObservation{ManifestDigest: inspection.ManifestDigest, DatabaseBytes: inspection.DatabaseBytes}, nil
			},
		}, nil
	case "mysql", "mariadb":
		bindingID, binding, err := e.resolveMySQLBinding(ctx, task, inputs)
		if err != nil {
			return sourceDatabaseObserver{}, err
		}
		if binding.Mode != "source" || binding.Engine != engine {
			binding.clear()
			return sourceDatabaseObserver{}, errors.New("source observation database engine does not match its binding")
		}
		return sourceDatabaseObserver{
			engine: engine, close: binding.clear,
			inspect: func(sampleContext context.Context) (sourceDatabaseObservation, error) {
				inspection, inspectErr := e.inspectMySQL(sampleContext, bindingID, binding)
				if inspectErr != nil {
					return sourceDatabaseObservation{}, inspectErr
				}
				if !inspection.Exists {
					return sourceDatabaseObservation{}, errors.New("source MySQL or MariaDB database is missing")
				}
				return sourceDatabaseObservation{ManifestDigest: inspection.ManifestDigest, DatabaseBytes: inspection.DatabaseBytes}, nil
			},
		}, nil
	case "mongodb":
		bindingID, binding, err := e.resolveMongoDBBinding(ctx, task, inputs)
		if err != nil {
			return sourceDatabaseObserver{}, err
		}
		if binding.Mode != "source" {
			binding.clear()
			return sourceDatabaseObserver{}, errors.New("source observation requires a source MongoDB binding")
		}
		return sourceDatabaseObserver{
			engine: engine, close: binding.clear,
			inspect: func(sampleContext context.Context) (sourceDatabaseObservation, error) {
				inspection, inspectErr := e.inspectMongoDB(sampleContext, bindingID, binding)
				if inspectErr != nil {
					return sourceDatabaseObservation{}, inspectErr
				}
				if !inspection.Exists {
					return sourceDatabaseObservation{}, errors.New("source MongoDB database has no supported collections")
				}
				return sourceDatabaseObservation{ManifestDigest: inspection.ManifestDigest, DatabaseBytes: inspection.DatabaseBytes}, nil
			},
		}, nil
	case "redis", "valkey":
		bindingID, binding, err := e.resolveRedisBinding(ctx, task, inputs)
		if err != nil {
			return sourceDatabaseObserver{}, err
		}
		if binding.Mode != "source" || binding.Engine != engine {
			binding.clear()
			return sourceDatabaseObserver{}, errors.New("source observation Redis or Valkey engine does not match its binding")
		}
		return sourceDatabaseObserver{
			engine: engine, close: binding.clear,
			inspect: func(sampleContext context.Context) (sourceDatabaseObservation, error) {
				inspection, inspectErr := e.inspectRedis(sampleContext, bindingID, binding)
				if inspectErr != nil {
					return sourceDatabaseObservation{}, inspectErr
				}
				if !inspection.Exists {
					return sourceDatabaseObservation{}, errors.New("source Redis or Valkey instance is unavailable")
				}
				return sourceDatabaseObservation{ManifestDigest: inspection.ManifestDigest, DatabaseBytes: inspection.DatabaseBytes}, nil
			},
		}, nil
	default:
		return sourceDatabaseObserver{}, errors.New("source observation database engine is unsupported")
	}
}

func optionalDigestInput(inputs map[string]any, key string) (string, error) {
	raw, present := inputs[key]
	if !present {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok || !fileDigestPattern.MatchString(value) {
		return "", errors.New(key + " is invalid")
	}
	return value, nil
}

func (e *NativeExecutor) sourceEstimate(
	ctx context.Context,
	task TaskEnvelope,
	inputs map[string]any,
	progress func(string, int64, *int64) error,
) (map[string]any, error) {
	observer, err := e.newSourceDatabaseObserver(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer observer.close()
	inspection, err := observer.inspect(ctx)
	if err != nil {
		return nil, err
	}
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	relative := "."
	if value, ok := inputs["relative_handle"].(string); ok && value != "" {
		relative = value
	}
	root, err := e.resolver.Resolve(handle, relative, false)
	if err != nil {
		return nil, err
	}
	files, err := buildFileManifest(ctx, root, func(completed int64) error {
		return progress("cutover_estimate_files", completed, nil)
	})
	if err != nil {
		return nil, err
	}
	throughputMiB, err := boundedIntegerInput(inputs, "transfer_mib_per_second", 1, 1024)
	if err != nil {
		return nil, err
	}
	payloadBytes := inspection.DatabaseBytes + files.TotalBytes
	estimatedSeconds := int64(math.Ceil(float64(payloadBytes) / float64(throughputMiB*1024*1024)))
	if estimatedSeconds < 1 && payloadBytes > 0 {
		estimatedSeconds = 1
	}
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	proof := map[string]any{
		"schema_version":             "operations.migration.cutover-estimate.v1",
		"database_engine":            observer.engine,
		"database_manifest_digest":   inspection.ManifestDigest,
		"database_bytes":             inspection.DatabaseBytes,
		"file_manifest_digest":       files.Digest,
		"file_bytes":                 files.TotalBytes,
		"file_count":                 files.FileCount,
		"payload_bytes_upper_bound":  payloadBytes,
		"transfer_mib_per_second":    throughputMiB,
		"estimated_transfer_seconds": estimatedSeconds,
		"observed_at":                observedAt,
	}
	proofDigest, err := Digest(proof)
	if err != nil {
		return nil, err
	}
	proof["estimate_digest"] = proofDigest
	return proof, nil
}

func (e *NativeExecutor) sourceQuiescence(
	ctx context.Context,
	task TaskEnvelope,
	inputs map[string]any,
	progress func(string, int64, *int64) error,
) (map[string]any, error) {
	interval, err := boundedIntegerInput(inputs, "interval_seconds", 5, 60)
	if err != nil {
		return nil, err
	}
	expectedDatabase, err := optionalDigestInput(inputs, "expected_database_manifest_digest")
	if err != nil {
		return nil, err
	}
	expectedFiles, err := optionalDigestInput(inputs, "expected_file_manifest_digest")
	if err != nil {
		return nil, err
	}
	observer, err := e.newSourceDatabaseObserver(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer observer.close()
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	relative := "."
	if value, ok := inputs["relative_handle"].(string); ok && value != "" {
		relative = value
	}
	root, err := e.resolver.Resolve(handle, relative, false)
	if err != nil {
		return nil, err
	}

	verificationContext, cancelVerification := context.WithCancel(ctx)
	defer cancelVerification()
	brokerResult := make(chan brokerVerificationResult, 1)
	startedAt := time.Now().UTC()
	go func() {
		response, executeErr := e.broker.Execute(verificationContext, BrokerRequest{
			SchemaVersion: brokerSchemaVersion,
			RequestID:     task.Nonce,
			Task:          task,
		})
		brokerResult <- brokerVerificationResult{response: response, err: executeErr}
	}()

	beforeDatabase, err := observer.inspect(ctx)
	if err != nil {
		return nil, err
	}
	beforeFiles, err := buildFileManifest(ctx, root, func(completed int64) error {
		return progress("quiescence_first_sample", completed, nil)
	})
	if err != nil {
		return nil, err
	}
	remaining := time.Until(startedAt.Add(time.Duration(interval) * time.Second))
	if remaining > 0 {
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := progress("quiescence_second_sample", 0, nil); err != nil {
		return nil, err
	}
	afterDatabase, err := observer.inspect(ctx)
	if err != nil {
		return nil, err
	}
	afterFiles, err := buildFileManifest(ctx, root, func(completed int64) error {
		return progress("quiescence_second_sample", completed, nil)
	})
	if err != nil {
		return nil, err
	}
	verification := <-brokerResult
	if verification.err != nil {
		return nil, errors.New("writer fence verification was unavailable")
	}
	if !verification.response.OK {
		if verification.response.Error != nil {
			return nil, errors.New(verification.response.Error.SafeMessage)
		}
		return nil, errors.New("writer fence verification failed")
	}
	writerActive, _ := verification.response.Outputs["writer_fence_active"].(bool)
	violations, violationErr := boundedIntegerInput(verification.response.Outputs, "violation_count", 0, math.MaxInt64)
	if violationErr != nil || !writerActive || violations != 0 {
		return nil, errors.New("writer fence was violated during source quiescence")
	}
	if beforeDatabase.ManifestDigest != afterDatabase.ManifestDigest || beforeFiles.Digest != afterFiles.Digest {
		return nil, errors.New("source data changed during the quiescence interval")
	}
	if expectedDatabase != "" && afterDatabase.ManifestDigest != expectedDatabase {
		return nil, errors.New("source database changed after the final dump")
	}
	if expectedFiles != "" && afterFiles.Digest != expectedFiles {
		return nil, errors.New("source files changed after the final manifest")
	}
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	proof := map[string]any{
		"schema_version":               "operations.migration.source-quiescence.v1",
		"database_engine":              observer.engine,
		"writer_fence_active":          true,
		"writer_fence_verified_at":     verification.response.Outputs["verified_at"],
		"writer_fence_activated_at":    verification.response.Outputs["activated_at"],
		"writer_fence_fencing_token":   verification.response.Outputs["fence_fencing_token"],
		"writer_fence_violation_count": violations,
		"interval_seconds":             interval,
		"database_manifest_digest":     afterDatabase.ManifestDigest,
		"file_manifest_digest":         afterFiles.Digest,
		"file_count":                   afterFiles.FileCount,
		"file_bytes":                   afterFiles.TotalBytes,
		"observed_at":                  observedAt,
	}
	proofDigest, err := Digest(proof)
	if err != nil {
		return nil, err
	}
	proof["quiescence_proof_digest"] = proofDigest
	return proof, nil
}
