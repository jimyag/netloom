package ovn

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
)

type LibOVSDBTopologyWriter struct {
	client client.Client
}

func NewLibOVSDBTopologyWriter(client client.Client) *LibOVSDBTopologyWriter {
	return &LibOVSDBTopologyWriter{client: client}
}

func (w *LibOVSDBTopologyWriter) EnsureVPC(ctx context.Context, vpc model.VPC) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router := &ovnnb.LogicalRouter{
		Name:        logicalRouter(vpc.Name),
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": vpc.Name},
	}
	existing, ok, err := w.logicalRouterByName(ctx, router.Name)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		ops, err = w.client.Create(router)
		if err != nil {
			return fmt.Errorf("create logical router %s: %w", router.Name, err)
		}
	} else {
		nextExternalIDs := mergeStringMap(existing.ExternalIDs, router.ExternalIDs)
		if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) {
			return nil
		}
		existing.ExternalIDs = nextExternalIDs
		ops, err = w.client.Where(existing).Update(existing, &existing.ExternalIDs)
		if err != nil {
			return fmt.Errorf("update logical router %s external IDs: %w", router.Name, err)
		}
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact logical router %s: %w", router.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("logical router %s operation errors=%+v: %w", router.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) logicalRouterByName(ctx context.Context, name string) (*ovnnb.LogicalRouter, bool, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == name }).List(ctx, &routers); err != nil {
		return nil, false, fmt.Errorf("list logical router %s from libovsdb cache: %w", name, err)
	}
	if len(routers) == 0 {
		return nil, false, nil
	}
	return &routers[0], true, nil
}

func mergeStringMap(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}
