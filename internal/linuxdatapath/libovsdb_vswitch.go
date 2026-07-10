package linuxdatapath

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/ovn-kubernetes/libovsdb/client"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	netloommodel "github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

type LibOVSDBProviderSyncer struct {
	client client.Client
}

func NewLibOVSDBProviderSyncer(client client.Client) *LibOVSDBProviderSyncer {
	return &LibOVSDBProviderSyncer{client: client}
}

func (s *LibOVSDBProviderSyncer) SyncProviderOVSDB(ctx context.Context, rows ProviderOVSDBDesiredRows, cleanup bool) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("libovsdb provider syncer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	openvSwitch, ok, err := s.openVSwitch(ctx)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		openvSwitch = &vswitch.OpenvSwitch{UUID: ovsdbProviderNamedUUID("open_vswitch", "root")}
		createOps, err := s.client.Create(openvSwitch)
		if err != nil {
			return fmt.Errorf("create Open_vSwitch root row: %w", err)
		}
		ops = append(ops, createOps...)
	}

	desiredBridgeRefs := make([]string, 0, len(rows.Bridges))
	desiredBridgeSet := make(map[string]struct{}, len(rows.Bridges))
	controllerUUIDByName := make(map[string]string, len(rows.Controllers))
	desiredControllerSet := make(map[string]struct{}, len(rows.Controllers))
	portsByBridge := make(map[string][]string, len(rows.Bridges))
	qosUUIDByName := make(map[string]string, len(rows.QoS))
	desiredQoSSet := make(map[string]struct{}, len(rows.QoS))
	queueUUIDByName := make(map[string]string, len(rows.Queues))
	desiredQueueSet := make(map[string]struct{}, len(rows.Queues))
	for _, controller := range rows.Controllers {
		name := controller.ExternalIDs["netloom_provider_controller"]
		if name == "" {
			return fmt.Errorf("provider Controller row is missing netloom_provider_controller external ID")
		}
		desiredControllerSet[name] = struct{}{}
		controllerUUID, controllerOps, err := s.ensureController(ctx, controller)
		if err != nil {
			return err
		}
		ops = append(ops, controllerOps...)
		controllerUUIDByName[name] = controllerUUID
	}
	for _, bridge := range rows.Bridges {
		desiredBridgeSet[bridge.Name] = struct{}{}
		if len(bridge.Controller) > 0 {
			controllerUUIDs := make([]string, 0, len(bridge.Controller))
			for _, controllerName := range bridge.Controller {
				controllerUUID := controllerUUIDByName[controllerName]
				if controllerUUID == "" {
					return fmt.Errorf("provider bridge %s references unknown Controller %s", bridge.Name, controllerName)
				}
				controllerUUIDs = append(controllerUUIDs, controllerUUID)
			}
			sort.Strings(controllerUUIDs)
			bridge.Controller = controllerUUIDs
		}
		bridgeUUID, bridgeOps, err := s.ensureBridge(ctx, bridge)
		if err != nil {
			return err
		}
		ops = append(ops, bridgeOps...)
		desiredBridgeRefs = append(desiredBridgeRefs, bridgeUUID)
		portsByBridge[bridge.Name] = append([]string(nil), bridge.Ports...)
	}
	sort.Strings(desiredBridgeRefs)
	for _, queue := range rows.Queues {
		name := queue.ExternalIDs["netloom_provider_queue"]
		if name == "" {
			return fmt.Errorf("provider Queue row is missing netloom_provider_queue external ID")
		}
		desiredQueueSet[name] = struct{}{}
		queueUUID, queueOps, err := s.ensureQueue(ctx, queue)
		if err != nil {
			return err
		}
		ops = append(ops, queueOps...)
		queueUUIDByName[name] = queueUUID
	}
	for _, qos := range rows.QoS {
		name := qos.ExternalIDs["netloom_provider_qos"]
		if name == "" {
			return fmt.Errorf("provider QoS row is missing netloom_provider_qos external ID")
		}
		desiredQoSSet[name] = struct{}{}
		if len(qos.Queues) > 0 {
			queues := make(map[int]string, len(qos.Queues))
			for queueID, queueName := range qos.Queues {
				queueUUID := queueUUIDByName[queueName]
				if queueUUID == "" {
					return fmt.Errorf("provider QoS %s references unknown Queue %s", name, queueName)
				}
				queues[queueID] = queueUUID
			}
			qos.Queues = queues
		}
		qosUUID, qosOps, err := s.ensureQoS(ctx, qos)
		if err != nil {
			return err
		}
		ops = append(ops, qosOps...)
		qosUUIDByName[name] = qosUUID
	}

	for _, port := range rows.Ports {
		if port.QOS != nil {
			if qosUUID := qosUUIDByName[*port.QOS]; qosUUID != "" {
				port.QOS = &qosUUID
			}
		}
		portUUID, portOps, err := s.ensurePort(ctx, port)
		if err != nil {
			return err
		}
		ops = append(ops, portOps...)
		for bridgeName, names := range portsByBridge {
			if !containsProviderString(names, port.Name) {
				continue
			}
			bridge, ok, err := s.bridgeByName(ctx, bridgeName)
			if err != nil {
				return err
			}
			if !ok {
				bridge = &vswitch.Bridge{UUID: ovsdbProviderNamedUUID("bridge", bridgeName)}
			}
			attachOps, err := s.attachPortToBridge(ctx, bridge, portUUID)
			if err != nil {
				return err
			}
			ops = append(ops, attachOps...)
			detachOps, err := s.detachPortFromOtherBridges(ctx, bridge.Name, portUUID)
			if err != nil {
				return err
			}
			ops = append(ops, detachOps...)
		}
	}

	rootOps, err := s.updateOpenVSwitchRoot(openvSwitch, rows.OpenVSwitch.ExternalIDs, desiredBridgeRefs)
	if err != nil {
		return err
	}
	ops = append(ops, rootOps...)
	if cleanup {
		cleanupOps, err := s.cleanupStaleProviderBridges(ctx, desiredBridgeSet, openvSwitch.UUID)
		if err != nil {
			return err
		}
		ops = append(ops, cleanupOps...)
		qosOps, err := s.cleanupStaleProviderQoS(ctx, desiredQoSSet)
		if err != nil {
			return err
		}
		ops = append(ops, qosOps...)
		queueOps, err := s.cleanupStaleProviderQueues(ctx, desiredQueueSet)
		if err != nil {
			return err
		}
		ops = append(ops, queueOps...)
		controllerOps, err := s.cleanupStaleProviderControllers(ctx, desiredControllerSet)
		if err != nil {
			return err
		}
		ops = append(ops, controllerOps...)
	}
	return s.transact(ctx, "sync provider Open_vSwitch OVSDB rows", ops)
}

func (s *LibOVSDBProviderSyncer) ReadProviderOVSDBStatus(ctx context.Context, rows ProviderOVSDBDesiredRows) ([]ProviderOVSDBStatus, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("libovsdb provider syncer has no client")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	openvSwitch, _, err := s.openVSwitch(ctx)
	if err != nil {
		return nil, err
	}
	mappings := ""
	if openvSwitch != nil {
		mappings = openvSwitch.ExternalIDs["ovn-bridge-mappings"]
	}
	bridgeByName := make(map[string]vswitch.Bridge, len(rows.Bridges))
	for _, bridge := range rows.Bridges {
		bridgeByName[bridge.Name] = bridge
	}
	bridgeNameByPort := make(map[string]string, len(rows.Ports))
	providerByBridge := make(map[string]string, len(rows.Bridges))
	desiredQoSByName := make(map[string]vswitch.QoS, len(rows.QoS))
	desiredQueueByName := make(map[string]vswitch.Queue, len(rows.Queues))
	for _, qos := range rows.QoS {
		desiredQoSByName[qos.ExternalIDs["netloom_provider_qos"]] = qos
	}
	for _, queue := range rows.Queues {
		desiredQueueByName[queue.ExternalIDs["netloom_provider_queue"]] = queue
	}
	for _, bridge := range rows.Bridges {
		provider := bridge.ExternalIDs["netloom_provider_network"]
		providerByBridge[bridge.Name] = provider
		for _, port := range bridge.Ports {
			bridgeNameByPort[port] = bridge.Name
		}
	}
	statuses := make([]ProviderOVSDBStatus, 0, len(rows.Ports))
	for _, desiredPort := range rows.Ports {
		bridgeName := bridgeNameByPort[desiredPort.Name]
		spec, err := providerSpecFromDesiredPort(providerByBridge[bridgeName], desiredPort)
		if err != nil {
			return nil, err
		}
		status := ProviderOVSDBStatus{
			ProviderNetwork: spec.ProviderNetwork,
			Bridge:          bridgeName,
			LinkName:        spec.Name,
			ParentDevice:    spec.ParentDevice,
			VLAN:            spec.VLAN,
			BridgeState:     "up",
			MappingState:    "up",
			PortState:       "up",
			InterfaceState:  "up",
			QoSState:        "up",
			QueueState:      "up",
		}
		bridge, ok, err := s.bridgeByName(ctx, bridgeName)
		if err != nil {
			return nil, err
		}
		if !ok {
			status.BridgeState = "missing"
		} else {
			controllerState, err := s.bridgeControllerState(ctx, bridge, bridgeByName[bridgeName])
			if err != nil {
				return nil, err
			}
			status.ControllerState = controllerState
		}
		if !ovsBridgeMappingsContain(mappings, spec.ProviderNetwork, bridgeName) {
			status.MappingState = "missing"
		}
		port, ok, err := s.portByName(ctx, spec.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			status.PortState = "missing"
			status.InterfaceState = "missing"
			if desiredPort.QOS != nil {
				status.QoSState = "missing"
				status.QueueState = "missing"
			}
			statuses = append(statuses, status)
			continue
		}
		if status.BridgeState == "up" && !containsProviderString(bridge.Ports, port.UUID) {
			status.PortState = "bridge-mismatch"
		} else if !providerExternalIDsMatch(port.ExternalIDs, providerOVSDBLinkExternalIDs(spec)) {
			status.PortState = "external-ids-mismatch"
		}
		qosState, queueState, err := s.providerPortQoSState(ctx, port, desiredPort, desiredQoSByName, desiredQueueByName)
		if err != nil {
			return nil, err
		}
		status.QoSState = qosState
		status.QueueState = queueState
		iface, ok, err := s.interfaceByName(ctx, spec.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			status.InterfaceState = "missing"
		} else if !providerExternalIDsMatch(iface.ExternalIDs, providerOVSDBLinkExternalIDs(spec)) {
			status.InterfaceState = "external-ids-mismatch"
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (s *LibOVSDBProviderSyncer) ensureQoS(ctx context.Context, desired vswitch.QoS) (string, []ovsdb.Operation, error) {
	name := desired.ExternalIDs["netloom_provider_qos"]
	existing, ok, err := s.qosByProviderName(ctx, name)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		desired.UUID = ovsdbProviderNamedUUID("qos", name)
		ops, err := s.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create OVS QoS %s: %w", name, err)
		}
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeProviderManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	if existing.Type == desired.Type && reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(existing.OtherConfig, desired.OtherConfig) && reflect.DeepEqual(existing.Queues, desired.Queues) {
		return existing.UUID, nil, nil
	}
	existing.Type = desired.Type
	existing.ExternalIDs = nextExternalIDs
	existing.OtherConfig = desired.OtherConfig
	existing.Queues = desired.Queues
	ops, err := s.client.Where(existing).Update(existing, &existing.Type, &existing.ExternalIDs, &existing.OtherConfig, &existing.Queues)
	if err != nil {
		return "", nil, fmt.Errorf("update OVS QoS %s: %w", name, err)
	}
	return existing.UUID, ops, nil
}

func (s *LibOVSDBProviderSyncer) ensureQueue(ctx context.Context, desired vswitch.Queue) (string, []ovsdb.Operation, error) {
	name := desired.ExternalIDs["netloom_provider_queue"]
	existing, ok, err := s.queueByProviderName(ctx, name)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		desired.UUID = ovsdbProviderNamedUUID("queue", name)
		ops, err := s.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create OVS Queue %s: %w", name, err)
		}
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeProviderManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(existing.OtherConfig, desired.OtherConfig) && intPointersEqual(existing.DSCP, desired.DSCP) {
		return existing.UUID, nil, nil
	}
	existing.ExternalIDs = nextExternalIDs
	existing.OtherConfig = desired.OtherConfig
	existing.DSCP = desired.DSCP
	ops, err := s.client.Where(existing).Update(existing, &existing.ExternalIDs, &existing.OtherConfig, &existing.DSCP)
	if err != nil {
		return "", nil, fmt.Errorf("update OVS Queue %s: %w", name, err)
	}
	return existing.UUID, ops, nil
}

func (s *LibOVSDBProviderSyncer) ensureController(ctx context.Context, desired vswitch.Controller) (string, []ovsdb.Operation, error) {
	name := desired.ExternalIDs["netloom_provider_controller"]
	existing, ok, err := s.controllerByProviderName(ctx, name)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		desired.UUID = ovsdbProviderNamedUUID("controller", name)
		ops, err := s.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create OVS Controller %s: %w", name, err)
		}
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeProviderManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	if existing.Target == desired.Target && reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) {
		return existing.UUID, nil, nil
	}
	existing.Target = desired.Target
	existing.ExternalIDs = nextExternalIDs
	ops, err := s.client.Where(existing).Update(existing, &existing.Target, &existing.ExternalIDs)
	if err != nil {
		return "", nil, fmt.Errorf("update OVS Controller %s: %w", name, err)
	}
	return existing.UUID, ops, nil
}

func (s *LibOVSDBProviderSyncer) bridgeControllerState(ctx context.Context, bridge *vswitch.Bridge, desired vswitch.Bridge) (string, error) {
	if bridge == nil || len(bridge.Controller) == 0 {
		if len(desired.Controller) > 0 {
			return "missing", nil
		}
		return "", nil
	}
	if len(desired.Controller) > 0 {
		actualTargets := make(map[string]struct{}, len(bridge.Controller))
		for _, controllerUUID := range bridge.Controller {
			controller, ok, err := s.controllerByUUID(ctx, controllerUUID)
			if err != nil {
				return "", err
			}
			if !ok {
				return "missing", nil
			}
			actualTargets[controller.Target] = struct{}{}
		}
		for _, controllerName := range desired.Controller {
			desiredController, ok, err := s.controllerByProviderName(ctx, controllerName)
			if err != nil {
				return "", err
			}
			if !ok {
				return "missing", nil
			}
			if _, ok := actualTargets[desiredController.Target]; !ok {
				return "target-mismatch", nil
			}
		}
	}
	connected := false
	for _, controllerUUID := range bridge.Controller {
		controller, ok, err := s.controllerByUUID(ctx, controllerUUID)
		if err != nil {
			return "", err
		}
		if !ok {
			return "missing", nil
		}
		if controller.IsConnected {
			connected = true
		}
	}
	if connected {
		return "up", nil
	}
	return "disconnected", nil
}

func (s *LibOVSDBProviderSyncer) controllerByProviderName(ctx context.Context, name string) (*vswitch.Controller, bool, error) {
	var rows []vswitch.Controller
	if err := s.client.WhereCache(func(row *vswitch.Controller) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" && row.ExternalIDs["netloom_provider_controller"] == name
	}).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS controller %s: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) controllerByUUID(ctx context.Context, uuid string) (*vswitch.Controller, bool, error) {
	var rows []vswitch.Controller
	if err := s.client.WhereCache(func(row *vswitch.Controller) bool { return row.UUID == uuid }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS controller %s: %w", uuid, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) ensureBridge(ctx context.Context, desired vswitch.Bridge) (string, []ovsdb.Operation, error) {
	existing, ok, err := s.bridgeByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		desired.UUID = ovsdbProviderNamedUUID("bridge", desired.Name)
		desired.Ports = nil
		ops, err := s.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create OVS bridge %s: %w", desired.Name, err)
		}
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeProviderManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	nextController := desired.Controller
	if len(nextController) == 0 {
		nextController, err = s.nonManagedControllerRefs(ctx, existing.Controller)
		if err != nil {
			return "", nil, err
		}
	}
	if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(sortedUniqueStrings(existing.Controller), sortedUniqueStrings(nextController)) {
		return existing.UUID, nil, nil
	}
	existing.ExternalIDs = nextExternalIDs
	existing.Controller = sortedUniqueStrings(nextController)
	ops, err := s.client.Where(existing).Update(existing, &existing.ExternalIDs, &existing.Controller)
	if err != nil {
		return "", nil, fmt.Errorf("update OVS bridge %s: %w", desired.Name, err)
	}
	return existing.UUID, ops, nil
}

func (s *LibOVSDBProviderSyncer) ensurePort(ctx context.Context, desired vswitch.Port) (string, []ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	interfaceUUID, interfaceOps, err := s.ensureInterface(ctx, vswitch.Interface{
		Name:        desired.Name,
		ExternalIDs: desired.ExternalIDs,
	})
	if err != nil {
		return "", nil, err
	}
	ops = append(ops, interfaceOps...)
	desired.Interfaces = []string{interfaceUUID}
	existing, ok, err := s.portByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		desired.UUID = ovsdbProviderNamedUUID("port", desired.Name)
		createOps, err := s.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create OVS port %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeProviderManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	nextInterfaces := sortedUniqueStrings(append(existing.Interfaces, interfaceUUID))
	nextQOS := desired.QOS
	if desired.QOS == nil && existing.QOS != nil {
		managed, err := s.qosUUIDIsNetloomManaged(ctx, *existing.QOS)
		if err != nil {
			return "", nil, err
		}
		if !managed {
			nextQOS = existing.QOS
		}
	}
	if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(sortedUniqueStrings(existing.Interfaces), nextInterfaces) && stringPointersEqual(existing.QOS, nextQOS) {
		return existing.UUID, ops, nil
	}
	existing.ExternalIDs = nextExternalIDs
	existing.Interfaces = nextInterfaces
	existing.QOS = nextQOS
	updateOps, err := s.client.Where(existing).Update(existing, &existing.ExternalIDs, &existing.Interfaces, &existing.QOS)
	if err != nil {
		return "", nil, fmt.Errorf("update OVS port %s: %w", desired.Name, err)
	}
	ops = append(ops, updateOps...)
	return existing.UUID, ops, nil
}

func (s *LibOVSDBProviderSyncer) nonManagedControllerRefs(ctx context.Context, controllerUUIDs []string) ([]string, error) {
	if len(controllerUUIDs) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(controllerUUIDs))
	for _, controllerUUID := range controllerUUIDs {
		controller, ok, err := s.controllerByUUID(ctx, controllerUUID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if controller.ExternalIDs["netloom_owner"] == "netloom" && controller.ExternalIDs["netloom_provider_controller"] != "" {
			continue
		}
		out = append(out, controllerUUID)
	}
	return sortedUniqueStrings(out), nil
}

func (s *LibOVSDBProviderSyncer) ensureInterface(ctx context.Context, desired vswitch.Interface) (string, []ovsdb.Operation, error) {
	existing, ok, err := s.interfaceByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		desired.UUID = ovsdbProviderNamedUUID("interface", desired.Name)
		ops, err := s.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create OVS interface %s: %w", desired.Name, err)
		}
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeProviderManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) {
		return existing.UUID, nil, nil
	}
	existing.ExternalIDs = nextExternalIDs
	ops, err := s.client.Where(existing).Update(existing, &existing.ExternalIDs)
	if err != nil {
		return "", nil, fmt.Errorf("update OVS interface %s external IDs: %w", desired.Name, err)
	}
	return existing.UUID, ops, nil
}

func (s *LibOVSDBProviderSyncer) attachPortToBridge(_ context.Context, bridge *vswitch.Bridge, portUUID string) ([]ovsdb.Operation, error) {
	if containsProviderString(bridge.Ports, portUUID) {
		return nil, nil
	}
	return s.client.Where(bridge).Mutate(bridge, ovsmodel.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{portUUID},
	})
}

func (s *LibOVSDBProviderSyncer) detachPortFromOtherBridges(ctx context.Context, keepBridge string, portUUID string) ([]ovsdb.Operation, error) {
	var bridges []vswitch.Bridge
	if err := s.client.WhereCache(func(row *vswitch.Bridge) bool {
		return row.Name != keepBridge && containsProviderString(row.Ports, portUUID)
	}).List(ctx, &bridges); err != nil {
		return nil, fmt.Errorf("list OVS bridges containing port %s: %w", portUUID, err)
	}
	var ops []ovsdb.Operation
	for i := range bridges {
		nextOps, err := s.client.Where(&bridges[i]).Mutate(&bridges[i], ovsmodel.Mutation{
			Field:   &bridges[i].Ports,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{portUUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach OVS port %s from bridge %s: %w", portUUID, bridges[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) updateOpenVSwitchRoot(root *vswitch.OpenvSwitch, externalIDs map[string]string, bridgeUUIDs []string) ([]ovsdb.Operation, error) {
	nextExternalIDs := mergeProviderStringMap(root.ExternalIDs, externalIDs)
	nextBridges := sortedUniqueStrings(append(root.Bridges, bridgeUUIDs...))
	if reflect.DeepEqual(root.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(sortedUniqueStrings(root.Bridges), nextBridges) {
		return nil, nil
	}
	root.ExternalIDs = nextExternalIDs
	root.Bridges = nextBridges
	return s.client.Where(root).Update(root, &root.ExternalIDs, &root.Bridges)
}

func (s *LibOVSDBProviderSyncer) cleanupStaleProviderBridges(ctx context.Context, desired map[string]struct{}, rootUUID string) ([]ovsdb.Operation, error) {
	var bridges []vswitch.Bridge
	if err := s.client.WhereCache(func(row *vswitch.Bridge) bool {
		if row.ExternalIDs["netloom_owner"] != "netloom" {
			return false
		}
		_, ok := desired[row.Name]
		return !ok
	}).List(ctx, &bridges); err != nil {
		return nil, fmt.Errorf("list stale OVS provider bridges: %w", err)
	}
	var ops []ovsdb.Operation
	for i := range bridges {
		root := &vswitch.OpenvSwitch{UUID: rootUUID}
		detachOps, err := s.client.Where(root).Mutate(root, ovsmodel.Mutation{
			Field:   &root.Bridges,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{bridges[i].UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach stale OVS bridge %s from Open_vSwitch: %w", bridges[i].Name, err)
		}
		ops = append(ops, detachOps...)
		for _, portUUID := range bridges[i].Ports {
			port, ok, err := s.portByUUID(ctx, portUUID)
			if err != nil {
				return nil, err
			}
			if ok {
				for _, interfaceUUID := range port.Interfaces {
					iface := &vswitch.Interface{UUID: interfaceUUID}
					deleteIfaceOps, err := s.client.Where(iface).Delete()
					if err != nil {
						return nil, fmt.Errorf("delete stale OVS interface %s: %w", interfaceUUID, err)
					}
					ops = append(ops, deleteIfaceOps...)
				}
				if port.QOS != nil {
					deleteQOSOps, err := s.deleteQoSIfManaged(ctx, *port.QOS)
					if err != nil {
						return nil, err
					}
					ops = append(ops, deleteQOSOps...)
				}
				deletePortOps, err := s.client.Where(port).Delete()
				if err != nil {
					return nil, fmt.Errorf("delete stale OVS port %s: %w", port.Name, err)
				}
				ops = append(ops, deletePortOps...)
			}
		}
		deleteBridgeOps, err := s.client.Where(&bridges[i]).Delete()
		if err != nil {
			return nil, fmt.Errorf("delete stale OVS bridge %s: %w", bridges[i].Name, err)
		}
		ops = append(ops, deleteBridgeOps...)
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) cleanupStaleProviderQoS(ctx context.Context, desired map[string]struct{}) ([]ovsdb.Operation, error) {
	var rows []vswitch.QoS
	if err := s.client.WhereCache(func(row *vswitch.QoS) bool {
		if row.ExternalIDs["netloom_owner"] != "netloom" || row.ExternalIDs["netloom_provider_qos"] == "" {
			return false
		}
		_, ok := desired[row.ExternalIDs["netloom_provider_qos"]]
		return !ok
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list stale OVS provider QoS rows: %w", err)
	}
	var ops []ovsdb.Operation
	for i := range rows {
		deleteOps, err := s.client.Where(&rows[i]).Delete()
		if err != nil {
			return nil, fmt.Errorf("delete stale OVS provider QoS %s: %w", rows[i].ExternalIDs["netloom_provider_qos"], err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) cleanupStaleProviderQueues(ctx context.Context, desired map[string]struct{}) ([]ovsdb.Operation, error) {
	var rows []vswitch.Queue
	if err := s.client.WhereCache(func(row *vswitch.Queue) bool {
		if row.ExternalIDs["netloom_owner"] != "netloom" || row.ExternalIDs["netloom_provider_queue"] == "" {
			return false
		}
		_, ok := desired[row.ExternalIDs["netloom_provider_queue"]]
		return !ok
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list stale OVS provider Queue rows: %w", err)
	}
	var ops []ovsdb.Operation
	for i := range rows {
		deleteOps, err := s.client.Where(&rows[i]).Delete()
		if err != nil {
			return nil, fmt.Errorf("delete stale OVS provider Queue %s: %w", rows[i].ExternalIDs["netloom_provider_queue"], err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) cleanupStaleProviderControllers(ctx context.Context, desired map[string]struct{}) ([]ovsdb.Operation, error) {
	var rows []vswitch.Controller
	if err := s.client.WhereCache(func(row *vswitch.Controller) bool {
		if row.ExternalIDs["netloom_owner"] != "netloom" || row.ExternalIDs["netloom_provider_controller"] == "" {
			return false
		}
		_, ok := desired[row.ExternalIDs["netloom_provider_controller"]]
		return !ok
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list stale OVS provider Controller rows: %w", err)
	}
	var ops []ovsdb.Operation
	for i := range rows {
		detachOps, err := s.detachControllerFromBridges(ctx, rows[i].UUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, detachOps...)
		deleteOps, err := s.client.Where(&rows[i]).Delete()
		if err != nil {
			return nil, fmt.Errorf("delete stale OVS provider Controller %s: %w", rows[i].ExternalIDs["netloom_provider_controller"], err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) detachControllerFromBridges(ctx context.Context, controllerUUID string) ([]ovsdb.Operation, error) {
	var bridges []vswitch.Bridge
	if err := s.client.WhereCache(func(row *vswitch.Bridge) bool {
		return containsProviderString(row.Controller, controllerUUID)
	}).List(ctx, &bridges); err != nil {
		return nil, fmt.Errorf("list OVS bridges containing controller %s: %w", controllerUUID, err)
	}
	var ops []ovsdb.Operation
	for i := range bridges {
		nextOps, err := s.client.Where(&bridges[i]).Mutate(&bridges[i], ovsmodel.Mutation{
			Field:   &bridges[i].Controller,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{controllerUUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach OVS controller %s from bridge %s: %w", controllerUUID, bridges[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) openVSwitch(ctx context.Context) (*vswitch.OpenvSwitch, bool, error) {
	var rows []vswitch.OpenvSwitch
	if err := s.client.List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list Open_vSwitch rows: %w", err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) bridgeByName(ctx context.Context, name string) (*vswitch.Bridge, bool, error) {
	var rows []vswitch.Bridge
	if err := s.client.WhereCache(func(row *vswitch.Bridge) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS bridge %s: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) portByName(ctx context.Context, name string) (*vswitch.Port, bool, error) {
	var rows []vswitch.Port
	if err := s.client.WhereCache(func(row *vswitch.Port) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS port %s: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) portByUUID(ctx context.Context, uuid string) (*vswitch.Port, bool, error) {
	var rows []vswitch.Port
	if err := s.client.WhereCache(func(row *vswitch.Port) bool { return row.UUID == uuid }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS port %s: %w", uuid, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) interfaceByName(ctx context.Context, name string) (*vswitch.Interface, bool, error) {
	var rows []vswitch.Interface
	if err := s.client.WhereCache(func(row *vswitch.Interface) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS interface %s: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) qosByProviderName(ctx context.Context, name string) (*vswitch.QoS, bool, error) {
	var rows []vswitch.QoS
	if err := s.client.WhereCache(func(row *vswitch.QoS) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" && row.ExternalIDs["netloom_provider_qos"] == name
	}).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS QoS %s: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) qosByUUID(ctx context.Context, uuid string) (*vswitch.QoS, bool, error) {
	var rows []vswitch.QoS
	if err := s.client.WhereCache(func(row *vswitch.QoS) bool { return row.UUID == uuid }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS QoS %s: %w", uuid, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) queueByProviderName(ctx context.Context, name string) (*vswitch.Queue, bool, error) {
	var rows []vswitch.Queue
	if err := s.client.WhereCache(func(row *vswitch.Queue) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" && row.ExternalIDs["netloom_provider_queue"] == name
	}).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS Queue %s: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) queueByUUID(ctx context.Context, uuid string) (*vswitch.Queue, bool, error) {
	var rows []vswitch.Queue
	if err := s.client.WhereCache(func(row *vswitch.Queue) bool { return row.UUID == uuid }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list OVS Queue %s: %w", uuid, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &rows[0], true, nil
}

func (s *LibOVSDBProviderSyncer) qosUUIDIsNetloomManaged(ctx context.Context, uuid string) (bool, error) {
	qos, ok, err := s.qosByUUID(ctx, uuid)
	if err != nil || !ok {
		return false, err
	}
	return qos.ExternalIDs["netloom_owner"] == "netloom" && qos.ExternalIDs["netloom_provider_qos"] != "", nil
}

func (s *LibOVSDBProviderSyncer) deleteQoSIfManaged(ctx context.Context, uuid string) ([]ovsdb.Operation, error) {
	qos, ok, err := s.qosByUUID(ctx, uuid)
	if err != nil || !ok {
		return nil, err
	}
	if qos.ExternalIDs["netloom_owner"] != "netloom" || qos.ExternalIDs["netloom_provider_qos"] == "" {
		return nil, nil
	}
	var ops []ovsdb.Operation
	deleteOps, err := s.client.Where(qos).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete OVS QoS %s: %w", uuid, err)
	}
	ops = append(ops, deleteOps...)
	for _, queueUUID := range qos.Queues {
		queue, ok, err := s.queueByUUID(ctx, queueUUID)
		if err != nil {
			return nil, err
		}
		if ok && queue.ExternalIDs["netloom_owner"] == "netloom" && queue.ExternalIDs["netloom_provider_queue"] != "" {
			deleteQueueOps, err := s.client.Where(queue).Delete()
			if err != nil {
				return nil, fmt.Errorf("delete OVS Queue %s: %w", queueUUID, err)
			}
			ops = append(ops, deleteQueueOps...)
		}
	}
	return ops, nil
}

func (s *LibOVSDBProviderSyncer) transact(ctx context.Context, label string, ops []ovsdb.Operation) error {
	if len(ops) == 0 {
		return nil
	}
	results, err := s.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("%s operation errors=%+v: %w", label, opErrors, err)
	}
	return nil
}

func ovsdbProviderNamedUUID(parts ...string) string {
	name := strings.Join(parts, "_")
	name = strings.NewReplacer("-", "_", ".", "_", "/", "_", "|", "_").Replace(name)
	return "@nl_provider_" + name
}

func mergeProviderStringMap(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func mergeProviderManagedExternalIDs(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		if strings.HasPrefix(key, "netloom_") {
			continue
		}
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func sortedUniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsProviderString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func providerSpecFromDesiredPort(providerNetwork string, port vswitch.Port) (providerNetworkLinkSpec, error) {
	parent := port.ExternalIDs["netloom_parent_device"]
	vlanRaw := port.ExternalIDs["netloom_vlan"]
	if providerNetwork == "" {
		providerNetwork = port.ExternalIDs["netloom_provider_network"]
	}
	if providerNetwork == "" || parent == "" || vlanRaw == "" || port.Name == "" {
		return providerNetworkLinkSpec{}, fmt.Errorf("provider OVSDB desired port %s is missing Netloom external IDs", port.Name)
	}
	vlan, err := strconv.Atoi(vlanRaw)
	if err != nil || vlan < 0 || vlan > 4095 {
		return providerNetworkLinkSpec{}, fmt.Errorf("provider OVSDB desired port %s has invalid VLAN %q", port.Name, vlanRaw)
	}
	return providerNetworkLinkSpec{
		ProviderNetwork: providerNetwork,
		ParentDevice:    parent,
		VLAN:            uint16(vlan),
		Name:            port.Name,
		QoS:             providerQoSFromDesiredPort(port),
	}, nil
}

func providerQoSFromDesiredPort(port vswitch.Port) netloommodel.ProviderNetworkQoS {
	var qos netloommodel.ProviderNetworkQoS
	rateRaw := port.ExternalIDs["netloom_provider_qos_egress_rate_bps"]
	if rateRaw != "" {
		rate, err := strconv.ParseUint(rateRaw, 10, 64)
		if err == nil {
			qos.EgressRateBPS = rate
		}
	}
	burstRaw := port.ExternalIDs["netloom_provider_qos_egress_burst_bps"]
	if burstRaw != "" {
		burst, err := strconv.ParseUint(burstRaw, 10, 64)
		if err == nil {
			qos.EgressBurstBPS = burst
		}
	}
	return qos
}

func (s *LibOVSDBProviderSyncer) providerPortQoSState(ctx context.Context, port *vswitch.Port, desiredPort vswitch.Port, desiredQoSByName map[string]vswitch.QoS, desiredQueueByName map[string]vswitch.Queue) (string, string, error) {
	if desiredPort.QOS == nil {
		if port.QOS == nil {
			return "up", "up", nil
		}
		managed, err := s.qosUUIDIsNetloomManaged(ctx, *port.QOS)
		if err != nil {
			return "", "", err
		}
		if managed {
			return "unexpected", "up", nil
		}
		return "up", "up", nil
	}
	if port.QOS == nil {
		return "missing", "missing", nil
	}
	desiredQoS, ok := desiredQoSByName[*desiredPort.QOS]
	if !ok {
		return "", "", fmt.Errorf("desired OVS port %s references unknown QoS %s", desiredPort.Name, *desiredPort.QOS)
	}
	qos, ok, err := s.qosByUUID(ctx, *port.QOS)
	if err != nil || !ok {
		if err != nil {
			return "", "", err
		}
		return "missing", "missing", nil
	}
	if qos.Type != desiredQoS.Type || !providerExternalIDsMatch(qos.ExternalIDs, desiredQoS.ExternalIDs) || !providerStringMapsEqual(qos.OtherConfig, desiredQoS.OtherConfig) {
		return "mismatch", providerQueueStateForDesiredQoS(ctx, s, qos, desiredQoS, desiredQueueByName), nil
	}
	if len(qos.Queues) != len(desiredQoS.Queues) {
		return "up", "mismatch", nil
	}
	for queueID, desiredQueueName := range desiredQoS.Queues {
		queueUUID := qos.Queues[queueID]
		if queueUUID == "" {
			return "up", "missing", nil
		}
		desiredQueue, ok := desiredQueueByName[desiredQueueName]
		if !ok {
			return "", "", fmt.Errorf("desired OVS QoS %s references unknown Queue %s", *desiredPort.QOS, desiredQueueName)
		}
		queue, ok, err := s.queueByUUID(ctx, queueUUID)
		if err != nil || !ok {
			if err != nil {
				return "", "", err
			}
			return "up", "missing", nil
		}
		if !providerExternalIDsMatch(queue.ExternalIDs, desiredQueue.ExternalIDs) || !providerStringMapsEqual(queue.OtherConfig, desiredQueue.OtherConfig) || !intPointersEqual(queue.DSCP, desiredQueue.DSCP) {
			return "up", "mismatch", nil
		}
	}
	return "up", "up", nil
}

func providerQueueStateForDesiredQoS(ctx context.Context, s *LibOVSDBProviderSyncer, qos *vswitch.QoS, desiredQoS vswitch.QoS, desiredQueueByName map[string]vswitch.Queue) string {
	for queueID, desiredQueueName := range desiredQoS.Queues {
		queueUUID := qos.Queues[queueID]
		if queueUUID == "" {
			return "missing"
		}
		desiredQueue, ok := desiredQueueByName[desiredQueueName]
		if !ok {
			return "mismatch"
		}
		queue, ok, err := s.queueByUUID(ctx, queueUUID)
		if err != nil || !ok {
			return "missing"
		}
		if !providerExternalIDsMatch(queue.ExternalIDs, desiredQueue.ExternalIDs) || !providerStringMapsEqual(queue.OtherConfig, desiredQueue.OtherConfig) || !intPointersEqual(queue.DSCP, desiredQueue.DSCP) {
			return "mismatch"
		}
	}
	return "up"
}

func stringPointersEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func intPointersEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func providerExternalIDsMatch(got map[string]string, want map[string]string) bool {
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	for key := range got {
		if !strings.HasPrefix(key, "netloom_") {
			continue
		}
		if _, ok := want[key]; !ok {
			return false
		}
	}
	return true
}

func providerStringMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}
