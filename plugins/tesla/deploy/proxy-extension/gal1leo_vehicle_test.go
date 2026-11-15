// Copyright 2026 GAL1LEO. Apache-2.0. Synthetic commands only.
package vehicle

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/connector"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	carserver "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	ext "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/gal1leo"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

func TestGal1leoGoldenWireContracts(t *testing.T) {
	// GPS and Supercharger bytes independently published by Teslemetry's Python
	// and TypeScript fixtures at commit 452c0ddd. Others pin the reviewed field
	// numbers/enums; these tests are wire compatibility, not vehicle qualification.
	cases := []struct {
		name, hex string
		build     func() (*ext.VehicleAction, error)
	}{
		{"gps", "1215aa0312090000000000c04240110000000000905ec0", func() (*ext.VehicleAction, error) { return gal1leoGPS(37.5, -122.25, 0) }},
		{"gps_origin", "1203aa0300", func() (*ext.VehicleAction, error) { return gal1leoGPS(0, 0, 0) }},
		{"supercharger_replace", "1209b2010608c0c4071001", func() (*ext.VehicleAction, error) { return gal1leoSupercharger(123456, 1) }},
		{"supercharger_prepend", "120bb2010808b1d1f9d6031002", func() (*ext.VehicleAction, error) { return gal1leoSupercharger(987654321, 2) }},
		{"supercharger_append", "1207b2010408011003", func() (*ext.VehicleAction, error) { return gal1leoSupercharger(1, 3) }},
		{"waypoints", "1206d205030a0178", func() (*ext.VehicleAction, error) { return gal1leoWaypoints("x", nil, nil) }},
		{"waypoints_options", "120ad205070a017812021014", func() (*ext.VehicleAction, error) { z, n := int32(0), int32(20); return gal1leoWaypoints("x", &z, &n) }},
		{"auto_heat_off", "1203b20400", func() (*ext.VehicleAction, error) { return gal1leoAutoHeat(false), nil }},
		{"heat_off", "1205ba04020801", func() (*ext.VehicleAction, error) { return gal1leoHeatLevel(0) }},
		{"heat_low", "1205ba04020802", func() (*ext.VehicleAction, error) { return gal1leoHeatLevel(1) }},
		{"heat_high", "1205ba04020803", func() (*ext.VehicleAction, error) { return gal1leoHeatLevel(3) }},
		{"boombox", "120682040308d00f", func() (*ext.VehicleAction, error) { return gal1leoBoombox(2000) }},
		{"calendar", "1206c201030a0178", func() (*ext.VehicleAction, error) { return gal1leoCalendar("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			action, err := c.build()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := proto.Marshal(&ext.Action{VehicleAction: action})
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(wire) != c.hex {
				t.Fatalf("wire %x, wanted %s", wire, c.hex)
			}
			var decoded ext.Action
			if err = proto.Unmarshal(wire, &decoded); err != nil || !proto.Equal(action, decoded.VehicleAction) {
				t.Fatal("round trip", err)
			}
		})
	}
}

type gal1leoDispatch struct {
	*testSender
	count   int
	message *universal.RoutableMessage
	auth    connector.AuthMethod
}

func (s *gal1leoDispatch) Send(ctx context.Context, m *universal.RoutableMessage, a connector.AuthMethod) (protocol.Receiver, error) {
	s.count++
	s.message = proto.Clone(m).(*universal.RoutableMessage)
	s.auth = a
	return s.testSender.Send(ctx, m, a)
}

func TestGal1leoPinnedDeparturePayload(t *testing.T) {
	// The dispatcher is entirely in memory. Decode the actual SDK message,
	// including its oneof, without opening a network or vehicle connection.
	for _, c := range []struct {
		name   string
		policy ChargingPolicy
		clear  bool
	}{
		{"weekdays", ChargingPolicyWeekdays, false},
		{"all_days", ChargingPolicyAllDays, false},
		{"preconditioning_off", ChargingPolicyOff, false},
		{"schedule_disabled", ChargingPolicyOff, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			response, _ := proto.Marshal(&carserver.Response{ActionStatus: &carserver.ActionStatus{}})
			dispatcher := &gal1leoDispatch{testSender: newTestSender()}
			dispatcher.fixedResponse = &universal.RoutableMessage{Payload: &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: response}}
			v := &Vehicle{dispatcher: dispatcher, authMethod: connector.AuthMethodHMAC}
			var err error
			if c.clear {
				err = v.ClearScheduledDeparture(context.Background())
			} else {
				err = v.ScheduleDeparture(context.Background(), 420*time.Minute, 0, c.policy, ChargingPolicyOff)
			}
			if err != nil || dispatcher.count != 1 {
				t.Fatal("synthetic dispatch", dispatcher.count, err)
			}
			var action carserver.Action
			if err = proto.Unmarshal(dispatcher.message.GetProtobufMessageAsBytes(), &action); err != nil {
				t.Fatal(err)
			}
			schedule := action.GetVehicleAction().GetScheduledDepartureAction()
			if schedule == nil || schedule.Enabled == c.clear {
				t.Fatal("wrong enabled state", schedule)
			}
			if c.clear {
				if schedule.DepartureTime != 0 || schedule.PreconditioningTimes != nil {
					t.Fatal("disabled schedule has unused settings", schedule)
				}
				return
			}
			if schedule.DepartureTime != 420 {
				t.Fatal("wrong departure time", schedule)
			}
			switch c.policy {
			case ChargingPolicyWeekdays:
				if schedule.GetPreconditioningTimes().GetWeekdays() == nil {
					t.Fatal("weekday oneof missing", schedule)
				}
			case ChargingPolicyAllDays:
				if schedule.GetPreconditioningTimes().GetAllWeek() == nil {
					t.Fatal("all-days oneof missing", schedule)
				}
			case ChargingPolicyOff:
				if schedule.PreconditioningTimes != nil {
					t.Fatal("disabled preconditioning has a oneof", schedule)
				}
			}
		})
	}
}

func TestGal1leoUsesOfficialAuthenticatedSend(t *testing.T) {
	for _, call := range []func(*Vehicle) error{
		func(v *Vehicle) error { return v.Gal1leoNavigateGPS(context.Background(), 0, 0, 1) },
		func(v *Vehicle) error { return v.Gal1leoNavigateSupercharger(context.Background(), 1, 1) },
		func(v *Vehicle) error { return v.Gal1leoNavigateWaypoints(context.Background(), "synthetic", nil, nil) },
		func(v *Vehicle) error { return v.Gal1leoAutoSteeringWheelHeat(context.Background(), false) },
		func(v *Vehicle) error { return v.Gal1leoSteeringWheelHeatLevel(context.Background(), 0) },
		func(v *Vehicle) error { return v.Gal1leoBoombox(context.Background(), 0) },
		func(v *Vehicle) error { return v.Gal1leoCalendar(context.Background(), "synthetic") },
	} {
		response, _ := proto.Marshal(&carserver.Response{ActionStatus: &carserver.ActionStatus{}})
		dispatcher := &gal1leoDispatch{testSender: newTestSender()}
		dispatcher.fixedResponse = &universal.RoutableMessage{Payload: &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: response}}
		v := &Vehicle{dispatcher: dispatcher, authMethod: connector.AuthMethodHMAC}
		if err := call(v); err != nil {
			t.Fatal(err)
		}
		if dispatcher.count != 1 || dispatcher.auth != connector.AuthMethodHMAC || dispatcher.message.GetToDestination().GetDomain() != universal.Domain_DOMAIN_INFOTAINMENT {
			t.Fatal("wrong signing/dispatch contract")
		}
		var action ext.Action
		if err := proto.Unmarshal(dispatcher.message.GetProtobufMessageAsBytes(), &action); err != nil || action.GetVehicleAction().GetAction() == nil {
			t.Fatal("missing typed action", err)
		}
	}
}

func TestGal1leoUncertainSendNotRetried(t *testing.T) {
	sentinel := &protocol.CommandError{Err: errors.New("synthetic connection lost"), PossibleSuccess: true, PossibleTemporary: true}
	dispatcher := &gal1leoDispatch{testSender: newTestSender()}
	dispatcher.SendError = sentinel
	v := &Vehicle{dispatcher: dispatcher, authMethod: connector.AuthMethodHMAC}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := v.Gal1leoBoombox(ctx, 0); err != sentinel || dispatcher.count != 1 {
		t.Fatal("uncertain action retried", dispatcher.count, err)
	}
}

func TestGal1leoResponseDoesNotInventAcceptance(t *testing.T) {
	for _, wire := range [][]byte{nil, {0xff}, {0x22, 0}} {
		var uncertain *protocol.CommandError
		if err := gal1leoResponse(wire); !errors.As(err, &uncertain) || !uncertain.MayHaveSucceeded() || protocol.ShouldRetry(err) {
			t.Fatal("missing/invalid response must remain uncertain", err)
		}
	}
	rejected, _ := proto.Marshal(&carserver.Response{ActionStatus: &carserver.ActionStatus{Result: carserver.OperationStatus_E_OPERATIONSTATUS_ERROR}})
	if err := gal1leoResponse(rejected); !protocol.IsNominalError(err) || protocol.ShouldRetry(err) {
		t.Fatal(err)
	}
}
