// Copyright 2026 GAL1LEO. Licensed under the Apache License, Version 2.0.
// Additive typed commands: official Vehicle.Send handles authentication, session
// and transport. The public wire-contract provenance is in GAL1LEO-NOTICE.txt.
package vehicle

import (
	"context"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/teslamotors/vehicle-command/pkg/protocol"
	carserver "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	ext "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/gal1leo"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"google.golang.org/protobuf/proto"
)

// These functions accept seven closed, typed messages, never arbitrary wire
// bytes. A successful response is command acceptance, not physical verification.
func (v *Vehicle) executeGal1leoAction(ctx context.Context, action *ext.VehicleAction) error {
	payload, err := proto.Marshal(&ext.Action{VehicleAction: action})
	if err != nil {
		return err
	}
	response, err := v.Send(ctx, universal.Domain_DOMAIN_INFOTAINMENT, payload, v.authMethod)
	if err != nil {
		return err
	}
	return gal1leoResponse(response)
}

func gal1leoResponse(payload []byte) error {
	var response carserver.Response
	if err := proto.Unmarshal(payload, &response); err != nil || response.GetActionStatus() == nil {
		return &protocol.CommandError{Err: fmt.Errorf("invalid extended command response"), PossibleSuccess: true}
	}
	switch response.GetActionStatus().GetResult() {
	case carserver.OperationStatus_E_OPERATIONSTATUS_OK:
		return nil
	case carserver.OperationStatus_E_OPERATIONSTATUS_ERROR:
		// Do not echo calendar text, coordinates or arbitrary firmware error strings.
		return &protocol.NominalError{Details: protocol.NewError("vehicle rejected extended command", false, false)}
	default:
		return &protocol.CommandError{Err: fmt.Errorf("unknown extended command response"), PossibleSuccess: true}
	}
}

func gal1leoOrder(order int32) bool { return order >= 0 && order <= 3 }
func gal1leoText(value string) bool {
	return utf8.ValidString(value) && len(value) <= 16384 && len(strings.TrimSpace(value)) > 0 && !strings.ContainsRune(value, 0)
}

func gal1leoGPS(lat, lon float64, order int32) (*ext.VehicleAction, error) {
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) || lat < -90 || lat > 90 || lon < -180 || lon > 180 || !gal1leoOrder(order) {
		return nil, fmt.Errorf("invalid navigation coordinates or order")
	}
	return &ext.VehicleAction{Action: &ext.VehicleAction_NavigationGps{NavigationGps: &ext.NavigationGpsRequest{Lat: lat, Lon: lon, Order: ext.TripOrder(order)}}}, nil
}
func (v *Vehicle) Gal1leoNavigateGPS(ctx context.Context, lat, lon float64, order int32) error {
	action, err := gal1leoGPS(lat, lon, order)
	if err != nil {
		return err
	}
	return v.executeGal1leoAction(ctx, action)
}

func gal1leoSupercharger(id int64, order int32) (*ext.VehicleAction, error) {
	// HTTP JSON numbers must be exactly representable before conversion to int64.
	if id <= 0 || id > 9007199254740991 || !gal1leoOrder(order) {
		return nil, fmt.Errorf("invalid supercharger id or order")
	}
	return &ext.VehicleAction{Action: &ext.VehicleAction_NavigationSupercharger{NavigationSupercharger: &ext.NavigationSuperchargerRequest{Id: id, Order: ext.TripOrder(order)}}}, nil
}
func (v *Vehicle) Gal1leoNavigateSupercharger(ctx context.Context, id int64, order int32) error {
	action, err := gal1leoSupercharger(id, order)
	if err != nil {
		return err
	}
	return v.executeGal1leoAction(ctx, action)
}

func gal1leoWaypoints(waypoints string, start, arrival *int32) (*ext.VehicleAction, error) {
	if !gal1leoText(waypoints) {
		return nil, fmt.Errorf("invalid waypoints")
	}
	for _, value := range []*int32{start, arrival} {
		if value != nil && (*value < 0 || *value > 100) {
			return nil, fmt.Errorf("invalid trip energy percent")
		}
	}
	request := &ext.NavigationWaypointsRequest{Waypoints: waypoints}
	if start != nil || arrival != nil {
		request.TripPlanOptions = &ext.NavigationWaypointsRequest_TripPlanOptions{}
		if start != nil {
			request.TripPlanOptions.DestinationStartSoe = *start
		}
		if arrival != nil {
			request.TripPlanOptions.DestinationArrivalSoe = *arrival
		}
	}
	return &ext.VehicleAction{Action: &ext.VehicleAction_NavigationWaypoints{NavigationWaypoints: request}}, nil
}
func (v *Vehicle) Gal1leoNavigateWaypoints(ctx context.Context, waypoints string, start, arrival *int32) error {
	action, err := gal1leoWaypoints(waypoints, start, arrival)
	if err != nil {
		return err
	}
	return v.executeGal1leoAction(ctx, action)
}

func gal1leoAutoHeat(on bool) *ext.VehicleAction {
	return &ext.VehicleAction{Action: &ext.VehicleAction_AutoSteeringWheelHeat{AutoSteeringWheelHeat: &ext.AutoSteeringWheelHeat{On: on}}}
}
func (v *Vehicle) Gal1leoAutoSteeringWheelHeat(ctx context.Context, on bool) error {
	return v.executeGal1leoAction(ctx, gal1leoAutoHeat(on))
}

func gal1leoHeatLevel(level int32) (*ext.VehicleAction, error) {
	// REST/plugin levels are 0/off, 1/low, 3/high; protobuf is 1,2,3.
	// Node's old 0,1,2 array indices are not this public input contract.
	values := map[int32]carserver.StwHeatLevel{0: carserver.StwHeatLevel_StwHeatLevel_Off, 1: carserver.StwHeatLevel_StwHeatLevel_Low, 3: carserver.StwHeatLevel_StwHeatLevel_High}
	value, ok := values[level]
	if !ok {
		return nil, fmt.Errorf("invalid steering wheel heat level")
	}
	return &ext.VehicleAction{Action: &ext.VehicleAction_SteeringWheelHeatLevel{SteeringWheelHeatLevel: &ext.SteeringWheelHeatLevel{Level: value}}}, nil
}
func (v *Vehicle) Gal1leoSteeringWheelHeatLevel(ctx context.Context, level int32) error {
	action, err := gal1leoHeatLevel(level)
	if err != nil {
		return err
	}
	return v.executeGal1leoAction(ctx, action)
}

func gal1leoBoombox(sound uint32) (*ext.VehicleAction, error) {
	if sound != 0 && sound != 2000 {
		return nil, fmt.Errorf("unsupported boombox sound")
	}
	return &ext.VehicleAction{Action: &ext.VehicleAction_Boombox{Boombox: &ext.Boombox{Sound: sound}}}, nil
}
func (v *Vehicle) Gal1leoBoombox(ctx context.Context, sound uint32) error {
	action, err := gal1leoBoombox(sound)
	if err != nil {
		return err
	}
	return v.executeGal1leoAction(ctx, action)
}

func gal1leoCalendar(data string) (*ext.VehicleAction, error) {
	if !gal1leoText(data) {
		return nil, fmt.Errorf("invalid calendar data")
	}
	return &ext.VehicleAction{Action: &ext.VehicleAction_CalendarEntries{CalendarEntries: &ext.CalendarEntries{CalendarData: data}}}, nil
}
func (v *Vehicle) Gal1leoCalendar(ctx context.Context, data string) error {
	action, err := gal1leoCalendar(data)
	if err != nil {
		return err
	}
	return v.executeGal1leoAction(ctx, action)
}
