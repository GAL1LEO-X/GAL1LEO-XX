// Copyright 2026 GAL1LEO. Licensed under the Apache License, Version 2.0.
// Local HTTP adapter: official helpers plus seven isolated typed extensions.
// Official cryptography, authentication, sessions and retries are unchanged.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

const gal1leoProtocol = "gal1leo-vehicle-command/2"

var gal1leoOperations = []string{"close_trunk", "batch_remove_charge_schedules", "batch_remove_precondition_schedules", "set_seat_heaters",
	"navigation_gps_request", "navigation_sc_request", "navigation_waypoints_request",
	"remote_auto_steering_wheel_heat_climate_request", "remote_steering_wheel_heat_level_request", "remote_boombox", "upcoming_calendar_entries"}

func gal1leoCommand(name string) bool {
	for _, op := range gal1leoOperations {
		if name == op {
			return true
		}
	}
	return false
}

func gal1leoCapabilities(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"protocol": gal1leoProtocol, "operations": gal1leoOperations, "upstream_commit": "fc5a1910ad45c42921d541089e3e366d0b897f52"})
}

// Interface enables offline tests to observe the exact public SDK call.
type gal1leoVehicle interface {
	CloseTrunk(context.Context) error
	BatchRemoveChargeSchedules(context.Context, bool, bool, bool) error
	BatchRemovePreconditionSchedules(context.Context, bool, bool, bool) error
	SetSeatHeater(context.Context, map[vehicle.SeatPosition]vehicle.Level) error
	Gal1leoNavigateGPS(context.Context, float64, float64, int32) error
	Gal1leoNavigateSupercharger(context.Context, int64, int32) error
	Gal1leoNavigateWaypoints(context.Context, string, *int32, *int32) error
	Gal1leoAutoSteeringWheelHeat(context.Context, bool) error
	Gal1leoSteeringWheelHeatLevel(context.Context, int32) error
	Gal1leoBoombox(context.Context, uint32) error
	Gal1leoCalendar(context.Context, string) error
}

var _ gal1leoVehicle = (*vehicle.Vehicle)(nil)

func gal1leoNumber(params RequestParameters, key string, min, max float64, integer bool) (float64, bool) {
	value, ok := params[key].(float64)
	return value, ok && !math.IsNaN(value) && !math.IsInf(value, 0) && value >= min && value <= max && (!integer || math.Trunc(value) == value)
}
func gal1leoString(params RequestParameters, key string) (string, bool) {
	value, ok := params[key].(string)
	return value, ok && utf8.ValidString(value) && len(value) <= 16384 && len(strings.TrimSpace(value)) > 0 && !strings.ContainsRune(value, 0)
}

func gal1leoAction(ctx context.Context, name string, params RequestParameters) (func(gal1leoVehicle) error, error) {
	invalid := fmt.Errorf("invalid parameters for SDK extension")
	switch name {
	case "navigation_gps_request":
		lat, a := gal1leoNumber(params, "lat", -90, 90, false)
		lon, b := gal1leoNumber(params, "lon", -180, 180, false)
		order, c := gal1leoNumber(params, "order", 0, 3, true)
		if len(params) != 3 || !a || !b || !c {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoNavigateGPS(ctx, lat, lon, int32(order)) }, nil
	case "navigation_sc_request":
		id, a := gal1leoNumber(params, "id", 1, 9007199254740991, true)
		order, b := gal1leoNumber(params, "order", 0, 3, true)
		if len(params) != 2 || !a || !b {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoNavigateSupercharger(ctx, int64(id), int32(order)) }, nil
	case "navigation_waypoints_request":
		waypoints, ok := gal1leoString(params, "waypoints")
		if !ok {
			return nil, invalid
		}
		var start, arrival *int32
		for key := range params {
			switch key {
			case "waypoints":
			case "destination_start_soe", "destination_arrival_soe":
				value, ok := gal1leoNumber(params, key, 0, 100, true)
				if !ok {
					return nil, invalid
				}
				n := int32(value)
				if key == "destination_start_soe" {
					start = &n
				} else {
					arrival = &n
				}
			default:
				return nil, invalid
			}
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoNavigateWaypoints(ctx, waypoints, start, arrival) }, nil
	case "remote_auto_steering_wheel_heat_climate_request":
		on, ok := params["on"].(bool)
		if len(params) != 1 || !ok {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoAutoSteeringWheelHeat(ctx, on) }, nil
	case "remote_steering_wheel_heat_level_request":
		level, ok := gal1leoNumber(params, "level", 0, 3, true)
		if len(params) != 1 || !ok || level == 2 {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoSteeringWheelHeatLevel(ctx, int32(level)) }, nil
	case "remote_boombox":
		sound, ok := gal1leoNumber(params, "sound", 0, 2000, true)
		if len(params) != 1 || !ok || (sound != 0 && sound != 2000) {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoBoombox(ctx, uint32(sound)) }, nil
	case "upcoming_calendar_entries":
		data, ok := gal1leoString(params, "calendar_data")
		if len(params) != 1 || !ok {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.Gal1leoCalendar(ctx, data) }, nil
	case "close_trunk":
		if len(params) != 0 {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error { return v.CloseTrunk(ctx) }, nil
	case "batch_remove_charge_schedules", "batch_remove_precondition_schedules":
		if len(params) != 3 {
			return nil, invalid
		}
		home, h := params["home"].(bool)
		work, w := params["work"].(bool)
		other, o := params["other"].(bool)
		if !h || !w || !o || !(home || work || other) {
			return nil, invalid
		}
		return func(v gal1leoVehicle) error {
			if name == "batch_remove_charge_schedules" {
				return v.BatchRemoveChargeSchedules(ctx, home, work, other)
			}
			return v.BatchRemovePreconditionSchedules(ctx, home, work, other)
		}, nil
	case "set_seat_heaters":
		if len(params) != 1 {
			return nil, invalid
		}
		values, ok := params["levels"].(map[string]any)
		if !ok || len(values) == 0 || len(values) > 5 {
			return nil, invalid
		}
		seats := map[string]vehicle.SeatPosition{"0": vehicle.SeatFrontLeft, "1": vehicle.SeatFrontRight, "2": vehicle.SeatSecondRowLeft, "4": vehicle.SeatSecondRowCenter, "5": vehicle.SeatSecondRowRight}
		levels := make(map[vehicle.SeatPosition]vehicle.Level)
		for key, value := range values {
			seat, known := seats[key]
			level, number := value.(float64)
			if !known || !number || math.IsNaN(level) || level < 0 || level > 3 || math.Trunc(level) != level {
				return nil, invalid
			}
			levels[seat] = vehicle.Level(level)
		}
		return func(v gal1leoVehicle) error { return v.SetSeatHeater(ctx, levels) }, nil
	}
	return nil, ErrCommandNotImplemented
}
