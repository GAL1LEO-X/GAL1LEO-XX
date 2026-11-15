package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/teslamotors/vehicle-command/pkg/account"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

type extensionRecorder struct {
	name   string
	flags  []bool
	levels map[vehicle.SeatPosition]vehicle.Level
	err    error
	args   []any
}

func (r *extensionRecorder) CloseTrunk(context.Context) error { r.name = "close"; return r.err }
func (r *extensionRecorder) BatchRemoveChargeSchedules(_ context.Context, h, w, o bool) error {
	r.name = "charge"
	r.flags = []bool{h, w, o}
	return r.err
}
func (r *extensionRecorder) BatchRemovePreconditionSchedules(_ context.Context, h, w, o bool) error {
	r.name = "climate"
	r.flags = []bool{h, w, o}
	return r.err
}
func (r *extensionRecorder) SetSeatHeater(_ context.Context, levels map[vehicle.SeatPosition]vehicle.Level) error {
	r.name = "seats"
	r.levels = levels
	return r.err
}

func (r *extensionRecorder) Gal1leoNavigateGPS(_ context.Context, lat, lon float64, order int32) error {
	r.name = "gps"
	r.args = []any{lat, lon, order}
	return r.err
}
func (r *extensionRecorder) Gal1leoNavigateSupercharger(_ context.Context, id int64, order int32) error {
	r.name = "sc"
	r.args = []any{id, order}
	return r.err
}
func (r *extensionRecorder) Gal1leoNavigateWaypoints(_ context.Context, points string, start, arrival *int32) error {
	r.name = "waypoints"
	r.args = []any{points, start, arrival}
	return r.err
}
func (r *extensionRecorder) Gal1leoAutoSteeringWheelHeat(_ context.Context, on bool) error {
	r.name = "auto_heat"
	r.args = []any{on}
	return r.err
}
func (r *extensionRecorder) Gal1leoSteeringWheelHeatLevel(_ context.Context, level int32) error {
	r.name = "heat_level"
	r.args = []any{level}
	return r.err
}
func (r *extensionRecorder) Gal1leoBoombox(_ context.Context, sound uint32) error {
	r.name = "boombox"
	r.args = []any{sound}
	return r.err
}
func (r *extensionRecorder) Gal1leoCalendar(_ context.Context, data string) error {
	r.name = "calendar"
	r.args = []any{data}
	return r.err
}

func TestGal1leoSevenParameterMappings(t *testing.T) {
	zero, twenty := int32(0), int32(20)
	for _, c := range []struct {
		name, body, method string
		args               []any
	}{
		{"navigation_gps_request", `{"lat":37.5,"lon":-122.25,"order":3}`, "gps", []any{37.5, -122.25, int32(3)}},
		{"navigation_sc_request", `{"id":123456,"order":2}`, "sc", []any{int64(123456), int32(2)}},
		{"navigation_waypoints_request", `{"waypoints":"refId:synthetic-a,refId:synthetic-b"}`, "waypoints", []any{"refId:synthetic-a,refId:synthetic-b", (*int32)(nil), (*int32)(nil)}},
		{"navigation_waypoints_request", `{"waypoints":"refId:synthetic-a","destination_start_soe":0,"destination_arrival_soe":20}`, "waypoints", []any{"refId:synthetic-a", &zero, &twenty}},
		{"remote_auto_steering_wheel_heat_climate_request", `{"on":false}`, "auto_heat", []any{false}},
		{"remote_steering_wheel_heat_level_request", `{"level":3}`, "heat_level", []any{int32(3)}},
		{"remote_boombox", `{"sound":2000}`, "boombox", []any{uint32(2000)}},
		{"upcoming_calendar_entries", `{"calendar_data":"synthetic-encoded-data"}`, "calendar", []any{"synthetic-encoded-data"}},
	} {
		t.Run(c.name+c.body, func(t *testing.T) {
			var p RequestParameters
			if err := json.Unmarshal([]byte(c.body), &p); err != nil {
				t.Fatal(err)
			}
			action, err := gal1leoAction(context.Background(), c.name, p)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("synthetic uncertain result")
			r := &extensionRecorder{err: sentinel}
			if err = action(r); err != sentinel || r.name != c.method || !reflect.DeepEqual(r.args, c.args) {
				t.Fatalf("unexpected dispatch %s %#v %v", r.name, r.args, err)
			}
		})
	}
}

func TestGal1leoSevenRejectBeforeDispatch(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"navigation_gps_request", `{"lat":91,"lon":0,"order":1}`},
		{"navigation_gps_request", `{"lat":0,"lon":0,"order":4}`},
		{"navigation_gps_request", `{"lat":0,"lon":0,"order":1.5}`},
		{"navigation_gps_request", `{"lat":false,"lon":0,"order":1}`},
		{"navigation_sc_request", `{"id":9007199254740992,"order":1}`},
		{"navigation_sc_request", `{"id":0,"order":1}`},
		{"navigation_sc_request", `{"id":1.1,"order":1}`},
		{"navigation_waypoints_request", `{"waypoints":"x","append":true}`},
		{"navigation_waypoints_request", `{"waypoints":"x","destination_start_soe":101}`},
		{"navigation_waypoints_request", `{"waypoints":"x","destination_start_soe":null}`},
		{"navigation_waypoints_request", `{"waypoints":"x","destination_arrival_soe":1.5}`},
		{"remote_auto_steering_wheel_heat_climate_request", `{"on":0}`},
		{"remote_steering_wheel_heat_level_request", `{"level":2}`},
		{"remote_boombox", `{"sound":1}`},
		{"upcoming_calendar_entries", `{"calendar_data":" "}`},
		{"upcoming_calendar_entries", `{"calendar_data":"x\u0000"}`},
	} {
		var p RequestParameters
		_ = json.Unmarshal([]byte(c.body), &p)
		if _, err := gal1leoAction(context.Background(), c.name, p); err == nil {
			t.Fatalf("accepted %s %s", c.name, c.body)
		}
	}
}

func TestGal1leoPinnedOptionalCommandContracts(t *testing.T) {
	// Parse only: no action closure is executed and no vehicle is constructed.
	for _, c := range []struct{ name, body string }{
		{"set_preconditioning_max", `{"on":true}`},
		{"set_scheduled_departure", `{"enable":false}`},
		{"set_scheduled_departure", `{"enable":true,"departure_time":420,"preconditioning_weekdays_only":true}`},
	} {
		var params RequestParameters
		if err := json.Unmarshal([]byte(c.body), &params); err != nil {
			t.Fatal(err)
		}
		if action, err := ExtractCommandAction(context.Background(), c.name, params); err != nil || action == nil {
			t.Fatalf("%s %s: %v", c.name, c.body, err)
		}
	}
	for _, c := range []struct {
		body string
		want vehicle.ChargingPolicy
	}{
		{`{"preconditioning_weekdays_only":true}`, vehicle.ChargingPolicyWeekdays},
		{`{"preconditioning_enabled":true}`, vehicle.ChargingPolicyAllDays},
		{`{}`, vehicle.ChargingPolicyOff},
	} {
		var params RequestParameters
		_ = json.Unmarshal([]byte(c.body), &params)
		actual, err := params.getPolicy("preconditioning_enabled", "preconditioning_weekdays_only")
		if err != nil || actual != c.want {
			t.Fatalf("policy %s: got %v, %v; want %v", c.body, actual, err, c.want)
		}
	}
}

func TestGal1leoHelpers(t *testing.T) {
	cases := []struct{ name, body, method string }{
		{"close_trunk", `{}`, "close"},
		{"batch_remove_charge_schedules", `{"home":true,"work":false,"other":true}`, "charge"},
		{"batch_remove_precondition_schedules", `{"home":true,"work":false,"other":true}`, "climate"},
		{"set_seat_heaters", `{"levels":{"0":1,"5":3}}`, "seats"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p RequestParameters
			if err := json.Unmarshal([]byte(c.body), &p); err != nil {
				t.Fatal(err)
			}
			action, err := gal1leoAction(context.Background(), c.name, p)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("synthetic uncertain result")
			recorder := &extensionRecorder{err: sentinel}
			if action(recorder) != sentinel || recorder.name != c.method {
				t.Fatal("wrong helper or error swallowed")
			}
			if recorder.flags != nil && !reflect.DeepEqual(recorder.flags, []bool{true, false, true}) {
				t.Fatal(recorder.flags)
			}
			if c.method == "seats" && !reflect.DeepEqual(recorder.levels, map[vehicle.SeatPosition]vehicle.Level{vehicle.SeatFrontLeft: 1, vehicle.SeatSecondRowRight: 3}) {
				t.Fatal(recorder.levels)
			}
			if _, err = ExtractCommandAction(context.Background(), c.name, p); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestGal1leoRejectParameters(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"close_trunk", `{"which_trunk":"front"}`},
		{"batch_remove_charge_schedules", `{"home":false,"work":false,"other":false}`},
		{"batch_remove_charge_schedules", `{"home":true,"work":false}`},
		{"set_seat_heaters", `{"levels":{"3":2}}`},
		{"set_seat_heaters", `{"levels":{"0":1.5}}`},
		{"set_seat_heaters", `{"levels":{"0":true}}`},
		{"set_seat_heaters", `{"levels":{"0":4}}`},
	} {
		var p RequestParameters
		_ = json.Unmarshal([]byte(c.body), &p)
		if _, err := gal1leoAction(context.Background(), c.name, p); err == nil {
			t.Fatalf("accepted %s", c.body)
		}
	}
}
func TestGal1leoCapabilitiesNeverConnects(t *testing.T) {
	p := &Proxy{Timeout: time.Second}
	for _, method := range []string{"GET", "POST"} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(method, "https://localhost/gal1leo/capabilities", nil))
		if method == "GET" && (w.Code != 200 || !strings.Contains(w.Body.String(), gal1leoProtocol)) {
			t.Fatal(w)
		}
		if method == "POST" && w.Code != 405 {
			t.Fatal(w.Code)
		}
	}
}

func TestGal1leoNeverFallsBackToREST(t *testing.T) {
	for _, command := range gal1leoOperations {
		for _, cached := range []bool{false, true} {
			p := newTestProxy(t)
			if cached {
				p.markUnsupportedVIN(testVIN)
			}
			p.fetchVehicle = func(context.Context, *account.Account, string) (vehicleSession, error) {
				return &mockVehicle{sessionErr: protocol.ErrProtocolNotSupported}, nil
			}
			p.client = roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("SDK extension must never forward to REST")
				return nil, nil
			})
			w := httptest.NewRecorder()
			bodies := map[string]string{
				"close_trunk": `{}`, "batch_remove_charge_schedules": `{"home":true,"work":false,"other":false}`, "batch_remove_precondition_schedules": `{"home":true,"work":false,"other":false}`,
				"set_seat_heaters": `{"levels":{"0":1}}`, "navigation_gps_request": `{"lat":0,"lon":0,"order":1}`, "navigation_sc_request": `{"id":1,"order":1}`, "navigation_waypoints_request": `{"waypoints":"synthetic"}`,
				"remote_auto_steering_wheel_heat_climate_request": `{"on":true}`, "remote_steering_wheel_heat_level_request": `{"level":1}`, "remote_boombox": `{"sound":0}`, "upcoming_calendar_entries": `{"calendar_data":"synthetic"}`}
			req := httptest.NewRequest("POST", "/api/1/vehicles/"+testVIN+"/command/"+command, strings.NewReader(bodies[command]))
			req.Header.Set("Authorization", authHeader())
			p.ServeHTTP(w, req)
			if w.Code != 412 {
				t.Fatal(w.Code)
			}
		}
	}
}
