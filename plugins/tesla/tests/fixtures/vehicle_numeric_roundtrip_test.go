package proxy

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// All outbound HTTP is intercepted; the test runs with Docker --network none.
func TestKittyNumericConfigurationRoundtrip(t *testing.T) {
	cases := []struct{ name, requested, emitted string }{
		{"integral", "1.0", "1"},
		{"zero", "0.0", "0"},
		{"negative_zero", "-0.0", "-0"},
		{"fraction", "0.25", "0.25"},
	}
	evidence := map[string]interface{}{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProxy(t)
			dispatches := 0
			p.fetchVehicle = nil // The telemetry signing route must never open a session.
			var claimsJSON []byte
			p.client = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				dispatches++
				if req.URL.Path != "/api/1/vehicles/fleet_telemetry_config_jws" {
					t.Fatalf("unexpected forwarded route: %s", req.URL.Path)
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				var signed struct {
					VINs  []string `json:"vins"`
					Token string   `json:"token"`
				}
				if err := json.Unmarshal(body, &signed); err != nil {
					t.Fatal(err)
				}
				if len(signed.VINs) != 1 || signed.VINs[0] != testVIN {
					t.Fatal("VIN list changed")
				}
				verified, err := jwt.Parse(signed.Token, func(token *jwt.Token) (interface{}, error) {
					return testPrivateKey(t).PublicBytes(), nil
				}, jwt.WithValidMethods([]string{"Tesla.SS256"}), jwt.WithAudience("com.tesla.fleet.TelemetryClient"))
				if err != nil || !verified.Valid {
					t.Fatalf("signature failed: %v", err)
				}
				parts := strings.Split(signed.Token, ".")
				claimsJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatal(err)
				}
				var claims map[string]interface{}
				dec := json.NewDecoder(strings.NewReader(string(claimsJSON)))
				dec.UseNumber()
				if err := dec.Decode(&claims); err != nil {
					t.Fatal(err)
				}
				fields := claims["fields"].(map[string]interface{})
				options := fields["BatteryLevel"].(map[string]interface{})
				if got := options["minimum_delta"].(json.Number).String(); got != tc.emitted {
					t.Fatalf("minimum_delta serialized %s, want %s", got, tc.emitted)
				}
				if options["future_flag"] != true || claims["ca"] != "synthetic-ca" || claims["hostname"] != "telemetry.example" {
					t.Fatal("non-numeric config changed")
				}
				include := options["include_fields"].([]interface{})
				if len(include) != 2 || include[0] != "Locked" || include[1] != "ChargeLimitSoc" {
					t.Fatal("list order changed")
				}
				if claims["aud"] != "com.tesla.fleet.TelemetryClient" || claims["iss"] == "discarded-original" {
					t.Fatal("signing claims not replaced")
				}
				return jsonResponse(http.StatusOK, `{"response":{"updated_vehicles":1}}`, nil), nil
			})
			input := `{"vins":["` + testVIN + `"],"config":{"hostname":"telemetry.example","port":8443,"ca":"synthetic-ca","aud":"discarded-original","iss":"discarded-original","fields":{"BatteryLevel":{"interval_seconds":5,"minimum_delta":` + tc.requested + `,"future_flag":true,"include_fields":["Locked","ChargeLimitSoc"]}}}}`
			req := httptest.NewRequest(http.MethodPost, "/api/1/vehicles/fleet_telemetry_config", strings.NewReader(input))
			req.Header.Set("Authorization", authHeader())
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || dispatches != 1 {
				t.Fatalf("status=%d dispatches=%d body=%s", rec.Code, dispatches, rec.Body.String())
			}
			evidence[tc.name] = map[string]interface{}{"requested_delta_json": tc.requested, "signed_delta_json": tc.emitted, "signature_verified": true, "dispatches": dispatches, "claims": json.RawMessage(claimsJSON)}
		})
	}
	if !t.Failed() {
		data, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		output := os.Getenv("VEHICLE_ROUNDTRIP_EVIDENCE")
		if output == "" {
			output = filepath.Join(t.TempDir(), "go-numeric-roundtrip.json")
		}
		if err := os.WriteFile(output, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
