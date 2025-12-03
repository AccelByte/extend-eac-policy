package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	pb "extend-eac-policy/pkg/pb"

	"github.com/AccelByte/accelbyte-go-sdk/gametelemetry-sdk/pkg/gametelemetryclient"
	"github.com/AccelByte/accelbyte-go-sdk/gametelemetry-sdk/pkg/gametelemetryclient/gametelemetry_operations"
	"github.com/AccelByte/accelbyte-go-sdk/iam-sdk/pkg/iamclient"
	"github.com/AccelByte/accelbyte-go-sdk/iam-sdk/pkg/iamclient/users"
	"github.com/AccelByte/accelbyte-go-sdk/iam-sdk/pkg/iamclientmodels"
	"github.com/AccelByte/accelbyte-go-sdk/reporting-sdk/pkg/reportingclient"
	"github.com/AccelByte/accelbyte-go-sdk/reporting-sdk/pkg/reportingclient/admin_reports"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/gametelemetry"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/iam"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/reporting"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/swag"
	"github.com/sirupsen/logrus"
)

func TestActionClients_SendTelemetryAndReport(t *testing.T) {
	actions, telemetryClient, reportClient := newTestActionClients(nil, nil)

	req := &pb.EACReportRequest{
		UserId:                          "user-123",
		ClientActionReason:              pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		ClientActionDetailsReasonString: "details",
	}
	plan := reaction{
		action:      pb.AppliedAction_LOGGED,
		banDuration: time.Hour,
	}

	if err := actions.SendTelemetry(context.Background(), req, plan, "public"); err != nil {
		t.Fatalf("SendTelemetry should succeed, got %v", err)
	}
	if !telemetryClient.called {
		t.Fatalf("telemetry client was not invoked")
	}

	reported, err := actions.SubmitReport(context.Background(), req, "public")
	if err != nil {
		t.Fatalf("SubmitReport should succeed, got %v", err)
	}
	if !reportClient.submitCalled {
		t.Fatalf("report client was not invoked")
	}
	if !reported {
		t.Fatalf("expected report to be marked submitted")
	}

	if err := actions.ApplyBan(context.Background(), req, plan); err != nil {
		t.Fatalf("ApplyBan should short-circuit for non-ban actions, got %v", err)
	}
}

func TestActionClients_SendTelemetryError(t *testing.T) {
	expectedErr := errors.New("telemetry failure")
	actions, _, _ := newTestActionClients(expectedErr, nil)

	req := &pb.EACReportRequest{UserId: "user-1"}
	plan := reaction{action: pb.AppliedAction_LOGGED}
	if err := actions.SendTelemetry(context.Background(), req, plan, "admin"); err == nil {
		t.Fatalf("expected telemetry error")
	}
}

func TestActionClients_SubmitReportError(t *testing.T) {
	expectedErr := errors.New("report failure")
	actions, _, _ := newTestActionClients(nil, expectedErr)

	req := &pb.EACReportRequest{UserId: "user-1", ClientActionReason: pb.ClientActionReason_ACTION_INTERNAL_ERROR}
	if _, err := actions.SubmitReport(context.Background(), req, "public"); err == nil {
		t.Fatalf("expected report error")
	}
}

func TestActionClients_SubmitReportSkipsNonUserTokenError(t *testing.T) {
	clientErr := errors.New("Requested POST /reporting/v1/admin/namespaces/{namespace}/reports returns an error 403: {\"errorCode\": 20022, \"errorMessage\": \"access forbidden: token is not user token\"}")
	actions, _, _ := newTestActionClients(nil, clientErr)

	req := &pb.EACReportRequest{UserId: "user-1", ClientActionReason: pb.ClientActionReason_ACTION_INTERNAL_ERROR}
	reported, err := actions.SubmitReport(context.Background(), req, "admin")
	if err != nil {
		t.Fatalf("expected skip without error, got %v", err)
	}
	if reported {
		t.Fatalf("expected reporting to be marked as skipped")
	}
}

func TestActionClients_ApplyBan(t *testing.T) {
	banResponse := &users.AdminBanUserV3Created{Payload: &iamclientmodels.ModelUserBanResponseV3{}}
	transport := stubTransport{response: banResponse}

	usersService := iam.UsersService{
		Client: &iamclient.JusticeIamService{
			Users:   users.New(transport, nil),
			Runtime: &httptransport.Runtime{Transport: http.DefaultTransport},
		},
		TokenRepository:  stubTokenRepository{},
		ConfigRepository: stubConfigRepository{},
	}

	actions := &ActionClients{
		users:     usersService,
		logger:    logrus.New().WithField("component", "actions-test"),
		namespace: "test-ns",
	}

	req := &pb.EACReportRequest{UserId: "user-123", ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION}
	plan := reaction{action: pb.AppliedAction_TEMP_BANNED, banDuration: time.Hour}

	if err := actions.ApplyBan(context.Background(), req, plan); err != nil {
		t.Fatalf("expected ban to succeed, got %v", err)
	}
}

func TestNewActionClients(t *testing.T) {
	logger := logrus.New()
	clients := NewActionClients(ActionClientConfig{
		Logger: logger,
	})
	if clients.logger == nil {
		t.Fatalf("expected logger to be initialized")
	}
	if clients.namespace == "" {
		t.Fatalf("expected namespace to be set")
	}
}

// newTestActionClients assembles ActionClients with stubbed SDK clients so we do not make network calls.
func newTestActionClients(telemetryErr, reportErr error) (*ActionClients, *fakeTelemetryClient, *fakeAdminReportsClient) {
	telemetryClient := &fakeTelemetryClient{err: telemetryErr}
	reportClient := &fakeAdminReportsClient{err: reportErr}

	gametelemetryService := gametelemetry.GametelemetryOperationsService{
		Client: &gametelemetryclient.JusticeGametelemetryService{
			GametelemetryOperations: telemetryClient,
			Runtime:                 &httptransport.Runtime{Transport: http.DefaultTransport},
		},
		TokenRepository:  stubTokenRepository{},
		ConfigRepository: stubConfigRepository{},
	}

	reportingService := reporting.AdminReportsService{
		Client: &reportingclient.JusticeReportingService{
			AdminReports: reportClient,
			Runtime:      &httptransport.Runtime{Transport: http.DefaultTransport},
		},
		TokenRepository:  stubTokenRepository{},
		ConfigRepository: stubConfigRepository{},
	}

	return &ActionClients{
		users:     iam.UsersService{},
		reporting: reportingService,
		telemetry: gametelemetryService,
		logger:    logrus.New().WithField("component", "actions-test"),
		namespace: "test-ns",
	}, telemetryClient, reportClient
}

type fakeTelemetryClient struct {
	called bool
	err    error
}

func (f *fakeTelemetryClient) ProtectedSaveEventsGameTelemetryV1ProtectedEventsPost(params *gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostParams, authInfo runtime.ClientAuthInfoWriter) (*gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostNoContent, *gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostUnprocessableEntity, *gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostInternalServerError, *gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostInsufficientStorage, error) {
	f.called = true
	return &gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostNoContent{}, nil, nil, nil, f.err
}

func (f *fakeTelemetryClient) ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostShort(params *gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostParams, authInfo runtime.ClientAuthInfoWriter) (*gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostNoContent, error) {
	f.called = true
	return &gametelemetry_operations.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostNoContent{}, f.err
}

func (f *fakeTelemetryClient) ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGet(params *gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetParams, authInfo runtime.ClientAuthInfoWriter) (*gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetOK, *gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetNotFound, *gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetUnprocessableEntity, *gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetInternalServerError, error) {
	return nil, nil, nil, nil, nil
}

func (f *fakeTelemetryClient) ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetShort(params *gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetParams, authInfo runtime.ClientAuthInfoWriter) (*gametelemetry_operations.ProtectedGetPlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimeGetOK, error) {
	return nil, nil
}

func (f *fakeTelemetryClient) ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePut(params *gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutParams, authInfo runtime.ClientAuthInfoWriter) (*gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutOK, *gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutNotFound, *gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutUnprocessableEntity, *gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutInternalServerError, error) {
	return nil, nil, nil, nil, nil
}

func (f *fakeTelemetryClient) ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutShort(params *gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutParams, authInfo runtime.ClientAuthInfoWriter) (*gametelemetry_operations.ProtectedUpdatePlaytimeGameTelemetryV1ProtectedSteamIdsSteamIDPlaytimePlaytimePutOK, error) {
	return nil, nil
}

func (f *fakeTelemetryClient) SetTransport(transport runtime.ClientTransport) {}

type fakeAdminReportsClient struct {
	submitCalled bool
	err          error
}

func (f *fakeAdminReportsClient) ListReports(params *admin_reports.ListReportsParams, authInfo runtime.ClientAuthInfoWriter) (*admin_reports.ListReportsOK, *admin_reports.ListReportsInternalServerError, error) {
	return nil, nil, nil
}

func (f *fakeAdminReportsClient) ListReportsShort(params *admin_reports.ListReportsParams, authInfo runtime.ClientAuthInfoWriter) (*admin_reports.ListReportsOK, error) {
	return nil, nil
}

func (f *fakeAdminReportsClient) AdminSubmitReport(params *admin_reports.AdminSubmitReportParams, authInfo runtime.ClientAuthInfoWriter) (*admin_reports.AdminSubmitReportCreated, *admin_reports.AdminSubmitReportBadRequest, *admin_reports.AdminSubmitReportConflict, *admin_reports.AdminSubmitReportInternalServerError, error) {
	f.submitCalled = true
	return &admin_reports.AdminSubmitReportCreated{}, nil, nil, nil, f.err
}

func (f *fakeAdminReportsClient) AdminSubmitReportShort(params *admin_reports.AdminSubmitReportParams, authInfo runtime.ClientAuthInfoWriter) (*admin_reports.AdminSubmitReportCreated, error) {
	f.submitCalled = true
	return &admin_reports.AdminSubmitReportCreated{}, f.err
}

func (f *fakeAdminReportsClient) SetTransport(transport runtime.ClientTransport) {}

type stubTokenRepository struct{}

func (stubTokenRepository) GetToken() (*iamclientmodels.OauthmodelTokenResponseV3, error) {
	token := "token"
	return &iamclientmodels.OauthmodelTokenResponseV3{AccessToken: swag.String(token)}, nil
}

func (stubTokenRepository) Store(_ interface{}) error { return nil }

func (stubTokenRepository) RemoveToken() error { return nil }

func (stubTokenRepository) TokenIssuedTimeUTC() time.Time { return time.Time{} }

type stubConfigRepository struct{}

func (stubConfigRepository) GetClientId() string { return "client" }

func (stubConfigRepository) GetClientSecret() string { return "secret" }

func (stubConfigRepository) GetJusticeBaseUrl() string { return "http://example.com" }

type stubTransport struct {
	response interface{}
	err      error
}

func (s stubTransport) Submit(operation *runtime.ClientOperation) (interface{}, error) {
	return s.response, s.err
}
