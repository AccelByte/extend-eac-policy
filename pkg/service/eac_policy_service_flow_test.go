package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	pb "extend-eac-policy/pkg/pb"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestReportPublicViolationSuccess(t *testing.T) {
	actions := &spyActions{reportResult: true}
	sessionValidator := &stubSessionValidator{}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenForSubject("user-123")))
	req := &pb.EACReportRequest{
		UserId:                          "user-123",
		ClientActionReason:              pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		ClientActionDetailsReasonString: "speed hack",
		SessionId:                       "session-1",
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), actions, sessionValidator)
	resp, err := svc.ReportPublicViolation(ctx, req)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if resp.AppliedAction != pb.AppliedAction_TEMP_BANNED {
		t.Fatalf("unexpected action: %s", resp.AppliedAction)
	}
	if !resp.TelemetryRecorded {
		t.Fatalf("expected telemetry to be recorded")
	}
	if resp.ModerationReported {
		t.Fatalf("expected moderation report to be skipped for ban actions")
	}
	if actions.telemetryCalls == 0 || actions.banCalls == 0 {
		t.Fatalf("expected telemetry and ban handlers to be invoked")
	}
	if actions.reportCalls != 0 {
		t.Fatalf("expected report handler not to be invoked for ban actions")
	}
	if !sessionValidator.called {
		t.Fatalf("expected session validator to be called")
	}
}

func TestReportPublicViolationPermissionDeniedForNonUserToken(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenWithoutUserID("user-123")))
	req := &pb.EACReportRequest{
		UserId:             "user-123",
		ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		SessionId:          "session-1",
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), nil, &stubSessionValidator{})
	_, err := svc.ReportPublicViolation(ctx, req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestReportClientIntegrityViolationSuccess(t *testing.T) {
	actions := &spyActions{reportResult: true}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenForSubject("user-123")))
	req := &pb.EACIntegrityReportRequest{
		UserId:           "user-123",
		ViolationType:    pb.IntegrityViolationType_INTEGRITY_GAME_FILE_MISMATCH,
		ViolationMessage: "checksum mismatch",
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), actions, nil)
	resp, err := svc.ReportClientIntegrityViolation(ctx, req)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if resp.AppliedAction != pb.AppliedAction_LOGGED {
		t.Fatalf("unexpected action: %s", resp.AppliedAction)
	}
	if resp.BanDurationSeconds != 0 {
		t.Fatalf("expected no ban duration for integrity violation, got %d", resp.BanDurationSeconds)
	}
	if !resp.TelemetryRecorded {
		t.Fatalf("expected telemetry to be recorded for integrity violation")
	}
	if !resp.ModerationReported {
		t.Fatalf("expected moderation report for integrity violation")
	}
}

func TestReportClientIntegrityViolationSkipUserCheck(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenForSubject("someone-else")))
	req := &pb.EACIntegrityReportRequest{
		UserId:        "user-123",
		ViolationType: pb.IntegrityViolationType_INTEGRITY_GAME_FILE_MISMATCH,
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), nil, nil)
	resp, err := svc.ReportClientIntegrityViolation(ctx, req)
	if err != nil {
		t.Fatalf("expected success without user check, got %v", err)
	}
	if resp.AppliedAction != pb.AppliedAction_LOGGED {
		t.Fatalf("expected log-only action, got %s", resp.AppliedAction)
	}
}

func TestReportAdminViolationValidationFailure(t *testing.T) {
	req := &pb.EACReportRequest{
		ClientActionReason: pb.ClientActionReason_ACTION_INVALID_UNSPECIFIED,
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), nil, nil)
	_, err := svc.ReportAdminViolation(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestProcessClientViolationInvalidBanDuration(t *testing.T) {
	customResolver := NewPolicyResolver()
	customResolver.clientPolicies[pb.ClientActionReason_ACTION_CLIENT_VIOLATION] = PolicyRule{
		Action:      pb.AppliedAction_TEMP_BANNED,
		Telemetry:   true,
		BanDuration: "not-a-duration",
	}

	svc := NewAntiCheatService(nil, nil, nil, customResolver, NewMetrics(prometheus.NewRegistry()), logrus.New(), nil, nil)
	req := &pb.EACReportRequest{
		UserId:             "user-123",
		ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		SessionId:          "session-1",
	}

	_, err := svc.processClientViolation(context.Background(), req, "admin")
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected internal error, got %v", err)
	}
}

func TestApplyPlanSkipsDisabledActions(t *testing.T) {
	actions := &spyActions{}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), actions, nil)
	req := &pb.EACReportRequest{
		UserId:             "user-123",
		ClientActionReason: pb.ClientActionReason_ACTION_INTERNAL_ERROR,
	}
	plan := reaction{action: pb.AppliedAction_LOGGED}

	if err := svc.applyPlan(context.Background(), req, &plan, "public"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestReportAdminViolationSkipsNonUserTokenReporting(t *testing.T) {
	actions := &spyActions{reportResult: false}

	req := &pb.EACReportRequest{
		UserId:             "user-123",
		ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		SessionId:          "session-1",
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), actions, &stubSessionValidator{})
	resp, err := svc.ReportAdminViolation(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if resp.ModerationReported {
		t.Fatalf("expected reporting to be marked skipped for ban actions")
	}
	if actions.reportCalls != 0 {
		t.Fatalf("expected report handler not to be invoked for ban actions")
	}
}

func TestReportAdminViolationBypassesSessionValidationWhenDisabled(t *testing.T) {
	t.Setenv(disableSessionValidationEnv, "true")
	validator := &stubSessionValidator{err: status.Error(codes.PermissionDenied, "should not be called")}

	req := &pb.EACReportRequest{
		UserId:             "user-123",
		ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), nil, validator)
	if _, err := svc.ReportAdminViolation(context.Background(), req); err != nil {
		t.Fatalf("expected success when session validation disabled, got %v", err)
	}
	if validator.called {
		t.Fatalf("expected session validator to be skipped when disabled")
	}
}

func TestReportPublicViolationPropagatesSessionValidationError(t *testing.T) {
	validator := &stubSessionValidator{err: status.Error(codes.PermissionDenied, "not leader")}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tokenForSubject("user-123")))
	req := &pb.EACReportRequest{
		UserId:             "user-123",
		ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		SessionId:          "session-1",
	}

	svc := NewAntiCheatService(nil, nil, nil, NewPolicyResolver(), NewMetrics(prometheus.NewRegistry()), logrus.New(), nil, validator)
	_, err := svc.ReportPublicViolation(ctx, req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected session validation error to propagate, got %v", err)
	}
	if !validator.called {
		t.Fatalf("expected session validator to be invoked")
	}
}

type spyActions struct {
	telemetryCalls int
	reportCalls    int
	banCalls       int

	telemetryErr error
	reportErr    error
	banErr       error
	reportResult bool
}

type stubSessionValidator struct {
	called bool
	err    error
}

func (s *stubSessionValidator) ValidateSession(ctx context.Context, sessionID, reportedUserID, callerUserID string, requireLeader bool) error {
	s.called = true
	return s.err
}

func (s *spyActions) SendTelemetry(ctx context.Context, req *pb.EACReportRequest, plan Reaction, source string) error {
	s.telemetryCalls++
	return s.telemetryErr
}

func (s *spyActions) SubmitReport(ctx context.Context, req *pb.EACReportRequest, source string) (bool, error) {
	s.reportCalls++
	if s.reportErr != nil {
		return false, s.reportErr
	}

	return s.reportResult, nil
}

func (s *spyActions) ApplyBan(ctx context.Context, req *pb.EACReportRequest, plan Reaction) error {
	s.banCalls++
	return s.banErr
}

func tokenForSubject(sub string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%s","user_id":"%s"}`, sub, sub)))
	return "hdr." + payload + ".sig"
}

func tokenWithoutUserID(sub string) string {
	// Simulate a non-user token by omitting the expected subject claim entirely.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_id":"service-client"}`))
	return "hdr." + payload + ".sig"
}
