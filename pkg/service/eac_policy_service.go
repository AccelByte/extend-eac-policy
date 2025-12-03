// Copyright (c) 2023 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"extend-eac-policy/pkg/common"
	pb "extend-eac-policy/pkg/pb"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/repository"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/session"
	"github.com/AccelByte/accelbyte-go-sdk/session-sdk/pkg/sessionclient/game_session"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	disableSessionValidationEnv   = "DISABLE_SESSION_VALIDATION"
	sessionValidationFeatureLabel = "session_validation"
)

type reaction struct {
	action             pb.AppliedAction
	banDuration        time.Duration
	telemetryRecorded  bool
	moderationReported bool
}

// Reaction is an exported alias used in interfaces and tests.
type Reaction = reaction

type PolicyRule struct {
	Action      pb.AppliedAction `json:"action"`
	Telemetry   bool             `json:"telemetry"`
	BanDuration string           `json:"banDuration,omitempty"`
}

type clientActionPolicySet map[pb.ClientActionReason]PolicyRule
type integrityPolicySet map[pb.IntegrityViolationType]PolicyRule

type PolicyResolver struct {
	mu sync.RWMutex

	clientPolicies    map[pb.ClientActionReason]PolicyRule
	integrityPolicies map[pb.IntegrityViolationType]PolicyRule
}

func NewPolicyResolver() *PolicyResolver {
	clientDefaults := buildDefaultPolicies()
	integrityDefaults := buildDefaultIntegrityPolicies()

	return &PolicyResolver{
		clientPolicies:    clientDefaults,
		integrityPolicies: integrityDefaults,
	}
}

func (p *PolicyResolver) ResolveClientAction(reason pb.ClientActionReason) PolicyRule {
	p.mu.RLock()
	entry, ok := p.clientPolicies[reason]
	p.mu.RUnlock()

	if !ok {
		return PolicyRule{
			Action:    pb.AppliedAction_LOGGED,
			Telemetry: true,
		}
	}

	return entry
}

func (p *PolicyResolver) ResolveIntegrity(violation pb.IntegrityViolationType) PolicyRule {
	p.mu.RLock()
	entry, ok := p.integrityPolicies[violation]
	p.mu.RUnlock()

	if !ok {
		return PolicyRule{
			Action:    pb.AppliedAction_LOGGED,
			Telemetry: true,
		}
	}

	return entry
}

func buildDefaultPolicies() clientActionPolicySet {
	return clientActionPolicySet{
		pb.ClientActionReason_ACTION_INTERNAL_ERROR:        {Action: pb.AppliedAction_LOGGED, Telemetry: true},
		pb.ClientActionReason_ACTION_INVALID_MESSAGE:       {Action: pb.AppliedAction_LOGGED, Telemetry: true},
		pb.ClientActionReason_ACTION_AUTHENTICATION_FAILED: {Action: pb.AppliedAction_LOGGED, Telemetry: true},
		pb.ClientActionReason_ACTION_NULL_CLIENT:           {Action: pb.AppliedAction_LOGGED, Telemetry: true},
		pb.ClientActionReason_ACTION_HEARTBEAT_TIMEOUT:     {Action: pb.AppliedAction_LOGGED, Telemetry: true},
		pb.ClientActionReason_ACTION_CLIENT_VIOLATION:      {Action: pb.AppliedAction_TEMP_BANNED, Telemetry: true, BanDuration: "24h"},
		pb.ClientActionReason_ACTION_BACKEND_VIOLATION:     {Action: pb.AppliedAction_TEMP_BANNED, Telemetry: true, BanDuration: "24h"},
		pb.ClientActionReason_ACTION_TEMPORARY_COOLDOWN:    {Action: pb.AppliedAction_TEMP_BANNED, Telemetry: true, BanDuration: "30m"},
		pb.ClientActionReason_ACTION_TEMPORARY_BANNED:      {Action: pb.AppliedAction_TEMP_BANNED, Telemetry: true, BanDuration: "168h"}, // 7 days
		pb.ClientActionReason_ACTION_PERMANENT_BANNED:      {Action: pb.AppliedAction_PERM_BANNED, Telemetry: true},
	}
}

func buildDefaultIntegrityPolicies() integrityPolicySet {
	safeRule := PolicyRule{Action: pb.AppliedAction_LOGGED, Telemetry: true}

	return integrityPolicySet{
		pb.IntegrityViolationType_INTEGRITY_CATALOG_NOT_FOUND:               safeRule,
		pb.IntegrityViolationType_INTEGRITY_CATALOG_ERROR:                   safeRule,
		pb.IntegrityViolationType_INTEGRITY_CATALOG_CERTIFICATE_REVOKED:     safeRule,
		pb.IntegrityViolationType_INTEGRITY_CATALOG_MISSING_MAIN_EXECUTABLE: safeRule,
		pb.IntegrityViolationType_INTEGRITY_GAME_FILE_MISMATCH:              safeRule,
		pb.IntegrityViolationType_INTEGRITY_REQUIRED_GAME_FILE_NOT_FOUND:    safeRule,
		pb.IntegrityViolationType_INTEGRITY_UNKNOWN_GAME_FILE_FORBIDDEN:     safeRule,
		pb.IntegrityViolationType_INTEGRITY_SYSTEM_FILE_UNTRUSTED:           safeRule,
		pb.IntegrityViolationType_INTEGRITY_FORBIDDEN_MODULE_LOADED:         safeRule,
		pb.IntegrityViolationType_INTEGRITY_CORRUPTED_MEMORY:                safeRule,
		pb.IntegrityViolationType_INTEGRITY_FORBIDDEN_TOOL_DETECTED:         safeRule,
		pb.IntegrityViolationType_INTEGRITY_INTERNAL_ANTI_CHEAT_VIOLATION:   safeRule,
		pb.IntegrityViolationType_INTEGRITY_CORRUPTED_NETWORK_MESSAGE_FLOW:  safeRule,
		pb.IntegrityViolationType_INTEGRITY_VIRTUAL_MACHINE_NOT_ALLOWED:     safeRule,
		pb.IntegrityViolationType_INTEGRITY_FORBIDDEN_SYSTEM_CONFIGURATION:  safeRule,
	}
}

type Metrics struct {
	requests *prometheus.CounterVec
}

func NewMetrics(registry *prometheus.Registry) *Metrics {
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "anti_cheat",
		Name:      "requests_total",
		Help:      "Anti-cheat reports processed",
	}, []string{"source", "reason", "action", "status"})

	registry.MustRegister(requests)

	return &Metrics{
		requests: requests,
	}
}

type AntiCheatService struct {
	pb.UnimplementedAntiCheatServiceServer
	tokenRepo   repository.TokenRepository
	configRepo  repository.ConfigRepository
	refreshRepo repository.RefreshTokenRepository
	policies    *PolicyResolver
	metrics     *Metrics
	logger      *logrus.Entry
	actions     ActionHandler
	session     SessionValidator
	// gated so we can bypass session lookups when explicitly disabled
	sessionValidationEnabled bool
}

func NewAntiCheatService(
	tokenRepo repository.TokenRepository,
	configRepo repository.ConfigRepository,
	refreshRepo repository.RefreshTokenRepository,
	policies *PolicyResolver,
	metrics *Metrics,
	logger *logrus.Logger,
	actions ActionHandler,
	sessionValidator SessionValidator,
) *AntiCheatService {
	sessionValidationEnabled := strings.ToLower(common.GetEnv(disableSessionValidationEnv, "false")) != "true"

	return &AntiCheatService{
		tokenRepo:                tokenRepo,
		configRepo:               configRepo,
		refreshRepo:              refreshRepo,
		policies:                 policies,
		metrics:                  metrics,
		logger:                   logger.WithField("component", "anti-cheat-service"),
		actions:                  actions,
		session:                  sessionValidator,
		sessionValidationEnabled: sessionValidationEnabled,
	}
}

func (s *AntiCheatService) ReportClientIntegrityViolation(ctx context.Context, req *pb.EACIntegrityReportRequest) (*pb.EACReportResponse, error) {
	reasonLabel := req.ViolationType.String()
	if err := validateIntegrityReportRequest(req); err != nil {
		s.metrics.requests.WithLabelValues("public", reasonLabel, "invalid", "failed").Inc()

		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	response, err := s.processIntegrityViolation(ctx, req, "public")
	if err != nil {
		return nil, err
	}

	return response, nil
}

/** TODO: Currently it just accept any user token, which can be abused to report other user
 * Suggestion: add one more field to store the AccelByte SessionID and request the session info to see if reported user is in session and reporting user is a session leader. This function should be called from P2P host client
 *
 */
func (s *AntiCheatService) ReportPublicViolation(ctx context.Context, req *pb.EACReportRequest) (*pb.EACReportResponse, error) {
	if err := validateReportRequest(req); err != nil {
		s.metrics.requests.WithLabelValues("public", req.ClientActionReason.String(), "invalid", "failed").Inc()

		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	tokenInfo, err := s.extractUserTokenInfo(ctx)
	if err != nil {
		s.metrics.requests.WithLabelValues("public", req.ClientActionReason.String(), "unauthorized", "failed").Inc()

		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}

	if err := s.validateSession(ctx, req.SessionId, req.UserId, tokenInfo.userID, true); err != nil {
		s.metrics.requests.WithLabelValues("public", req.ClientActionReason.String(), sessionValidationFeatureLabel, "failed").Inc()

		return nil, err
	}

	response, err := s.processClientViolation(ctx, req, "public")
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *AntiCheatService) ReportAdminViolation(ctx context.Context, req *pb.EACReportRequest) (*pb.EACReportResponse, error) {
	if err := validateReportRequest(req); err != nil {
		s.metrics.requests.WithLabelValues("admin", req.ClientActionReason.String(), "invalid", "failed").Inc()

		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	if err := s.validateSession(ctx, req.SessionId, req.UserId, "", false); err != nil {
		s.metrics.requests.WithLabelValues("admin", req.ClientActionReason.String(), sessionValidationFeatureLabel, "failed").Inc()

		return nil, err
	}

	response, err := s.processClientViolation(ctx, req, "admin")
	if err != nil {
		return nil, err
	}

	return response, nil
}

// TODO: Modify this function to process client integrity violation
func (s *AntiCheatService) processIntegrityViolation(ctx context.Context, req *pb.EACIntegrityReportRequest, source string) (*pb.EACReportResponse, error) {
	rule := s.policies.ResolveIntegrity(req.ViolationType)
	plan := reaction{
		action:             rule.Action,
		telemetryRecorded:  rule.Telemetry,
		moderationReported: !isBanAction(rule.Action),
	}

	if rule.BanDuration != "" {
		duration, err := time.ParseDuration(rule.BanDuration)
		if err != nil {
			s.metrics.requests.WithLabelValues(source, req.ViolationType.String(), "invalid_policy", "failed").Inc()

			return nil, status.Errorf(codes.Internal, "invalid ban duration configured for %s", req.ViolationType.String())
		}
		plan.banDuration = duration
	}

	details := req.ViolationType.String()
	if strings.TrimSpace(req.ViolationMessage) != "" {
		details = fmt.Sprintf("%s: %s", details, req.ViolationMessage)
	}

	reportReq := &pb.EACReportRequest{
		UserId:                          req.UserId,
		ClientActionReason:              pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
		ClientActionDetailsReasonString: details,
	}

	if err := s.applyPlan(ctx, reportReq, &plan, source); err != nil {
		s.metrics.requests.WithLabelValues(source, req.ViolationType.String(), plan.action.String(), "failed").Inc()

		return nil, err
	}

	s.metrics.requests.WithLabelValues(source, req.ViolationType.String(), plan.action.String(), "success").Inc()

	return &pb.EACReportResponse{
		AppliedAction:      plan.action,
		TelemetryRecorded:  plan.telemetryRecorded,
		ModerationReported: plan.moderationReported,
		BanDurationSeconds: int64(plan.banDuration.Seconds()),
	}, nil
}

// TODO: Modify this function to process client violation
func (s *AntiCheatService) processClientViolation(ctx context.Context, req *pb.EACReportRequest, source string) (*pb.EACReportResponse, error) {
	rule := s.policies.ResolveClientAction(req.ClientActionReason)
	plan := reaction{
		action:             rule.Action,
		telemetryRecorded:  rule.Telemetry,
		moderationReported: !isBanAction(rule.Action),
	}

	if rule.BanDuration != "" {
		duration, err := time.ParseDuration(rule.BanDuration)
		if err != nil {
			s.metrics.requests.WithLabelValues(source, req.ClientActionReason.String(), "invalid_policy", "failed").Inc()

			return nil, status.Errorf(codes.Internal, "invalid ban duration configured for %s", req.ClientActionReason.String())
		}
		plan.banDuration = duration
	}

	if err := s.applyPlan(ctx, req, &plan, source); err != nil {
		s.metrics.requests.WithLabelValues(source, req.ClientActionReason.String(), plan.action.String(), "failed").Inc()

		return nil, err
	}

	s.metrics.requests.WithLabelValues(source, req.ClientActionReason.String(), plan.action.String(), "success").Inc()

	return &pb.EACReportResponse{
		AppliedAction:      plan.action,
		TelemetryRecorded:  plan.telemetryRecorded,
		ModerationReported: plan.moderationReported,
		BanDurationSeconds: int64(plan.banDuration.Seconds()),
	}, nil
}

func (s *AntiCheatService) applyPlan(ctx context.Context, req *pb.EACReportRequest, plan *reaction, source string) error {
	event := map[string]interface{}{
		"source":     source,
		"namespace":  common.GetEnv("AB_NAMESPACE", "accelbyte"),
		"userId":     req.UserId,
		"reason":     req.ClientActionReason.String(),
		"details":    req.ClientActionDetailsReasonString,
		"action":     plan.action.String(),
		"banSeconds": int64(plan.banDuration.Seconds()),
	}

	s.logger.WithContext(ctx).WithFields(logrus.Fields(event)).Info("Processed anti-cheat report")

	if plan.telemetryRecorded && s.actions != nil {
		if err := s.actions.SendTelemetry(ctx, req, *plan, source); err != nil {
			return status.Errorf(codes.Internal, "telemetry failed: %v", err)
		}
	}

	if isBanAction(plan.action) {
		plan.moderationReported = false
	}

	if plan.moderationReported && s.actions != nil {
		reported, err := s.actions.SubmitReport(ctx, req, source)
		if err != nil {
			return status.Errorf(codes.Internal, "reporting failed: %v", err)
		}

		plan.moderationReported = reported
	}

	if s.actions != nil {
		if err := s.actions.ApplyBan(ctx, req, *plan); err != nil {
			return status.Errorf(codes.Internal, "ban failed: %v", err)
		}
	}

	return nil
}

func isBanAction(action pb.AppliedAction) bool {
	return action == pb.AppliedAction_TEMP_BANNED || action == pb.AppliedAction_PERM_BANNED
}

func validateReportRequest(req *pb.EACReportRequest) error {
	if strings.TrimSpace(req.UserId) == "" {
		return fmt.Errorf("userId is required")
	}
	if req.ClientActionReason == pb.ClientActionReason_ACTION_INVALID_UNSPECIFIED {
		return fmt.Errorf("clientActionReason is required")
	}

	return nil
}

func (s *AntiCheatService) extractUserTokenInfo(ctx context.Context) (tokenInfo, error) {
	token, err := bearerTokenFromContext(ctx)
	if err != nil {
		return tokenInfo{}, err
	}

	return parseUserToken(token)
}

func bearerTokenFromContext(ctx context.Context) (string, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("authorization metadata missing")
	}

	authHeaders := meta.Get("authorization")
	if len(authHeaders) == 0 {
		return "", fmt.Errorf("authorization metadata missing")
	}

	token := strings.TrimPrefix(authHeaders[0], "Bearer ")
	if token == "" {
		return "", fmt.Errorf("authorization token missing")
	}

	return token, nil
}

type tokenInfo struct {
	subject string
	userID  string
}

func parseUserToken(token string) (tokenInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return tokenInfo{}, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenInfo{}, fmt.Errorf("invalid token payload")
	}

	var claims map[string]interface{}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return tokenInfo{}, fmt.Errorf("invalid token claims")
	}

	rawUserID, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(rawUserID) == "" {
		return tokenInfo{}, fmt.Errorf("token is not a user token")
	}

	subject := rawUserID
	if sub, ok := claims["sub"].(string); ok && strings.TrimSpace(sub) != "" {
		subject = sub
	}

	return tokenInfo{
		subject: subject,
		userID:  rawUserID,
	}, nil
}

func validateIntegrityReportRequest(req *pb.EACIntegrityReportRequest) error {
	if strings.TrimSpace(req.UserId) == "" {
		return fmt.Errorf("userId is required")
	}
	if req.ViolationType == pb.IntegrityViolationType_INTEGRITY_INVALID_UNSPECIFIED {
		return fmt.Errorf("violationType is required")
	}

	return nil
}

// SessionValidator defines how we ensure a reported user belongs to the session (and optionally that the caller is the leader).
type SessionValidator interface {
	ValidateSession(ctx context.Context, sessionID, reportedUserID, callerUserID string, requireLeader bool) error
}

type GameSessionValidator struct {
	client    *session.GameSessionService
	namespace string
	logger    *logrus.Entry
}

func NewGameSessionValidator(client *session.GameSessionService, namespace string, logger *logrus.Logger) SessionValidator {
	return &GameSessionValidator{
		client:    client,
		namespace: namespace,
		logger:    logger.WithField("component", "session-validator"),
	}
}

func (v *GameSessionValidator) ValidateSession(ctx context.Context, sessionID, reportedUserID, callerUserID string, requireLeader bool) error {
	if v == nil || v.client == nil {
		return nil
	}

	params := game_session.NewGetGameSessionParams()
	params.Context = ctx
	params.Namespace = v.namespace
	params.SessionID = sessionID

	sessionResp, err := v.client.GetGameSessionShort(params)
	if err != nil {
		// differentiate not found so callers can map to gRPC NOT_FOUND.
		var notFound *game_session.GetGameSessionNotFound
		if errors.As(err, &notFound) {
			return status.Errorf(codes.NotFound, "session %s not found", sessionID)
		}

		v.logger.WithError(err).Warn("failed to fetch session for validation")
		return status.Errorf(codes.Internal, "session lookup failed")
	}

	if sessionResp == nil {
		return status.Errorf(codes.Internal, "session lookup returned empty response")
	}

	if requireLeader {
		if sessionResp.LeaderID == nil || callerUserID == "" || *sessionResp.LeaderID != callerUserID {
			return status.Errorf(codes.PermissionDenied, "caller is not session leader")
		}
	}

	for _, member := range sessionResp.Members {
		if member != nil && member.ID != nil && *member.ID == reportedUserID {
			return nil
		}
	}

	return status.Errorf(codes.PermissionDenied, "reported user not in session")
}

func (s *AntiCheatService) validateSession(ctx context.Context, sessionID, reportedUserID, callerUserID string, requireLeader bool) error {
	if !s.sessionValidationEnabled || s.session == nil {
		return nil
	}
	if strings.TrimSpace(sessionID) == "" {
		return status.Errorf(codes.InvalidArgument, "sessionId is required")
	}

	return s.session.ValidateSession(ctx, sessionID, reportedUserID, callerUserID, requireLeader)
}
