package service

import (
	"testing"

	pb "extend-eac-policy/pkg/pb"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func TestValidateReportRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *pb.EACReportRequest
		wantErr bool
	}{
		{
			name: "valid",
			req: &pb.EACReportRequest{
				UserId:                          "user-1",
				ClientActionReason:              pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
				ClientActionDetailsReasonString: "details",
			},
			wantErr: false,
		},
		{
			name: "missing user",
			req: &pb.EACReportRequest{
				ClientActionReason: pb.ClientActionReason_ACTION_CLIENT_VIOLATION,
			},
			wantErr: true,
		},
		{
			name: "missing reason",
			req: &pb.EACReportRequest{
				UserId: "user-1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReportRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error=%v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestPolicyResolver(t *testing.T) {
	overrideRule := PolicyRule{
		Action:    pb.AppliedAction_PERM_BANNED,
		Telemetry: true,
	}
	integrityRule := PolicyRule{
		Action: pb.AppliedAction_REPORTED,
	}

	resolver := NewPolicyResolver()
	resolver.clientPolicies[pb.ClientActionReason_ACTION_TEMPORARY_BANNED] = overrideRule
	resolver.integrityPolicies[pb.IntegrityViolationType_INTEGRITY_GAME_FILE_MISMATCH] = integrityRule

	rule := resolver.ResolveClientAction(pb.ClientActionReason_ACTION_TEMPORARY_BANNED)
	if rule.Action != overrideRule.Action {
		t.Fatalf("expected action %s, got %s", overrideRule.Action, rule.Action)
	}

	rule = resolver.ResolveClientAction(pb.ClientActionReason_ACTION_INTERNAL_ERROR)
	if rule.Action == pb.AppliedAction_UNSPECIFIED {
		t.Fatalf("expected non-empty default action")
	}

	rule = resolver.ResolveIntegrity(pb.IntegrityViolationType_INTEGRITY_GAME_FILE_MISMATCH)
	if rule.Action != integrityRule.Action {
		t.Fatalf("expected integrity override, got %s", rule.Action)
	}

	rule = resolver.ResolveIntegrity(pb.IntegrityViolationType_INTEGRITY_FORBIDDEN_TOOL_DETECTED)
	if rule.Action == pb.AppliedAction_UNSPECIFIED {
		t.Fatalf("expected non-empty default integrity action")
	}
}

func TestNewAntiCheatServiceRegistersMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	policies := NewPolicyResolver()
	logger := logrus.New()

	svc := NewAntiCheatService(nil, nil, nil, policies, NewMetrics(registry), logger, nil, nil)
	if svc == nil {
		t.Fatalf("service should be constructed")
	}
}
