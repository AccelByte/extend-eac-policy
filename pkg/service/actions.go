package service

import (
	"context"
	"time"

	"extend-eac-policy/pkg/common"
	pb "extend-eac-policy/pkg/pb"
	"strings"

	"github.com/AccelByte/accelbyte-go-sdk/gametelemetry-sdk/pkg/gametelemetryclient/gametelemetry_operations"
	"github.com/AccelByte/accelbyte-go-sdk/gametelemetry-sdk/pkg/gametelemetryclientmodels"
	"github.com/AccelByte/accelbyte-go-sdk/iam-sdk/pkg/iamclient/users"
	"github.com/AccelByte/accelbyte-go-sdk/iam-sdk/pkg/iamclientmodels"
	"github.com/AccelByte/accelbyte-go-sdk/reporting-sdk/pkg/reportingclient/admin_reports"
	"github.com/AccelByte/accelbyte-go-sdk/reporting-sdk/pkg/reportingclientmodels"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/gametelemetry"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/iam"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/reporting"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ActionClientConfig struct {
	IAMUsersService  iam.UsersService
	ReportingService reporting.AdminReportsService
	TelemetryService gametelemetry.GametelemetryOperationsService
	Logger           *logrus.Logger
}

// ActionHandler abstracts side effects for telemetry, reporting, and bans.
type ActionHandler interface {
	ApplyBan(ctx context.Context, req *pb.EACReportRequest, plan Reaction) error
	SendTelemetry(ctx context.Context, req *pb.EACReportRequest, plan Reaction, source string) error
	SubmitReport(ctx context.Context, req *pb.EACReportRequest, source string) (bool, error)
}

type ActionClients struct {
	users     iam.UsersService
	reporting reporting.AdminReportsService
	telemetry gametelemetry.GametelemetryOperationsService
	logger    *logrus.Entry
	namespace string
}

var _ ActionHandler = (*ActionClients)(nil)

func NewActionClients(cfg ActionClientConfig) *ActionClients {
	return &ActionClients{
		users:     cfg.IAMUsersService,
		reporting: cfg.ReportingService,
		telemetry: cfg.TelemetryService,
		logger:    cfg.Logger.WithField("component", "actions"),
		namespace: common.GetEnv("AB_NAMESPACE", "accelbyte"),
	}
}

func (a *ActionClients) SendTelemetry(ctx context.Context, req *pb.EACReportRequest, plan Reaction, source string) error {
	eventName := "anti_cheat.eac.report"
	eventNamespace := a.namespace
	body := &gametelemetryclientmodels.TelemetryBody{
		EventName:      &eventName,
		EventNamespace: &eventNamespace,
		// Payload kept simple; extend as needed.
		Payload: map[string]interface{}{
			"userId":   req.UserId,
			"reason":   req.ClientActionReason.String(),
			"details":  req.ClientActionDetailsReasonString,
			"action":   plan.action.String(),
			"source":   source,
			"banUntil": time.Now().UTC().Add(plan.banDuration).Format(time.RFC3339),
		},
	}

	params := gametelemetry_operations.NewProtectedSaveEventsGameTelemetryV1ProtectedEventsPostParams()
	params.Body = []*gametelemetryclientmodels.TelemetryBody{body}
	params.Context = ctx

	err := a.telemetry.ProtectedSaveEventsGameTelemetryV1ProtectedEventsPostShort(params)
	if err != nil {
		a.logger.WithError(err).Warn("telemetry send failed")
		return err
	}

	return nil
}

func (a *ActionClients) SubmitReport(ctx context.Context, req *pb.EACReportRequest, source string) (bool, error) {
	category := "EXTENSION"
	reason := req.ClientActionReason.String()
	body := &reportingclientmodels.RestapiSubmitReportRequest{
		Category:          &category,
		Reason:            &reason,
		UserID:            &req.UserId,
		Comment:           req.ClientActionDetailsReasonString,
		ExtensionCategory: "EAC",
		AdditionalInfo: map[string]interface{}{
			"clientActionReason": req.ClientActionReason.String(),
			"details":            req.ClientActionDetailsReasonString,
		},
	}

	params := admin_reports.NewAdminSubmitReportParams()
	params.Context = ctx
	params.Namespace = a.namespace
	params.Body = body

	_, err := a.reporting.AdminSubmitReportShort(params)
	if err != nil {
		if source == "admin" && isNonUserTokenError(err) {
			a.logger.WithError(err).Warn("moderation report skipped: client token not accepted")

			return false, nil
		}

		a.logger.WithError(err).Warn("moderation report failed")
		return false, err
	}

	return true, nil
}

func (a *ActionClients) ApplyBan(ctx context.Context, req *pb.EACReportRequest, plan Reaction) error {
	if plan.action != pb.AppliedAction_TEMP_BANNED && plan.action != pb.AppliedAction_PERM_BANNED {
		return nil
	}

	endDate := "9999-12-31T23:59:59Z"
	if plan.action == pb.AppliedAction_TEMP_BANNED && plan.banDuration > 0 {
		endDate = time.Now().UTC().Add(plan.banDuration).Format(time.RFC3339)
	}

	banType := "LOGIN"
	comment := "EAC auto-enforcement"
	reason := req.ClientActionReason.String()
	skipNotif := true

	body := &iamclientmodels.ModelBanCreateRequest{
		Ban:       &banType,
		Comment:   &comment,
		EndDate:   &endDate,
		Reason:    &reason,
		SkipNotif: &skipNotif,
	}

	params := users.NewAdminBanUserV3Params()
	params.Context = ctx
	params.Namespace = a.namespace
	params.UserID = req.UserId
	params.Body = body

	_, err := a.users.AdminBanUserV3Short(params)
	if err != nil {
		a.logger.WithError(err).Warn("ban application failed")
		return errors.Wrap(err, "ban user")
	}

	return nil
}

func isNonUserTokenError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "token is not user token") || strings.Contains(msg, "errorcode\": 20022")
}
