// Copyright (c) 2023 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

package common

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	pb "extend-eac-policy/pkg/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/AccelByte/accelbyte-go-sdk/iam-sdk/pkg/iamclientmodels"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/iam"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/utils/auth/validator"
	"github.com/pkg/errors"
)

var (
	Validator validator.AuthTokenValidator
)

type ProtoPermissionExtractor interface {
	ExtractPermission(infoUnary *grpc.UnaryServerInfo, infoStream *grpc.StreamServerInfo) (permission *iam.Permission, err error)
}

func NewProtoPermissionExtractor() *ProtoPermissionExtractorImpl {
	return &ProtoPermissionExtractorImpl{}
}

type ProtoPermissionExtractorImpl struct{}

func (p *ProtoPermissionExtractorImpl) ExtractPermission(infoUnary *grpc.UnaryServerInfo, infoStream *grpc.StreamServerInfo) (*iam.Permission, error) {
	if infoUnary != nil && infoStream != nil {
		return nil, errors.New("both infoUnary and infoStream cannot be filled at the same time")
	}

	var serviceName string
	var methodName string
	var err error

	if infoUnary != nil {
		serviceName, methodName, err = parseFullMethod(infoUnary.FullMethod)
	} else if infoStream != nil {
		serviceName, methodName, err = parseFullMethod(infoStream.FullMethod)
	} else {
		return nil, errors.New("both infoUnary and infoStream are nil")
	}
	if err != nil {
		return nil, err
	}

	// Read the required permission stated in the proto file
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(serviceName))
	if err != nil {
		return nil, err
	}

	serviceDesc := desc.(protoreflect.ServiceDescriptor)
	method := serviceDesc.Methods().ByName(protoreflect.Name(methodName))
	resource := proto.GetExtension(method.Options(), pb.E_Resource).(string)
	action := proto.GetExtension(method.Options(), pb.E_Action).(pb.Action)
	permission := wrapPermission(resource, int(action.Number()))

	if resource == "" {
		return nil, nil
	}

	return &permission, nil
}

func NewUnaryAuthServerIntercept(
	permissionExtractor ProtoPermissionExtractor,
) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) { // nolint

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !skipCheckAuthorizationMetadata(info.FullMethod) {
			// Extract permission stated in the proto file
			permission, err := permissionExtractor.ExtractPermission(info, nil)
			if err != nil {
				return nil, err
			}

			err = checkAuthorizationMetadata(ctx, permission)
			if err != nil {
				return nil, err
			}
		}

		return handler(ctx, req)
	}
}

func parseFullMethod(fullMethod string) (string, string, error) {
	// Define the regular expression according to example shown here https://github.com/grpc/grpc-java/issues/4726
	re := regexp.MustCompile(`^/([^/]+)/([^/]+)$`)
	matches := re.FindStringSubmatch(fullMethod)

	// Validate the match
	if matches == nil {
		return "", "", fmt.Errorf("invalid FullMethod format")
	}

	// Extract service and method names
	serviceName, methodName := matches[1], matches[2]

	if len(serviceName) == 0 {
		return "", "", fmt.Errorf("invalid FullMethod format: service name is empty")
	}

	if len(methodName) == 0 {
		return "", "", fmt.Errorf("invalid FullMethod format: method name is empty")
	}

	return serviceName, methodName, nil
}

func NewStreamAuthServerIntercept(
	permissionExtractor ProtoPermissionExtractor,
) func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !skipCheckAuthorizationMetadata(info.FullMethod) {
			// Permission extraction is intentionally ignored; we only validate token authenticity.
			err := checkAuthorizationMetadata(ss.Context(), nil)
			if err != nil {
				return err
			}
		}

		return handler(srv, ss)
	}
}

func skipCheckAuthorizationMetadata(fullMethod string) bool {
	if strings.HasPrefix(fullMethod, "/grpc.reflection.v1alpha.ServerReflection/") {
		return true
	}

	if strings.HasPrefix(fullMethod, "/grpc.health.v1.Health/") {
		return true
	}

	return false
}

func checkAuthorizationMetadata(ctx context.Context, permission *iam.Permission) error {
	if Validator == nil {
		return status.Error(codes.Internal, "authorization token validator is not set")
	}

	// Permission check is disabled; we only validate token presence and authenticity.
	permission = nil

	meta, found := metadata.FromIncomingContext(ctx)

	if !found {
		return status.Error(codes.Unauthenticated, "metadata is missing")
	}

	if _, ok := meta["authorization"]; !ok {
		return status.Error(codes.Unauthenticated, "authorization metadata is missing")
	}

	if len(meta["authorization"]) == 0 {
		return status.Error(codes.Unauthenticated, "authorization metadata length is 0")
	}

	authorization := meta["authorization"][0]
	token := strings.TrimPrefix(authorization, "Bearer ")
	namespace := getNamespace()

	err := Validator.Validate(token, permission, &namespace, nil)

	if err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}

	return nil
}

func getNamespace() string {
	return GetEnv("AB_NAMESPACE", "accelbyte")
}

func wrapPermission(resource string, action int) iam.Permission {
	return iam.Permission{
		Action:   action,
		Resource: resource,
	}
}

func NewTokenValidator(authService iam.OAuth20Service, refreshInterval time.Duration, validateLocally bool) validator.AuthTokenValidator {
	return &iam.TokenValidator{
		AuthService:     authService,
		RefreshInterval: refreshInterval,

		Filter:                nil,
		JwkSet:                nil,
		JwtClaims:             iam.JWTClaims{},
		JwtEncoding:           *base64.URLEncoding.WithPadding(base64.NoPadding),
		PublicKeys:            make(map[string]*rsa.PublicKey),
		LocalValidationActive: validateLocally,
		RevokedUsers:          make(map[string]time.Time),
		Roles:                 make(map[string]*iamclientmodels.ModelRolePermissionResponseV3),
	}
}
