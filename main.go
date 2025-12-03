// Copyright (c) 2023-2025 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-openapi/loads"

	"extend-eac-policy/pkg/common"
	"extend-eac-policy/pkg/service"

	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/repository"

	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/factory"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/gametelemetry"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/iam"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/reporting"
	"github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/service/session"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "extend-eac-policy/pkg/pb"

	sdkAuth "github.com/AccelByte/accelbyte-go-sdk/services-api/pkg/utils/auth"
	prometheusGrpc "github.com/grpc-ecosystem/go-grpc-prometheus"
	prometheusCollectors "github.com/prometheus/client_golang/prometheus/collectors"
)

const (
	metricsEndpoint     = "/metrics"
	metricsPort         = 8080
	grpcServerPort      = 6565
	grpcGatewayHTTPPort = 8000
)

var (
	serviceName = common.GetEnv("OTEL_SERVICE_NAME", "ExtendCustomServiceGo")
	logLevelStr = common.GetEnv("LOG_LEVEL", logrus.InfoLevel.String())
	basePath    = common.GetBasePath()
)

func main() {
	logrus.Infof("Starting %s...", serviceName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logrusLevel, err := logrus.ParseLevel(logLevelStr)
	if err != nil {
		logrusLevel = logrus.InfoLevel
	}
	logrusLogger := logrus.New()
	logrusLogger.SetLevel(logrusLevel)

	loggingOptions := []logging.Option{
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall, logging.PayloadReceived, logging.PayloadSent),
		logging.WithFieldsFromContext(func(ctx context.Context) logging.Fields {
			if span := trace.SpanContextFromContext(ctx); span.IsSampled() {
				return logging.Fields{"traceID", span.TraceID().String()}
			}

			return nil
		}),
		logging.WithLevels(logging.DefaultClientCodeToLevel),
		logging.WithDurationField(logging.DurationToDurationField),
	}

	unaryServerInterceptors := []grpc.UnaryServerInterceptor{
		prometheusGrpc.UnaryServerInterceptor,
		logging.UnaryServerInterceptor(common.InterceptorLogger(logrusLogger), loggingOptions...),
	}
	streamServerInterceptors := []grpc.StreamServerInterceptor{
		prometheusGrpc.StreamServerInterceptor,
		logging.StreamServerInterceptor(common.InterceptorLogger(logrusLogger), loggingOptions...),
	}

	// Preparing the IAM authorization
	var tokenRepo repository.TokenRepository = sdkAuth.DefaultTokenRepositoryImpl()
	var configRepo repository.ConfigRepository = sdkAuth.DefaultConfigRepositoryImpl()
	var refreshRepo repository.RefreshTokenRepository = &sdkAuth.RefreshTokenImpl{RefreshRate: 0.8, AutoRefresh: true}

	oauthService := iam.OAuth20Service{
		Client:                 factory.NewIamClient(configRepo),
		TokenRepository:        tokenRepo,
		RefreshTokenRepository: refreshRepo,
		ConfigRepository:       configRepo,
	}

	if strings.ToLower(common.GetEnv("PLUGIN_GRPC_SERVER_AUTH_ENABLED", "true")) == "true" {
		refreshInterval := common.GetEnvInt("REFRESH_INTERVAL", 600)
		common.Validator = common.NewTokenValidator(oauthService, time.Duration(refreshInterval)*time.Second, true)
		err := common.Validator.Initialize(ctx)
		if err != nil {
			logrus.Infof("%v", err)
		}

		permissionExtractor := common.NewProtoPermissionExtractor()
		unaryServerInterceptor := common.NewUnaryAuthServerIntercept(permissionExtractor)
		serverServerInterceptor := common.NewStreamAuthServerIntercept(permissionExtractor)

		unaryServerInterceptors = append(unaryServerInterceptors, unaryServerInterceptor)
		streamServerInterceptors = append(streamServerInterceptors, serverServerInterceptor)
		logrus.Infof("added auth interceptors")
	}

	// Create gRPC Server
	s := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(unaryServerInterceptors...),
		grpc.ChainStreamInterceptor(streamServerInterceptors...),
	)

	// Configure IAM authorization
	clientId := configRepo.GetClientId()
	clientSecret := configRepo.GetClientSecret()
	err = oauthService.LoginClient(&clientId, &clientSecret)
	if err != nil {
		logrus.Fatalf("Error unable to login using clientId and clientSecret: %v", err)
	}

	// Register Prometheus Metrics
	prometheusRegistry := prometheus.NewRegistry()
	prometheusRegistry.MustRegister(
		prometheusCollectors.NewGoCollector(),
		prometheusCollectors.NewProcessCollector(prometheusCollectors.ProcessCollectorOpts{}),
		prometheusGrpc.DefaultServerMetrics,
	)

	go func() {
		if strings.ToLower(common.GetEnv("ENABLE_PPROF", "false")) == "true" {
			registerPprofHandlers()
			logrus.Infof("pprof enabled at (:%d/debug/pprof/)", metricsPort)
		}

		http.Handle(metricsEndpoint, promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))
		logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", metricsPort), nil))
	}()
	logrus.Infof("Metrics endpoint: (:%d%s)", metricsPort, metricsEndpoint)

	policies := service.NewPolicyResolver()
	metrics := service.NewMetrics(prometheusRegistry)

	actionClients := service.NewActionClients(service.ActionClientConfig{
		IAMUsersService: iam.UsersService{
			Client:           factory.NewIamClient(configRepo),
			TokenRepository:  tokenRepo,
			ConfigRepository: configRepo,
		},
		ReportingService: reporting.AdminReportsService{
			Client:           factory.NewReportingClient(configRepo),
			TokenRepository:  tokenRepo,
			ConfigRepository: configRepo,
		},
		TelemetryService: gametelemetry.GametelemetryOperationsService{
			Client:          factory.NewGametelemetryClient(configRepo),
			TokenRepository: tokenRepo,
		},
		Logger: logrusLogger,
	})

	sessionService := session.GameSessionService{
		Client:           factory.NewSessionClient(configRepo),
		TokenRepository:  tokenRepo,
		ConfigRepository: configRepo,
	}
	sessionValidator := service.NewGameSessionValidator(&sessionService, common.GetEnv("AB_NAMESPACE", "accelbyte"), logrusLogger)

	antiCheatService := service.NewAntiCheatService(tokenRepo, configRepo, refreshRepo, policies, metrics, logrusLogger, actionClients, sessionValidator)
	pb.RegisterAntiCheatServiceServer(s, antiCheatService)

	// Enable gRPC Reflection
	reflection.Register(s)

	// Enable gRPC Health Check
	grpc_health_v1.RegisterHealthServer(s, health.NewServer())

	// Create a new HTTP server for the gRPC-Gateway
	grpcGateway, err := common.NewGateway(ctx, fmt.Sprintf("localhost:%d", grpcServerPort), basePath)
	if err != nil {
		logrus.Fatalf("Failed to create gRPC-Gateway: %v", err)
	}

	// Start the gRPC-Gateway HTTP server
	go func() {
		swaggerDir := "gateway/apidocs" // Path to swagger directory
		grpcGatewayHTTPServer := newGRPCGatewayHTTPServer(fmt.Sprintf(":%d", grpcGatewayHTTPPort), grpcGateway, logrus.New(), swaggerDir)
		logrus.Infof("Starting gRPC-Gateway HTTP server on port %d", grpcGatewayHTTPPort)
		if err := grpcGatewayHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Failed to run gRPC-Gateway HTTP server: %v", err)
		}
	}()

	prometheusGrpc.Register(s)

	// Set Tracer Provider
	tracerProvider, err := common.NewTracerProvider(serviceName)
	if err != nil {
		logrus.Fatalf("Failed to create tracer provider: %v", err)

		return
	}
	otel.SetTracerProvider(tracerProvider)
	defer func(ctx context.Context) {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			logrus.Fatal(err)
		}
	}(ctx)

	// Set Text Map Propagator
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			b3.New(),
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	// Start gRPC Server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcServerPort))
	if err != nil {
		logrus.Fatalf("Failed to listen to tcp:%d: %v", grpcServerPort, err)

		return
	}
	go func() {
		if err = s.Serve(lis); err != nil {
			logrus.Fatalf("Failed to run gRPC server: %v", err)

			return
		}
	}()

	logrus.Infof("%s started", serviceName)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	logrus.Infof("SIGTERM received")
}

func newGRPCGatewayHTTPServer(
	addr string, handler http.Handler, logger *logrus.Logger, swaggerDir string,
) *http.Server {
	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add the gRPC-Gateway handler
	mux.Handle("/", handler)

	// Serve Swagger UI and JSON
	serveSwaggerUI(mux)
	serveSwaggerJSON(mux, swaggerDir)

	// Add logging middleware
	loggedMux := loggingMiddleware(logger, mux)

	return &http.Server{
		Addr:     addr,
		Handler:  loggedMux,
		ErrorLog: log.New(os.Stderr, "httpSrv: ", log.LstdFlags), // Configure the logger for the HTTP server
	}
}

// loggingMiddleware is a middleware that logs HTTP requests
func loggingMiddleware(logger *logrus.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		logger.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"duration": duration,
		}).Info("HTTP request")
	})
}

func serveSwaggerUI(mux *http.ServeMux) {
	swaggerUIDir := "third_party/swagger-ui"
	fileServer := http.FileServer(http.Dir(swaggerUIDir))
	swaggerUiPath := fmt.Sprintf("%s/apidocs/", basePath)
	mux.Handle(swaggerUiPath, http.StripPrefix(swaggerUiPath, fileServer))
}

func serveSwaggerJSON(mux *http.ServeMux, swaggerDir string) {
	fileHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matchingFiles, err := filepath.Glob(filepath.Join(swaggerDir, "*.swagger.json"))
		if err != nil || len(matchingFiles) == 0 {
			http.Error(w, "Error finding Swagger JSON file", http.StatusInternalServerError)

			return
		}

		firstMatchingFile := matchingFiles[0]
		swagger, err := loads.Spec(firstMatchingFile)
		if err != nil {
			http.Error(w, "Error parsing Swagger JSON file", http.StatusInternalServerError)

			return
		}

		// Update the base path
		swagger.Spec().BasePath = basePath

		updatedSwagger, err := swagger.Spec().MarshalJSON()
		if err != nil {
			http.Error(w, "Error serializing updated Swagger JSON", http.StatusInternalServerError)

			return
		}
		var prettySwagger bytes.Buffer
		err = json.Indent(&prettySwagger, updatedSwagger, "", "  ")
		if err != nil {
			http.Error(w, "Error formatting updated Swagger JSON", http.StatusInternalServerError)

			return
		}

		_, err = w.Write(prettySwagger.Bytes())
		if err != nil {
			http.Error(w, "Error writing Swagger JSON response", http.StatusInternalServerError)

			return
		}
	})
	apidocsPath := fmt.Sprintf("%s/apidocs/api.json", basePath)
	mux.Handle(apidocsPath, fileHandler)
}

func registerPprofHandlers() {
	http.HandleFunc("/debug/pprof/", pprof.Index)
	http.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	http.HandleFunc("/debug/pprof/profile", pprof.Profile)
	http.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	http.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
