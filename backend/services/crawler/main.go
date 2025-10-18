package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/cobra-ai/crawler/proto"
	"github.com/cobra-ai/crawler/internal/crawler"
)

type server struct {
	pb.UnimplementedWebCrawlerServer
	crawler   *crawler.WebCrawler
	logger    *zap.Logger
	startTime time.Time
}

func NewServer(logger *zap.Logger) *server {
	return &server{
		crawler:   crawler.New(logger),
		logger:    logger,
		startTime: time.Now(),
	}
}

func (s *server) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status:        "healthy",
		ServiceName:   "COBRA AI Web Crawler",
		Version:       "1.0.0",
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
	}, nil
}

func (s *server) CrawlWebsite(req *pb.CrawlRequest, stream pb.WebCrawler_CrawlWebsiteServer) error {
	s.logger.Info("Starting crawl", zap.String("url", req.Url))
	
	opts := crawler.CrawlOptions{
		MaxDepth:            int(req.Options.MaxDepth),
		MaxPages:            int(req.Options.MaxPages),
		FollowExternalLinks: req.Options.FollowExternalLinks,
		RespectRobotsTxt:    req.Options.RespectRobotsTxt,
		AllowedDomains:      req.Options.AllowedDomains,
		ExcludedPaths:       req.Options.ExcludedPaths,
		ConcurrentRequests:  int(req.Options.ConcurrentRequests),
		DelayMs:             int(req.Options.DelayMs),
		UserAgent:           req.Options.UserAgent,
		JavascriptRendering: req.Options.JavascriptRendering,
		CustomHeaders:       req.Options.CustomHeaders,
	}
	
	resultChan := make(chan *pb.CrawlResult)
	errChan := make(chan error)
	
	go func() {
		err := s.crawler.Crawl(req.Url, opts, resultChan)
		if err != nil {
			errChan <- err
		}
		close(resultChan)
	}()
	
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				return nil
			}
			if err := stream.Send(result); err != nil {
				return err
			}
		case err := <-errChan:
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *server) ExtractData(ctx context.Context, req *pb.ExtractRequest) (*pb.ExtractResponse, error) {
	s.logger.Info("Extracting data", zap.String("url", req.Url))
	
	selectors := make([]crawler.Selector, len(req.Selectors))
	for i, sel := range req.Selectors {
		selectors[i] = crawler.Selector{
			Name:        sel.Name,
			CSSSelector: sel.CssSelector,
			XPath:       sel.Xpath,
			Attribute:   sel.Attribute,
			Multiple:    sel.Multiple,
		}
	}
	
	data, err := s.crawler.ExtractData(req.Url, selectors, req.JavascriptRendering)
	if err != nil {
		return &pb.ExtractResponse{
			Status: &pb.Status{
				Success: false,
				Message: err.Error(),
			},
		}, nil
	}
	
	extractedData := make(map[string]*pb.ExtractedData)
	for name, values := range data {
		extractedData[name] = &pb.ExtractedData{
			Values: values,
		}
	}
	
	return &pb.ExtractResponse{
		Status: &pb.Status{
			Success: true,
			Message: "Data extracted successfully",
		},
		Data: extractedData,
	}, nil
}

func (s *server) TakeScreenshot(ctx context.Context, req *pb.ScreenshotRequest) (*pb.ScreenshotResponse, error) {
	s.logger.Info("Taking screenshot", zap.String("url", req.Url))
	
	opts := crawler.ScreenshotOptions{
		Width:           int(req.Options.Width),
		Height:          int(req.Options.Height),
		FullPage:        req.Options.FullPage,
		Quality:         int(req.Options.Quality),
		Format:          req.Options.Format,
		WaitMs:          int(req.Options.WaitMs),
		WaitForSelector: req.Options.WaitForSelector,
	}
	
	imageData, width, height, err := s.crawler.TakeScreenshot(req.Url, opts)
	if err != nil {
		return &pb.ScreenshotResponse{
			Status: &pb.Status{
				Success: false,
				Message: err.Error(),
			},
		}, nil
	}
	
	return &pb.ScreenshotResponse{
		Status: &pb.Status{
			Success: true,
			Message: "Screenshot taken successfully",
		},
		ImageData: imageData,
		Format:    opts.Format,
		Width:     int32(width),
		Height:    int32(height),
	}, nil
}

func (s *server) FindSubdomains(ctx context.Context, req *pb.SubdomainRequest) (*pb.SubdomainResponse, error) {
	s.logger.Info("Finding subdomains", zap.String("domain", req.Domain))
	
	subdomains, err := s.crawler.FindSubdomains(req.Domain, req.Sources)
	if err != nil {
		return &pb.SubdomainResponse{
			Status: &pb.Status{
				Success: false,
				Message: err.Error(),
			},
		}, nil
	}
	
	var subdomainInfos []*pb.SubdomainInfo
	for _, sub := range subdomains {
		subdomainInfos = append(subdomainInfos, &pb.SubdomainInfo{
			Subdomain:   sub.Subdomain,
			IpAddresses: sub.IPAddresses,
			Source:      sub.Source,
			Active:      sub.Active,
		})
	}
	
	return &pb.SubdomainResponse{
		Status: &pb.Status{
			Success: true,
			Message: fmt.Sprintf("Found %d subdomains", len(subdomainInfos)),
		},
		Subdomains: subdomainInfos,
	}, nil
}

func (s *server) CheckRobotsTxt(ctx context.Context, req *pb.RobotsTxtRequest) (*pb.RobotsTxtResponse, error) {
	s.logger.Info("Checking robots.txt", zap.String("url", req.Url))
	
	robotsInfo, err := s.crawler.CheckRobotsTxt(req.Url, req.UserAgent)
	if err != nil {
		return &pb.RobotsTxtResponse{
			Status: &pb.Status{
				Success: false,
				Message: err.Error(),
			},
		}, nil
	}
	
	return &pb.RobotsTxtResponse{
		Status: &pb.Status{
			Success: true,
			Message: "Robots.txt checked successfully",
		},
		Exists:         robotsInfo.Exists,
		Content:        robotsInfo.Content,
		DisallowedPaths: robotsInfo.DisallowedPaths,
		AllowedPaths:   robotsInfo.AllowedPaths,
		Sitemaps:       robotsInfo.Sitemaps,
		CrawlDelay:     int32(robotsInfo.CrawlDelay),
	}, nil
}

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Get port from environment or use default
	port := os.Getenv("CRAWLER_SERVICE_PORT")
	if port == "" {
		port = "8004"
	}

	// Create listener
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logger.Fatal("Failed to listen", zap.Error(err))
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	
	// Register services
	crawlerServer := NewServer(logger)
	pb.RegisterWebCrawlerServer(grpcServer, crawlerServer)
	
	// Register health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	
	// Register reflection service
	reflection.Register(grpcServer)

	// Start server in goroutine
	go func() {
		logger.Info("🕷️ Go Web Crawler listening", zap.String("port", port))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("Failed to serve", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down server...")
	grpcServer.GracefulStop()
} 