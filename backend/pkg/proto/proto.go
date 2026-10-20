package proto

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Martin2877/blue-team-box/engine"

	"log"
	"net"

	"github.com/Martin2877/blue-team-box/pkg/conf"

	pb "github.com/Martin2877/blue-team-box/pkg/proto/pb"
	"google.golang.org/grpc"
)

// BTAB

type gRPCBTABServer struct {
	pb.UnimplementedBTABServer
}

// Ping 这里实现服务端接口中的方法。
func (ins *gRPCBTABServer) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PingReply, error) {
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  "Pong",
		Type:    "success",
	}
	return &pb.PingReply{Message: &jResp}, nil
}

// Engines 每个请求创建独立实例，避免并发请求共享 GlobalPayloads/Steps 造成数据竞争
func newEngines() *engine.Engines {
	return engine.NewEngines()
}

type gRPCEnginesServer struct {
	pb.UnimplementedEnginesServer
}

func (ins *gRPCEnginesServer) CheckAlive(ctx context.Context, in *pb.CheckAliveRequest) (*pb.CheckAliveReply, error) {
	// TODO
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  "todo",
		Type:    "success",
	}
	return &pb.CheckAliveReply{Message: &jResp}, nil
}

func (ins *gRPCEnginesServer) Set(ctx context.Context, in *pb.SetRequest) (*pb.SetReply, error) {
	engines := newEngines()
	engines.SetGlobalFieldValues(in.Name, in.Content)
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  strconv.Itoa(len(engines.GlobalPayloads)),
		Type:    "success",
	}
	return &pb.SetReply{Message: &jResp}, nil
}

func (ins *gRPCEnginesServer) Get(ctx context.Context, in *pb.GetRequest) (*pb.GetReply, error) {
	engines := newEngines()
	value, ok := engines.GlobalPayloads[in.Name]
	if ok {
		jResp := pb.ResponseType{
			Code:    20000,
			Message: "",
			Result:  value,
			Type:    "success",
		}
		return &pb.GetReply{Message: &jResp}, nil
	}
	jResp := pb.ResponseType{
		Code:    40000,
		Message: "找不到相关变量",
		Result:  "",
		Type:    "failed",
	}
	return &pb.GetReply{Message: &jResp}, nil

}

func (ins *gRPCEnginesServer) Run(ctx context.Context, in *pb.RunRequest) (*pb.RunReply, error) {
	var err error
	engines := newEngines()
	// 清除原有的 steps
	engines.ClearSteps()

	err = engines.LoadQueries(in.Content)
	if err != nil {
		jResp := pb.ResponseType{
			Code:    40000,
			Message: err.Error(),
			Result:  "",
			Type:    "failed",
		}
		return &pb.RunReply{Message: &jResp}, nil
	}
	err = engines.Run()
	if err != nil {
		jResp := pb.ResponseType{
			Code:    40000,
			Message: err.Error(),
			Result:  "",
			Type:    "failed",
		}
		return &pb.RunReply{Message: &jResp}, nil
	}
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  engines.GetFinalResult(),
		Type:    "success",
	}
	return &pb.RunReply{Message: &jResp}, nil
}

type gRPCSearchServer struct {
	pb.UnimplementedSearchServer
}

func (ins *gRPCSearchServer) CheckConnection(ctx context.Context, in *pb.CheckConnectionRequest) (*pb.CheckConnectionReply, error) {
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  "Pong",
		Type:    "success",
	}
	return &pb.CheckConnectionReply{Message: &jResp}, nil
}

func (ins *gRPCSearchServer) Submit(ctx context.Context, in *pb.SubmitRequest) (*pb.SubmitReply, error) {
	var err error
	engines := newEngines()
	engines.ClearSteps()
	err = engines.LoadQueries(in.Content)
	if err != nil {
		jResp := pb.ResponseType{
			Code:    40000,
			Message: err.Error(),
			Result:  "",
			Type:    "failed",
		}
		return &pb.SubmitReply{Message: &jResp}, nil
	}
	// 开始执行各引擎
	err = engines.Run()
	if err != nil {
		jResp := pb.ResponseType{
			Code:    40000,
			Message: err.Error(),
			Result:  "",
			Type:    "failed",
		}
		return &pb.SubmitReply{Message: &jResp}, nil
	}

	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  engines.GetFinalResult(),
		Type:    "success",
	}
	return &pb.SubmitReply{Message: &jResp}, nil
}

func (ins *gRPCSearchServer) Save(ctx context.Context, in *pb.SaveRequest) (*pb.SaveReply, error) {
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  "Pong",
		Type:    "success",
	}
	return &pb.SaveReply{Message: &jResp}, nil
}

func (ins *gRPCSearchServer) SubmitByName(ctx context.Context, in *pb.SubmitByNameRequest) (*pb.SubmitByNameReply, error) {
	jResp := pb.ResponseType{
		Code:    20000,
		Message: "",
		Result:  "Pong",
		Type:    "success",
	}
	return &pb.SubmitByNameReply{Message: &jResp}, nil
}

func RunGRPCServer(port string) {
	var address string
	if port != "" {
		address = fmt.Sprintf(":%s", port)
	} else if conf.GlobalConfig.GRPCConfig.Address != "" {
		address = conf.GlobalConfig.GRPCConfig.Address
	} else {
		log.Fatalf("grpc address not found")
	}
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterBTABServer(s, &gRPCBTABServer{})
	pb.RegisterEnginesServer(s, &gRPCEnginesServer{})
	pb.RegisterSearchServer(s, &gRPCSearchServer{})

	fmt.Printf("Starting gRPC listen on: %s\n", address)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
