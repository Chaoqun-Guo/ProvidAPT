// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Code generated hand-written gRPC service definitions for ProvidAPT mgmt proto.
// Equivalent to what protoc-gen-go-grpc would generate.

package mgmt

import (
	"context"

	"google.golang.org/grpc"
)

// ─── ProvidAPTManagement Server ──────────────────────────────

// ProvidAPTManagementServer is the server API for ProvidAPTManagement service.
type ProvidAPTManagementServer interface {
	Query(context.Context, *QueryRequest) (*QueryResponse, error)
	WatchAlerts(*AlertFilter, ProvidAPTManagement_WatchAlertsServer) error
	UpdatePolicy(context.Context, *PolicyUpdate) (*PolicyAck, error)
	Check(context.Context, *HealthCheck) (*HealthStatus, error)
}

// ProvidAPTManagement_WatchAlertsServer is the server stream for WatchAlerts.
type ProvidAPTManagement_WatchAlertsServer interface {
	Send(*AlertEvent) error
	grpc.ServerStream
}

// RegisterProvidAPTManagementServer registers the management service.
func RegisterProvidAPTManagementServer(s grpc.ServiceRegistrar, srv ProvidAPTManagementServer) {
	s.RegisterService(&ProvidAPTManagement_ServiceDesc, srv)
}

// ProvidAPTManagement_ServiceDesc is the grpc.ServiceDesc for ProvidAPTManagement.
var ProvidAPTManagement_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "providapt.mgmt.ProvidAPTManagement",
	HandlerType: (*ProvidAPTManagementServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Query",
			Handler:    _ProvidAPTManagement_Query_Handler,
		},
		{
			MethodName: "UpdatePolicy",
			Handler:    _ProvidAPTManagement_UpdatePolicy_Handler,
		},
		{
			MethodName: "Check",
			Handler:    _ProvidAPTManagement_Check_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "WatchAlerts",
			Handler:       _ProvidAPTManagement_WatchAlerts_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "mgmt.proto",
}

func _ProvidAPTManagement_Query_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProvidAPTManagementServer).Query(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/providapt.mgmt.ProvidAPTManagement/Query",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProvidAPTManagementServer).Query(ctx, req.(*QueryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ProvidAPTManagement_WatchAlerts_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(AlertFilter)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ProvidAPTManagementServer).WatchAlerts(m, &providaptManagementWatchAlertsServer{stream})
}

type providaptManagementWatchAlertsServer struct {
	grpc.ServerStream
}

func (x *providaptManagementWatchAlertsServer) Send(m *AlertEvent) error {
	return x.ServerStream.SendMsg(m)
}

func _ProvidAPTManagement_UpdatePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PolicyUpdate)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProvidAPTManagementServer).UpdatePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/providapt.mgmt.ProvidAPTManagement/UpdatePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProvidAPTManagementServer).UpdatePolicy(ctx, req.(*PolicyUpdate))
	}
	return interceptor(ctx, in, info, handler)
}

func _ProvidAPTManagement_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealthCheck)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProvidAPTManagementServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/providapt.mgmt.ProvidAPTManagement/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProvidAPTManagementServer).Check(ctx, req.(*HealthCheck))
	}
	return interceptor(ctx, in, info, handler)
}

// ─── ProvidAPTTelemetry Client ───────────────────────────────

// ProvidAPTTelemetryClient is the client API for ProvidAPTTelemetry service.
type ProvidAPTTelemetryClient interface {
	ReportEvents(ctx context.Context, opts ...grpc.CallOption) (ProvidAPTTelemetry_ReportEventsClient, error)
}

type providaptAPTTelemetryClient struct {
	cc grpc.ClientConnInterface
}

// NewProvidAPTTelemetryClient creates a new ProvidAPTTelemetryClient.
func NewProvidAPTTelemetryClient(cc grpc.ClientConnInterface) ProvidAPTTelemetryClient {
	return &providaptAPTTelemetryClient{cc}
}

func (c *providaptAPTTelemetryClient) ReportEvents(ctx context.Context, opts ...grpc.CallOption) (ProvidAPTTelemetry_ReportEventsClient, error) {
	stream, err := c.cc.NewStream(ctx, &ProvidAPTTelemetry_ServiceDesc.Streams[0], "/providapt.mgmt.ProvidAPTTelemetry/ReportEvents", opts...)
	if err != nil {
		return nil, err
	}
	x := &providaptAPTTelemetryReportEventsClient{stream}
	return x, nil
}

// ProvidAPTTelemetry_ReportEventsClient is the client stream for ReportEvents.
type ProvidAPTTelemetry_ReportEventsClient interface {
	Send(*CompressedEvent) error
	CloseAndRecv() (*ReportAck, error)
	grpc.ClientStream
}

type providaptAPTTelemetryReportEventsClient struct {
	grpc.ClientStream
}

func (x *providaptAPTTelemetryReportEventsClient) Send(m *CompressedEvent) error {
	return x.ClientStream.SendMsg(m)
}

func (x *providaptAPTTelemetryReportEventsClient) CloseAndRecv() (*ReportAck, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(ReportAck)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ProvidAPTTelemetry_ServiceDesc is the grpc.ServiceDesc for ProvidAPTTelemetry.
var ProvidAPTTelemetry_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "providapt.mgmt.ProvidAPTTelemetry",
	HandlerType: (*ProvidAPTTelemetryServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ReportEvents",
			Handler:       _ProvidAPTTelemetry_ReportEvents_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "mgmt.proto",
}

// ProvidAPTTelemetryServer is the server API for ProvidAPTTelemetry service.
type ProvidAPTTelemetryServer interface {
	ReportEvents(ProvidAPTTelemetry_ReportEventsServer) error
}

// RegisterProvidAPTTelemetryServer registers the telemetry service.
func RegisterProvidAPTTelemetryServer(s grpc.ServiceRegistrar, srv ProvidAPTTelemetryServer) {
	s.RegisterService(&ProvidAPTTelemetry_ServiceDesc, srv)
}

// ProvidAPTTelemetry_ReportEventsServer is the server stream for ReportEvents.
type ProvidAPTTelemetry_ReportEventsServer interface {
	SendAndClose(*ReportAck) error
	Recv() (*CompressedEvent, error)
	grpc.ServerStream
}

type providaptAPTTelemetryReportEventsServer struct {
	grpc.ServerStream
}

func (x *providaptAPTTelemetryReportEventsServer) SendAndClose(m *ReportAck) error {
	return x.ServerStream.SendMsg(m)
}

func (x *providaptAPTTelemetryReportEventsServer) Recv() (*CompressedEvent, error) {
	m := new(CompressedEvent)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _ProvidAPTTelemetry_ReportEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ProvidAPTTelemetryServer).ReportEvents(&providaptAPTTelemetryReportEventsServer{stream})
}
