// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: remotesignerrpc/remotesigner.proto

/*
Package remotesignerrpc is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package remotesignerrpc

import (
	"context"
	"io"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/v2/utilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Suppress "imported and not used" errors
var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray
var _ = metadata.Join

func request_RemoteSigner_WhitelistAddress_0(ctx context.Context, marshaler runtime.Marshaler, client RemoteSignerClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistAddressRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.WhitelistAddress(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_RemoteSigner_WhitelistAddress_0(ctx context.Context, marshaler runtime.Marshaler, server RemoteSignerServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistAddressRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.WhitelistAddress(ctx, &protoReq)
	return msg, metadata, err

}

func request_RemoteSigner_WhitelistedAddresses_0(ctx context.Context, marshaler runtime.Marshaler, client RemoteSignerClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistedAddressesRequest
	var metadata runtime.ServerMetadata

	msg, err := client.WhitelistedAddresses(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_RemoteSigner_WhitelistedAddresses_0(ctx context.Context, marshaler runtime.Marshaler, server RemoteSignerServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistedAddressesRequest
	var metadata runtime.ServerMetadata

	msg, err := server.WhitelistedAddresses(ctx, &protoReq)
	return msg, metadata, err

}

func request_RemoteSigner_RemoveWhitelistedAddress_0(ctx context.Context, marshaler runtime.Marshaler, client RemoteSignerClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq RemoveWhitelistAddressRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["address"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "address")
	}

	protoReq.Address, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "address", err)
	}

	msg, err := client.RemoveWhitelistedAddress(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_RemoteSigner_RemoveWhitelistedAddress_0(ctx context.Context, marshaler runtime.Marshaler, server RemoteSignerServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq RemoveWhitelistAddressRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["address"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "address")
	}

	protoReq.Address, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "address", err)
	}

	msg, err := server.RemoveWhitelistedAddress(ctx, &protoReq)
	return msg, metadata, err

}

func request_RemoteSigner_WhitelistPaymentHash_0(ctx context.Context, marshaler runtime.Marshaler, client RemoteSignerClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistPaymentHashRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.WhitelistPaymentHash(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_RemoteSigner_WhitelistPaymentHash_0(ctx context.Context, marshaler runtime.Marshaler, server RemoteSignerServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistPaymentHashRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.WhitelistPaymentHash(ctx, &protoReq)
	return msg, metadata, err

}

func request_RemoteSigner_WhitelistedPaymentHashes_0(ctx context.Context, marshaler runtime.Marshaler, client RemoteSignerClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistedPaymentHashesRequest
	var metadata runtime.ServerMetadata

	msg, err := client.WhitelistedPaymentHashes(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_RemoteSigner_WhitelistedPaymentHashes_0(ctx context.Context, marshaler runtime.Marshaler, server RemoteSignerServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq WhitelistedPaymentHashesRequest
	var metadata runtime.ServerMetadata

	msg, err := server.WhitelistedPaymentHashes(ctx, &protoReq)
	return msg, metadata, err

}

func request_RemoteSigner_RemoveWhitelistedPaymentHash_0(ctx context.Context, marshaler runtime.Marshaler, client RemoteSignerClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq RemoveWhitelistPaymentHashRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["payment_hash"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "payment_hash")
	}

	protoReq.PaymentHash, err = runtime.Bytes(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "payment_hash", err)
	}

	msg, err := client.RemoveWhitelistedPaymentHash(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_RemoteSigner_RemoveWhitelistedPaymentHash_0(ctx context.Context, marshaler runtime.Marshaler, server RemoteSignerServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq RemoveWhitelistPaymentHashRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["payment_hash"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "payment_hash")
	}

	protoReq.PaymentHash, err = runtime.Bytes(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "payment_hash", err)
	}

	msg, err := server.RemoveWhitelistedPaymentHash(ctx, &protoReq)
	return msg, metadata, err

}

// RegisterRemoteSignerHandlerServer registers the http handlers for service RemoteSigner to "mux".
// UnaryRPC     :call RemoteSignerServer directly.
// StreamingRPC :currently unsupported pending https://github.com/grpc/grpc-go/issues/906.
// Note that using this registration option will cause many gRPC library features to stop working. Consider using RegisterRemoteSignerHandlerFromEndpoint instead.
func RegisterRemoteSignerHandlerServer(ctx context.Context, mux *runtime.ServeMux, server RemoteSignerServer) error {

	mux.Handle("POST", pattern_RemoteSigner_WhitelistAddress_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistAddress", runtime.WithHTTPPathPattern("/v2/remotesigner/addresswhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_RemoteSigner_WhitelistAddress_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistAddress_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_RemoteSigner_WhitelistedAddresses_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistedAddresses", runtime.WithHTTPPathPattern("/v2/remotesigner/addresswhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_RemoteSigner_WhitelistedAddresses_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistedAddresses_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_RemoteSigner_RemoveWhitelistedAddress_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/RemoveWhitelistedAddress", runtime.WithHTTPPathPattern("/v2/remotesigner/addresswhitelist/{address}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_RemoteSigner_RemoveWhitelistedAddress_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_RemoveWhitelistedAddress_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_RemoteSigner_WhitelistPaymentHash_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistPaymentHash", runtime.WithHTTPPathPattern("/v2/remotesigner/paymenthashwhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_RemoteSigner_WhitelistPaymentHash_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistPaymentHash_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_RemoteSigner_WhitelistedPaymentHashes_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistedPaymentHashes", runtime.WithHTTPPathPattern("/v2/remotesigner/paymenthashwhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_RemoteSigner_WhitelistedPaymentHashes_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistedPaymentHashes_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_RemoteSigner_RemoveWhitelistedPaymentHash_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/RemoveWhitelistedPaymentHash", runtime.WithHTTPPathPattern("/v2/remotesigner/paymenthashwhitelist/{payment_hash}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_RemoteSigner_RemoveWhitelistedPaymentHash_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_RemoveWhitelistedPaymentHash_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

// RegisterRemoteSignerHandlerFromEndpoint is same as RegisterRemoteSignerHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterRemoteSignerHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterRemoteSignerHandler(ctx, mux, conn)
}

// RegisterRemoteSignerHandler registers the http handlers for service RemoteSigner to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterRemoteSignerHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterRemoteSignerHandlerClient(ctx, mux, NewRemoteSignerClient(conn))
}

// RegisterRemoteSignerHandlerClient registers the http handlers for service RemoteSigner
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "RemoteSignerClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "RemoteSignerClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "RemoteSignerClient" to call the correct interceptors.
func RegisterRemoteSignerHandlerClient(ctx context.Context, mux *runtime.ServeMux, client RemoteSignerClient) error {

	mux.Handle("POST", pattern_RemoteSigner_WhitelistAddress_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistAddress", runtime.WithHTTPPathPattern("/v2/remotesigner/addresswhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_RemoteSigner_WhitelistAddress_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistAddress_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_RemoteSigner_WhitelistedAddresses_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistedAddresses", runtime.WithHTTPPathPattern("/v2/remotesigner/addresswhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_RemoteSigner_WhitelistedAddresses_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistedAddresses_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_RemoteSigner_RemoveWhitelistedAddress_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/RemoveWhitelistedAddress", runtime.WithHTTPPathPattern("/v2/remotesigner/addresswhitelist/{address}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_RemoteSigner_RemoveWhitelistedAddress_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_RemoveWhitelistedAddress_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_RemoteSigner_WhitelistPaymentHash_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistPaymentHash", runtime.WithHTTPPathPattern("/v2/remotesigner/paymenthashwhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_RemoteSigner_WhitelistPaymentHash_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistPaymentHash_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_RemoteSigner_WhitelistedPaymentHashes_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/WhitelistedPaymentHashes", runtime.WithHTTPPathPattern("/v2/remotesigner/paymenthashwhitelist"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_RemoteSigner_WhitelistedPaymentHashes_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_WhitelistedPaymentHashes_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_RemoteSigner_RemoveWhitelistedPaymentHash_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/remotesignerrpc.RemoteSigner/RemoveWhitelistedPaymentHash", runtime.WithHTTPPathPattern("/v2/remotesigner/paymenthashwhitelist/{payment_hash}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_RemoteSigner_RemoveWhitelistedPaymentHash_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_RemoteSigner_RemoveWhitelistedPaymentHash_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_RemoteSigner_WhitelistAddress_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v2", "remotesigner", "addresswhitelist"}, ""))

	pattern_RemoteSigner_WhitelistedAddresses_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v2", "remotesigner", "addresswhitelist"}, ""))

	pattern_RemoteSigner_RemoveWhitelistedAddress_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2, 1, 0, 4, 1, 5, 3}, []string{"v2", "remotesigner", "addresswhitelist", "address"}, ""))

	pattern_RemoteSigner_WhitelistPaymentHash_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v2", "remotesigner", "paymenthashwhitelist"}, ""))

	pattern_RemoteSigner_WhitelistedPaymentHashes_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v2", "remotesigner", "paymenthashwhitelist"}, ""))

	pattern_RemoteSigner_RemoveWhitelistedPaymentHash_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2, 1, 0, 4, 1, 5, 3}, []string{"v2", "remotesigner", "paymenthashwhitelist", "payment_hash"}, ""))
)

var (
	forward_RemoteSigner_WhitelistAddress_0 = runtime.ForwardResponseMessage

	forward_RemoteSigner_WhitelistedAddresses_0 = runtime.ForwardResponseMessage

	forward_RemoteSigner_RemoveWhitelistedAddress_0 = runtime.ForwardResponseMessage

	forward_RemoteSigner_WhitelistPaymentHash_0 = runtime.ForwardResponseMessage

	forward_RemoteSigner_WhitelistedPaymentHashes_0 = runtime.ForwardResponseMessage

	forward_RemoteSigner_RemoveWhitelistedPaymentHash_0 = runtime.ForwardResponseMessage
)
