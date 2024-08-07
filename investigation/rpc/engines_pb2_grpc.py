# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import engines_pb2 as engines__pb2


class EnginesStub(object):
    """The greeting service definition.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.CheckAlive = channel.unary_unary(
                '/rpc.Engines/CheckAlive',
                request_serializer=engines__pb2.CheckAliveRequest.SerializeToString,
                response_deserializer=engines__pb2.CheckAliveReply.FromString,
                )
        self.Set = channel.unary_unary(
                '/rpc.Engines/Set',
                request_serializer=engines__pb2.SetRequest.SerializeToString,
                response_deserializer=engines__pb2.SetReply.FromString,
                )
        self.Get = channel.unary_unary(
                '/rpc.Engines/Get',
                request_serializer=engines__pb2.GetRequest.SerializeToString,
                response_deserializer=engines__pb2.GetReply.FromString,
                )
        self.Run = channel.unary_unary(
                '/rpc.Engines/Run',
                request_serializer=engines__pb2.RunRequest.SerializeToString,
                response_deserializer=engines__pb2.RunReply.FromString,
                )


class EnginesServicer(object):
    """The greeting service definition.
    """

    def CheckAlive(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Set(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Get(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Run(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_EnginesServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'CheckAlive': grpc.unary_unary_rpc_method_handler(
                    servicer.CheckAlive,
                    request_deserializer=engines__pb2.CheckAliveRequest.FromString,
                    response_serializer=engines__pb2.CheckAliveReply.SerializeToString,
            ),
            'Set': grpc.unary_unary_rpc_method_handler(
                    servicer.Set,
                    request_deserializer=engines__pb2.SetRequest.FromString,
                    response_serializer=engines__pb2.SetReply.SerializeToString,
            ),
            'Get': grpc.unary_unary_rpc_method_handler(
                    servicer.Get,
                    request_deserializer=engines__pb2.GetRequest.FromString,
                    response_serializer=engines__pb2.GetReply.SerializeToString,
            ),
            'Run': grpc.unary_unary_rpc_method_handler(
                    servicer.Run,
                    request_deserializer=engines__pb2.RunRequest.FromString,
                    response_serializer=engines__pb2.RunReply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'rpc.Engines', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Engines(object):
    """The greeting service definition.
    """

    @staticmethod
    def CheckAlive(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Engines/CheckAlive',
            engines__pb2.CheckAliveRequest.SerializeToString,
            engines__pb2.CheckAliveReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Set(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Engines/Set',
            engines__pb2.SetRequest.SerializeToString,
            engines__pb2.SetReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Get(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Engines/Get',
            engines__pb2.GetRequest.SerializeToString,
            engines__pb2.GetReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Run(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Engines/Run',
            engines__pb2.RunRequest.SerializeToString,
            engines__pb2.RunReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
