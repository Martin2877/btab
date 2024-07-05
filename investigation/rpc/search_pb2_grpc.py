# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import search_pb2 as search__pb2


class SearchStub(object):
    """The greeting service definition.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SetPRS = channel.unary_unary(
                '/rpc.Search/SetPRS',
                request_serializer=search__pb2.SetPRSRequest.SerializeToString,
                response_deserializer=search__pb2.SetPRSReply.FromString,
                )
        self.CheckConnection = channel.unary_unary(
                '/rpc.Search/CheckConnection',
                request_serializer=search__pb2.CheckConnectionRequest.SerializeToString,
                response_deserializer=search__pb2.CheckConnectionReply.FromString,
                )
        self.SetDateRange = channel.unary_unary(
                '/rpc.Search/SetDateRange',
                request_serializer=search__pb2.SetDateRangeRequest.SerializeToString,
                response_deserializer=search__pb2.SetDateRangeReply.FromString,
                )
        self.Submit = channel.unary_unary(
                '/rpc.Search/Submit',
                request_serializer=search__pb2.SubmitRequest.SerializeToString,
                response_deserializer=search__pb2.SubmitReply.FromString,
                )
        self.Save = channel.unary_unary(
                '/rpc.Search/Save',
                request_serializer=search__pb2.SaveRequest.SerializeToString,
                response_deserializer=search__pb2.SaveReply.FromString,
                )
        self.SubmitByName = channel.unary_unary(
                '/rpc.Search/SubmitByName',
                request_serializer=search__pb2.SubmitByNameRequest.SerializeToString,
                response_deserializer=search__pb2.SubmitByNameReply.FromString,
                )


class SearchServicer(object):
    """The greeting service definition.
    """

    def SetPRS(self, request, context):
        """Sends a greeting
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CheckConnection(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SetDateRange(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Submit(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Save(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SubmitByName(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_SearchServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SetPRS': grpc.unary_unary_rpc_method_handler(
                    servicer.SetPRS,
                    request_deserializer=search__pb2.SetPRSRequest.FromString,
                    response_serializer=search__pb2.SetPRSReply.SerializeToString,
            ),
            'CheckConnection': grpc.unary_unary_rpc_method_handler(
                    servicer.CheckConnection,
                    request_deserializer=search__pb2.CheckConnectionRequest.FromString,
                    response_serializer=search__pb2.CheckConnectionReply.SerializeToString,
            ),
            'SetDateRange': grpc.unary_unary_rpc_method_handler(
                    servicer.SetDateRange,
                    request_deserializer=search__pb2.SetDateRangeRequest.FromString,
                    response_serializer=search__pb2.SetDateRangeReply.SerializeToString,
            ),
            'Submit': grpc.unary_unary_rpc_method_handler(
                    servicer.Submit,
                    request_deserializer=search__pb2.SubmitRequest.FromString,
                    response_serializer=search__pb2.SubmitReply.SerializeToString,
            ),
            'Save': grpc.unary_unary_rpc_method_handler(
                    servicer.Save,
                    request_deserializer=search__pb2.SaveRequest.FromString,
                    response_serializer=search__pb2.SaveReply.SerializeToString,
            ),
            'SubmitByName': grpc.unary_unary_rpc_method_handler(
                    servicer.SubmitByName,
                    request_deserializer=search__pb2.SubmitByNameRequest.FromString,
                    response_serializer=search__pb2.SubmitByNameReply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'rpc.Search', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Search(object):
    """The greeting service definition.
    """

    @staticmethod
    def SetPRS(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Search/SetPRS',
            search__pb2.SetPRSRequest.SerializeToString,
            search__pb2.SetPRSReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def CheckConnection(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Search/CheckConnection',
            search__pb2.CheckConnectionRequest.SerializeToString,
            search__pb2.CheckConnectionReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SetDateRange(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Search/SetDateRange',
            search__pb2.SetDateRangeRequest.SerializeToString,
            search__pb2.SetDateRangeReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Submit(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Search/Submit',
            search__pb2.SubmitRequest.SerializeToString,
            search__pb2.SubmitReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Save(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Search/Save',
            search__pb2.SaveRequest.SerializeToString,
            search__pb2.SaveReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SubmitByName(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpc.Search/SubmitByName',
            search__pb2.SubmitByNameRequest.SerializeToString,
            search__pb2.SubmitByNameReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)