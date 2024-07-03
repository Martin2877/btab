import grpc
import rpc.btab_pb2 as btab__pb2
import rpc.btab_pb2_grpc as btab_pb2__grpc
import rpc.engines_pb2 as engines__pb2
import rpc.engines_pb2_grpc as engines_pb2__grpc
import rpc.search_pb2 as search__pb2
import rpc.search_pb2_grpc as search_pb2__grpc

from datetime import datetime
import time

# address = "172.30.112.1:50051"
address = 'localhost:50051'

channel = grpc.insecure_channel(address)


class Search:
    def __init__(self) -> None:
        self.stub = search_pb2__grpc.SearchStub(channel)

    def CheckConnection(self):
        response = self.stub.CheckConnection(search__pb2.CheckConnectionRequest())
        return response.message

    def Submit(self, content):
        response = self.stub.Submit(search__pb2.SubmitRequest(content=content))
        return response.message

    def Save(self, name, content):
        response = self.stub.Save(search__pb2.SaveRequest(name=name, content=content))
        return response.message

    def SubmitByName(self, name):
        response = self.stub.SubmitByName(search__pb2.SubmitByNameRequest(name=name))
        return response.message


class Engines:
    def __init__(self) -> None:
        self.stub = engines_pb2__grpc.EnginesStub(channel)

    def CheckAlive(self):
        response = self.stub.CheckAlive(engines__pb2.CheckAliveRequest())
        return response.message

    def Set(self, name, content):
        response = self.stub.Set(engines__pb2.SetRequest(name=name, content=content))
        return response.message

    def Get(self, name):
        response = self.stub.Get(engines__pb2.GetRequest(name=name))
        return response.message

    def Run(self, content):
        response = self.stub.Run(engines__pb2.RunRequest(content=content))
        return response.message


class BTAB:
    def __init__(self) -> None:
        self.stub = btab_pb2__grpc.BTABStub(channel)

    def Ping(self):
        response = self.stub.Ping(btab__pb2.PingRequest())
        return response.message
