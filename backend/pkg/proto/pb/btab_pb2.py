# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: btab.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import msg_pb2 as msg__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\nbtab.proto\x12\x03rpc\x1a\tmsg.proto\"\r\n\x0bPingRequest\"/\n\tPingReply\x12\"\n\x07message\x18\x01 \x01(\x0b\x32\x11.rpc.ResponseType22\n\x04\x42TAB\x12*\n\x04Ping\x12\x10.rpc.PingRequest\x1a\x0e.rpc.PingReply\"\x00\x42\x04Z\x02./b\x06proto3')



_PINGREQUEST = DESCRIPTOR.message_types_by_name['PingRequest']
_PINGREPLY = DESCRIPTOR.message_types_by_name['PingReply']
PingRequest = _reflection.GeneratedProtocolMessageType('PingRequest', (_message.Message,), {
  'DESCRIPTOR' : _PINGREQUEST,
  '__module__' : 'btab_pb2'
  # @@protoc_insertion_point(class_scope:rpc.PingRequest)
  })
_sym_db.RegisterMessage(PingRequest)

PingReply = _reflection.GeneratedProtocolMessageType('PingReply', (_message.Message,), {
  'DESCRIPTOR' : _PINGREPLY,
  '__module__' : 'btab_pb2'
  # @@protoc_insertion_point(class_scope:rpc.PingReply)
  })
_sym_db.RegisterMessage(PingReply)

_BTAB = DESCRIPTOR.services_by_name['BTAB']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z\002./'
  _PINGREQUEST._serialized_start=30
  _PINGREQUEST._serialized_end=43
  _PINGREPLY._serialized_start=45
  _PINGREPLY._serialized_end=92
  _BTAB._serialized_start=94
  _BTAB._serialized_end=144
# @@protoc_insertion_point(module_scope)
