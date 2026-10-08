"""Finite stdin forwarding observation, never server execution authority."""
import json
class FrameObserver:
 def __init__(self):self.pending=b'';self.offset=0;self.forwarded=0;self.calls=[]
 def add(self,retained,bytes_written):
  if type(retained)is not bytes or type(bytes_written)is not int or not 0<=bytes_written<=len(retained):raise ValueError('forward_count')
  self.forwarded+=bytes_written;self.pending+=retained;new=[]
  while b'\n' in self.pending:
   line,self.pending=self.pending.split(b'\n',1);self.offset+=len(line)+1;value=json.loads(line)
   if type(value)is not dict:raise ValueError('protocol_frame')
   if value.get('method')=='tools/call':
    event={'kind':'tools_call_frame','frameOrdinal':len(self.calls),'frameEndOffset':self.offset,'fullyForwarded':self.offset<=self.forwarded,'serverExecutionProven':False};self.calls.append(event);new.append(event)
  return new
 def summary(self):return {'toolCallFrameCount':len(self.calls),'fullyForwardedToolCallFrameCount':sum(v['fullyForwarded'] for v in self.calls),'stdinBytesWritten':self.forwarded,'pendingFrameBytes':len(self.pending),'serverExecutionProven':False}
