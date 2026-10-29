using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace FortiSplit.Work;

internal static class AuthPipe
{
 internal static string Name(string id)=>"FortiSplitAuth-"+id;
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
 internal static void VerifyServer(PipeStream pipe,int pid){if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out uint actual)||actual!=pid)throw new IOException("Неизвестное окно авторизации.");}
 internal static void VerifyClient(PipeStream pipe,int pid){if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle,out uint actual)||actual!=pid)throw new IOException("Неизвестный процесс авторизации.");}
 internal static async Task<T> Read<T>(Stream stream,CancellationToken token=default){byte[] header=new byte[4];await stream.ReadExactlyAsync(header,token);int length=BinaryPrimitives.ReadInt32LittleEndian(header);if(length is <1 or >65536)throw new IOException("Слишком большая форма входа.");byte[] data=new byte[length];try{await stream.ReadExactlyAsync(data,token);return JsonSerializer.Deserialize<T>(data)??throw new IOException("Пустая форма входа.");}finally{CryptographicOperations.ZeroMemory(data);}}
 internal static async Task Write<T>(Stream stream,T value,CancellationToken token=default){byte[] data=JsonSerializer.SerializeToUtf8Bytes(value);try{if(data.Length>65536)throw new IOException("Слишком большая форма входа.");byte[] header=new byte[4];BinaryPrimitives.WriteInt32LittleEndian(header,data.Length);await stream.WriteAsync(header,token);await stream.WriteAsync(data,token);await stream.FlushAsync(token);}finally{CryptographicOperations.ZeroMemory(data);}}
 internal static AuthSession Login(string id,int parentPid,Config config,Func<bool> cancelled,Action<string>? stage=null,Action<string>? trace=null)
 {
  using var client=new NamedPipeClientStream(".",Name(id),PipeDirection.InOut,PipeOptions.Asynchronous);
  client.Connect(15000);VerifyServer(client,parentPid);
  using var lifetime=new CancellationTokenSource();
  Task monitor=Task.Run(async()=>{try{while(!lifetime.IsCancellationRequested){if(cancelled()){client.Dispose();return;}await Task.Delay(100,lifetime.Token);}}catch(OperationCanceledException){}});
  try{
   AuthReply Exchange(AuthRequest request){Write(client,request).GetAwaiter().GetResult();return Read<AuthReply>(client).GetAwaiter().GetResult();}
   AuthSession result=NativeAuth.Authenticate(config,Exchange,cancelled,stage,trace);
   if(Exchange(new("authenticated","","",[])).Cancelled)throw new OperationCanceledException();
   return result;
  }finally{lifetime.Cancel();monitor.GetAwaiter().GetResult();}
 }
}
