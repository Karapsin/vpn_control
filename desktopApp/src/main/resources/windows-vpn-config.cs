// Fixed NativeAOT configuration parser. No reflection-based serialization or runtime code generation.
namespace VpnScopedConfiguration {
 using System;
 using System.IO;
 using System.Text;
 using System.Text.Json;
 using System.Collections.Generic;

 public static class Configuration {
  sealed class Context {
   public static readonly Context Root=new Context(null,null);
   readonly Context parent;readonly string segment;readonly int depth;
   public Context(Context parent,string segment) { this.parent=parent;this.segment=segment;depth=parent==null?0:checked(parent.depth+1); }
   public bool Is(params string[] segments) { return depth==segments.Length&&EndsWith(segments); }
   public bool EndsWith(params string[] segments) {
    if(depth<segments.Length) return false;
    Context current=this;
    for(int i=segments.Length-1;i>=0;i--,current=current.parent) if(current.segment!=segments[i]) return false;
    return true;
   }
  }
  enum Kind { Value,Property,EndObject,EndArray,Resource,String }
  readonly struct Work {
   public readonly Kind Kind;public readonly JsonElement Value;public readonly Context Context;public readonly string Text;
   public Work(Kind kind,JsonElement value=default,Context context=null,string text=null) { Kind=kind;Value=value;Context=context;Text=text; }
  }
  static void Need(bool accepted) { if(!accepted) throw new ArgumentException("INVALID_ARGUMENT"); }
  static bool ReadFileField(string key,Context context,string type) {
   return (context.EndsWith("tls")&&(key=="certificate_path"||key=="client_certificate_path"||key=="key_path"||key=="client_key_path")) ||
    (context.EndsWith("tls","ech")&&(key=="key_path"||key=="config_path")) ||
    (context.Is("certificate")&&key=="certificate_path") ||
    (context.Is("dns","servers","*")&&type=="hosts"&&key=="path") ||
    (context.Is("route","rule_set","*")&&type=="local"&&key=="path") ||
    (context.Is("services","*")&&type=="derp"&&key=="mesh_psk_file") ||
    (context.Is("outbounds","*")&&type=="ssh"&&key=="private_key_path");
  }
  static string StringValue(JsonElement value) {
   if(value.ValueKind!=JsonValueKind.String) return null;
   try { return value.GetString(); }
   catch(InvalidOperationException) { throw new ArgumentException("INVALID_ARGUMENT"); }
  }
  static string PropertyName(JsonProperty property) {
   try { return property.Name; }
   catch(InvalidOperationException) { throw new ArgumentException("INVALID_ARGUMENT"); }
  }
  static Dictionary<string,JsonElement> Object(JsonElement value) {
   // The ordinary owner's JSON object model keeps the last occurrence of each exact key.
   // Keep that meaning while preserving each surviving number's original lexical bytes.
   var result=new Dictionary<string,JsonElement>(StringComparer.Ordinal);
   foreach(var property in value.EnumerateObject()) result[PropertyName(property)]=property.Value;
   return result;
  }
  static void QueueObject(Stack<Work> work,JsonElement value,Context context,string stage,
    Dictionary<string,string> mutable,HashSet<string> used) {
   var map=Object(value);JsonElement kind;
   string type=map.TryGetValue("type",out kind)?StringValue(kind):null;
   bool url=(context.Is("dns","servers","*")&&(type=="https"||type=="h3")) ||
    ((context.Is("outbounds","*","transport")||context.Is("inbounds","*","transport"))&&(type=="ws"||type=="http"||type=="httpupgrade")) ||
    (context.Is("outbounds","*")&&type=="http");
   bool cache=context.Is("experimental","cache_file");
   string cachePath=null;
   if(cache) {
    JsonElement enabled,path;
    if(mutable==null) {
     Need(map.Count==2&&map.TryGetValue("enabled",out enabled)&&
      (enabled.ValueKind==JsonValueKind.True||enabled.ValueKind==JsonValueKind.False)&&
      map.TryGetValue("path",out path)&&StringValue(path)=="cache.db");
     cachePath=stage==null?"cache.db":Path.Combine(stage,"cache.db");
    } else {
     foreach(string key in map.Keys) Need(key=="enabled"||key=="path"||key=="cache_id"||key=="store_fakeip"||key=="store_rdrc"||key=="rdrc_timeout");
     Need(map.TryGetValue("enabled",out enabled)&&enabled.ValueKind==JsonValueKind.True&&
      map.TryGetValue("path",out path)&&StringValue(path)!=null);
     string reference=StringValue(map["path"]);
     Need(mutable.TryGetValue(reference,out cachePath)&&used.Add(reference));
    }
   }
   var properties=new List<KeyValuePair<string,JsonElement>>(map);
   work.Push(new Work(Kind.EndObject));
   for(int i=properties.Count-1;i>=0;i--) {
    string key=properties[i].Key;JsonElement child=properties[i].Value;
    if(ReadFileField(key,context,type)) work.Push(new Work(Kind.Resource,child));
    else {
     Need(key!="output"&&key!="external_ui"&&key!="directory"&&!key.EndsWith("_directory",StringComparison.Ordinal)&&
      (key=="cache_file"||!key.EndsWith("_file",StringComparison.Ordinal))&&
      (key!="cache_file"||context.Is("experimental"))&&
      (key=="process_path"||key=="tcp_multi_path"||!key.EndsWith("_path",StringComparison.Ordinal)));
     if(key=="masquerade"&&child.ValueKind==JsonValueKind.String)
      Need(!StringValue(child).StartsWith("file:",StringComparison.OrdinalIgnoreCase));
     if(key=="path") Need(cache||(url&&child.ValueKind==JsonValueKind.String));
     if(cache&&key=="path") work.Push(new Work(Kind.String,text:cachePath));
     else work.Push(new Work(Kind.Value,child,new Context(context,key)));
    }
    work.Push(new Work(Kind.Property,text:key));
   }
  }
  public static string Normalize(string text,string stage,Dictionary<string,string> resources=null,
    Dictionary<string,string> mutable=null) {
   Need(text!=null);
   try {
    // Parsing and rendering materialize the logical document. A document is not rejected because
    // it exceeds a control frame or a small parser depth; allocation failures remain resource failures.
    var utf8=new UTF8Encoding(false,true);
    using(var document=JsonDocument.Parse(utf8.GetBytes(text),new JsonDocumentOptions { MaxDepth=Int32.MaxValue }))
    using(var output=new MemoryStream()) {
     Need(document.RootElement.ValueKind==JsonValueKind.Object);
     using(var writer=new Utf8JsonWriter(output,new JsonWriterOptions { MaxDepth=Int32.MaxValue })) {
      var used=new HashSet<string>(StringComparer.Ordinal);
      var work=new Stack<Work>();work.Push(new Work(Kind.Value,document.RootElement,Context.Root));
      while(work.Count!=0) {
       Work next=work.Pop();
       switch(next.Kind) {
        case Kind.Property: writer.WritePropertyName(next.Text);break;
        case Kind.String: writer.WriteStringValue(next.Text);break;
        case Kind.EndObject: writer.WriteEndObject();break;
        case Kind.EndArray: writer.WriteEndArray();break;
        case Kind.Resource:
         if(next.Value.ValueKind==JsonValueKind.Array) {
          writer.WriteStartArray();work.Push(new Work(Kind.EndArray));
          for(int i=next.Value.GetArrayLength()-1;i>=0;i--) work.Push(new Work(Kind.Resource,next.Value[i]));
         } else {
          string reference=StringValue(next.Value),path;
          Need(reference!=null&&resources!=null&&resources.TryGetValue(reference,out path));
          writer.WriteStringValue(resources[reference]);
         }
         break;
        case Kind.Value:
         if(next.Value.ValueKind==JsonValueKind.Object) {
          writer.WriteStartObject();QueueObject(work,next.Value,next.Context,stage,mutable,used);
         } else if(next.Value.ValueKind==JsonValueKind.Array) {
          writer.WriteStartArray();work.Push(new Work(Kind.EndArray));
          var context=new Context(next.Context,"*");
          for(int i=next.Value.GetArrayLength()-1;i>=0;i--) work.Push(new Work(Kind.Value,next.Value[i],context));
         } else if(next.Value.ValueKind==JsonValueKind.String) writer.WriteStringValue(StringValue(next.Value));
         else next.Value.WriteTo(writer); // Numbers never pass through double, decimal, or object serialization.
         break;
       }
      }
      Need(mutable==null||used.Count==mutable.Count);
     }
     return utf8.GetString(output.GetBuffer(),0,checked((int)output.Length));
    }
   } catch(JsonException) { throw new ArgumentException("INVALID_ARGUMENT"); }
   catch(EncoderFallbackException) { throw new ArgumentException("INVALID_ARGUMENT"); }
   catch(DecoderFallbackException) { throw new ArgumentException("INVALID_ARGUMENT"); }
  }
 }
}
