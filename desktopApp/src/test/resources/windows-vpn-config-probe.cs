// Fixed configuration-only compatibility executable. It never opens a user path or starts a runtime.
namespace VpnScopedConfiguration.Tests {
 using System;
 using System.Text;
 using System.Text.Json;
 using System.Collections.Generic;
 public static class ConfigurationProbe {
  static int selected;
  static void Need(bool value,string name) { if(!value) throw new InvalidOperationException(name); }
  static void Case(string name,Action test) { selected++;try { test(); } catch(Exception failure) { throw new InvalidOperationException(name,failure); } }
  static void Reject(string text,Dictionary<string,string> resources=null) {
   bool rejected=false;
   try { Configuration.Normalize(text,"C:\\protected-fixture",resources); }
   catch(ArgumentException) { rejected=true; }
   Need(rejected,"Configuration unexpectedly admitted");
  }
  static JsonDocument Normal(string text,Dictionary<string,string> resources=null) {
   return JsonDocument.Parse(Configuration.Normalize(text,"C:\\protected-fixture",resources));
  }
  public static int Main(string[] args) {
   try {
    Need(args.Length==0,"Unexpected arguments");
    string[] accepted={
     "{\"dns\":{\"servers\":[{\"type\":\"https\",\"path\":\"/dns-query\"}]}}",
     "{\"outbounds\":[{\"transport\":{\"type\":\"ws\",\"path\":\"/ws\"}}]}",
     "{\"outbounds\":[{\"tcp_multi_path\":true,\"transport\":{\"type\":\"httpupgrade\",\"path\":\"//opaque/path?value=1\"}}]}",
     "{\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\"cache.db\"}}}"
    };
    for(int i=0;i<accepted.Length;i++) { string text=accepted[i];Case("Existing accepted policy "+i,()=>{using(var parsed=Normal(text)) Need(parsed.RootElement.ValueKind==JsonValueKind.Object,"Root");}); }
    string[] denied={
     "{\"dns\":{\"servers\":[{\"type\":\"hosts\",\"path\":\"C:\\\\foreign\"}]}}",
     "{\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\"C:\\\\foreign\"}}}",
     "{\"tls\":{\"acme\":{\"data_directory\":\"C:\\\\foreign\"}}}",
     "{\"endpoints\":[{\"type\":\"tailscale\",\"state_directory\":\"C:\\\\foreign\"}]}",
     "{\"outbounds\":[{\"type\":\"ssh\",\"private_key_path\":\"C:\\\\foreign\"}]}",
     "{\"inbounds\":[{\"type\":\"hysteria2\",\"masquerade\":{\"type\":\"file\",\"directory\":\"C:\\\\foreign\"}}]}",
     "{\"inbounds\":[{\"type\":\"hysteria2\",\"masquerade\":\"file:///C:/foreign\"}]}",
     "{\"services\":[{\"type\":\"derp\",\"mesh_psk_file\":\"C:\\\\foreign\"}]}"
    };
    for(int i=0;i<denied.Length;i++) { string text=denied[i];Case("Existing rejected policy "+i,()=>Reject(text)); }
    Case("Cache destination confined",()=>{using(var parsed=Normal(accepted[3])) Need(parsed.RootElement.GetProperty("experimental").GetProperty("cache_file").GetProperty("path").GetString()=="C:\\protected-fixture\\cache.db","Cache destination");});
    Case("Numbers retain exact lexical value",()=>{
     const string numbers="[18446744073709551617,-0,1e+400,0.0000000000000000000000000000000000000001,-12345678901234567890123456789012345678901234567890]";
     string result=Configuration.Normalize("{\"numbers\":"+numbers+"}",null);
     Need(result=="{\"numbers\":"+numbers+"}","Number coercion");
    });
    Case("Unicode and escaped characters survive",()=>{
     const string expected="漢字🌍\\\"\n\t";
     using(var parsed=Normal("{\"opaque\":\"漢字\\ud83c\\udf0d\\\\\\\"\\n\\t\"}"))
      Need(parsed.RootElement.GetProperty("opaque").GetString()==expected,"Unicode changed");
    });
    Case("Duplicate keys match ordinary owner",()=>{
     using(var parsed=Normal("{\"n\":1,\"n\":18446744073709551617,\"N\":2}")) {
      int count=0;foreach(var property in parsed.RootElement.EnumerateObject()) count++;
      Need(count==2&&parsed.RootElement.GetProperty("n").GetRawText()=="18446744073709551617"&&parsed.RootElement.GetProperty("N").GetInt32()==2,"Duplicate semantics");
     }
    });
    Case("Read resources preserve arrays and opaque IDs",()=>{
     const string id="vpn-control-resource:00000000-0000-0000-0000-000000000041";
     var resources=new Dictionary<string,string>(StringComparer.Ordinal) {{id,"C:\\protected-fixture\\resource.bin"}};
     using(var parsed=Normal("{\"inbounds\":[{\"tls\":{\"certificate_path\":[\""+id+"\",[\""+id+"\"]]}}]}",resources)) {
      var value=parsed.RootElement.GetProperty("inbounds")[0].GetProperty("tls").GetProperty("certificate_path");
      Need(value[0].GetString()==resources[id]&&value[1][0].GetString()==resources[id],"Resource mapping");
     }
     Reject("{\"certificate\":{\"certificate_path\":\"foreign\"}}",resources);
    });
    Case("Property separators cannot impersonate schema context",()=>{
     Reject("{\"dns/servers\":[{\"type\":\"https\",\"path\":\"C:\\\\foreign\"}]}");
     Reject("{\"experimental/cache_file\":{\"enabled\":true,\"path\":\"cache.db\"}}");
    });
    Case("Strict JSON and UTF16 input validation",()=>{
     foreach(string text in new[]{"[]","null","{\"n\":01}","{\"n\":1,}","{/*comment*/\"n\":1}","{\"text\":\""+'\ud800'+"\"}"}) Reject(text);
    });
    Case("Escaped malformed surrogates are typed invalid input",()=>{
     Reject("{\"opaque\":\"\\ud800\"}");Reject("{\"opaque\":\"\\udc00\"}");
     Reject("{\"\\ud800\":1}");Reject("{\"opaque\":\"\\ud800\\u0041\"}");
    });
    Case("Logical document is not capped by control frames",()=>{
     string payload=new string('x',9*1024*1024);
     using(var parsed=Normal("{\"opaque\":\""+payload+"\"}")) Need(parsed.RootElement.GetProperty("opaque").GetString()==payload,"Large document changed");
    });
    Case("Deep input does not use recursive application traversal",()=>{
     const int depth=2048;var text=new StringBuilder("{\"opaque\":");text.Append('[',depth);text.Append("18446744073709551617");text.Append(']',depth);text.Append('}');
     string normalized=Configuration.Normalize(text.ToString(),null);
     Need(normalized==text.ToString(),"Deep document changed");
    });
    Console.Write("NATIVE_AOT_CONFIG_OK:"+selected);return 0;
   } catch(Exception failure) { Console.Error.Write(failure.ToString());return 1; }
  }
 }
}
