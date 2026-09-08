using System;
using System.IO;
using System.Collections.Generic;
using System.Web.Script.Serialization;
public static class InertMutableChild {
 public static int Main(string[] args) {
  var parser=new JavaScriptSerializer();parser.MaxJsonLength=Int32.MaxValue;
  var root=(Dictionary<string,object>)parser.DeserializeObject(Console.In.ReadToEnd());
  var experimental=(Dictionary<string,object>)root["experimental"];
  var cache=(Dictionary<string,object>)experimental["cache_file"];
  string path=(string)cache["path"];
  string before=File.ReadAllText(path);File.WriteAllText(path,before+"|owned-B");
  return 0;
 }
}
