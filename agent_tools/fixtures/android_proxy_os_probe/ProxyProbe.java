import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Fixed read-only Binder getter probe. Never changes proxy or hidden-API policy.
 * Android 15 AOSP: packages/modules/Connectivity refs/heads/android15-release
 * framework/src/android/net/IConnectivityManager.aidl SHA256
 * fd587c60a6181c53adce2016677b1fc12be18594a6bbedd79cbbd78e54a36247
 * service/src/com/android/server/ConnectivityService.java SHA256
 * 91b5d7a9922cd2386cae8284cc64b30dccbba180c55b098bea62756177937818
 * Actual device signatures/access must still be measured; exceptions are unknown.
 */
public final class ProxyProbe {
    private static String quote(String value) {
        if (value == null) return "null";
        if (value.length() > 4096) throw new IllegalArgumentException("bounds");
        StringBuilder out = new StringBuilder("\"");
        for (int i=0; i<value.length(); i++) {
            char c=value.charAt(i);
            if (c=='"' || c=='\\') out.append('\\').append(c);
            else if (c<32 || c>126) {
                String hex=Integer.toHexString(c);
                out.append("\\u");
                for (int j=hex.length(); j<4; j++) out.append('0');
                out.append(hex);
            } else out.append(c);
        }
        return out.append('"').toString();
    }
    private static String proxy(Object value) throws Exception {
        if (value==null) return "null";
        Class<?> type=Class.forName("android.net.ProxyInfo");
        if (!type.isInstance(value)) throw new IllegalArgumentException("proxy_type");
        String host=(String)type.getMethod("getHost").invoke(value);
        int port=((Integer)type.getMethod("getPort").invoke(value)).intValue();
        String[] exclude=(String[])type.getMethod("getExclusionList").invoke(value);
        Object pac=type.getMethod("getPacFileUrl").invoke(value);
        if (port < -1 || port>65535 || exclude==null || exclude.length>32 || pac==null)
            throw new IllegalArgumentException("proxy_shape");
        StringBuilder entries=new StringBuilder("[");
        for (int i=0;i<exclude.length;i++) {if(i>0)entries.append(',');entries.append(quote(exclude[i]));}
        entries.append(']');
        return "{\"host\":"+quote(host)+",\"port\":"+port+",\"exclusionList\":"+entries+",\"pacUrl\":"+quote(pac.toString())+"}";
    }
    public static void main(String[] args) {
        String phase="arguments";
        try {
            if (args.length!=1 || !args[0].matches("[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"))
                throw new IllegalArgumentException("correlation");
            phase="shell-uid";
            int uid=((Integer)Class.forName("android.os.Process").getMethod("myUid").invoke(null)).intValue();
            if(uid!=2000)throw new SecurityException("shell_uid_required");
            phase="service-signature";
            Class<?> binder=Class.forName("android.os.IBinder");
            Object handle=Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"connectivity");
            if(handle==null)throw new IllegalStateException("service_absent");
            Object service=Class.forName("android.net.IConnectivityManager$Stub").getMethod("asInterface",binder).invoke(null,handle);
            Class<?> iface=Class.forName("android.net.IConnectivityManager");
            if(service==null || !iface.isInstance(service))throw new IllegalStateException("service_type");
            Method global=iface.getMethod("getGlobalProxy");
            Method defaults=iface.getMethod("getProxyForNetwork",Class.forName("android.net.Network"));
            phase="getter-first";
            String first="{\"global\":"+proxy(global.invoke(service))+",\"defaultForShell\":"+proxy(defaults.invoke(service,new Object[]{null}))+"}";
            phase="getter-second";
            String second="{\"global\":"+proxy(global.invoke(service))+",\"defaultForShell\":"+proxy(defaults.invoke(service,new Object[]{null}))+"}";
            phase="getter-stability";
            if(!first.equals(second))throw new IllegalStateException("getter_changed");
            String result="{\"schema\":1,\"state\":\"observed\",\"uid\":2000,\"correlationId\":"+quote(args[0])+",\"reads\":["+first+","+second+"]}";
            if(result.length()>16384)throw new IllegalArgumentException("bounds");
            System.out.println(result);
        } catch(Throwable error) {
            Throwable cause=error instanceof InvocationTargetException && error.getCause()!=null ? error.getCause() : error;
            // No exception messages or untrusted service payload in stdout/stderr.
            System.out.println("{\"state\":\"unknown\",\"phase\":"+quote(phase)+",\"errorType\":"+quote(cause.getClass().getSimpleName())+"}");
            System.exit(1);
        }
    }
}
