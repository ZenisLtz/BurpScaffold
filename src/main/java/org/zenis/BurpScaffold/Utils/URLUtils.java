package org.zenis.BurpScaffold.Utils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import org.zenis.BurpScaffold.Entity.Record;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class URLUtils {

    private static Set<String> walkPath(String mypath){
        String[] mypathlist = mypath.split("/");
        if(mypathlist.length<1) {return new HashSet<>();}
        String[] pathlist = Arrays.copyOfRange(mypathlist,1,mypathlist.length);
        if (pathlist.length==0) return new HashSet<>();
        if (!mypath.endsWith("/")){
            pathlist = Arrays.copyOfRange(pathlist,0,pathlist.length-1);
        }
        for (int i=0; i< pathlist.length; i++){
            if(i==0) {continue;};
            pathlist[i]=pathlist[i-1]+"/"+pathlist[i];
        }
        return new HashSet<String>(Arrays.asList(pathlist));
    }

    public static String[] analysePath(String[] urllist) throws MalformedURLException {
        Set<String> retlist = new HashSet<String>();
        for(String url:urllist){
            URL myurl = new URL(url);
            Set<String> tmpset= walkPath(myurl.getPath());
            for (String ret: tmpset){
                retlist.add(myurl.getProtocol() + "://"+myurl.getHost()+"/"+ret+"/");
            }
        }
        return retlist.toArray(new String[0]);
    }
    public static String[] analysePath(List<Record> rcdlist, int depth) throws MalformedURLException {
        Set<String> retlist = new HashSet<String>();
        for(Record rcd:rcdlist){
            URL myurl = new URL(rcd.getUrl());
            Set<String> tmpset= walkPath(myurl.getPath());
            for (String ret: tmpset){
                if (ret.split("/").length > depth) continue;
                retlist.add(myurl.getProtocol() + "://"+myurl.getHost()+"/"+ret+"/");
            }
        }
        return retlist.toArray(new String[0]);
    }

    public static URL getURL(IHttpRequestResponse request) {
        IHttpService service = request.getHttpService();
        URL url;
        try {
            url = new URL(service.getProtocol(), service.getHost(), service.getPort(), getPathFromRequest(request.getRequest()));
        } catch (java.net.MalformedURLException e) {
            url = null;
        }
        return url;
    }

    public static  String  getPathFromRequest(byte[] request) {
        int i = 0;
        boolean recording = false;
        String  path = "";
        while (i < request.length) {
            byte x = request[i];

            if (recording) {
                if (x != ' ') {
                    path += (char) x;
                } else {
                    break;
                }
            } else {
                if (x == ' ') {
                    recording = true;
                }
            }
            i++;
        }
        return path;
    }
}
