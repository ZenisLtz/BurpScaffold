package org.zenis.BurpScaffold.Entity;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "records")
public class Record {
    @DatabaseField(id = true)
    private int     oid;
    @DatabaseField
    private int     id;
    @DatabaseField
    private String  request;
    @DatabaseField
    private String  response;
    @DatabaseField
    private String  host;
    @DatabaseField
    private int     port;
    @DatabaseField
    private String  protocol;
    @DatabaseField
    private String  url;
    @DatabaseField
    private String  method;
    @DatabaseField
    private int     status_code;
    @DatabaseField
    private String  mime_type;
    @DatabaseField
    private int     body_offset;

    public Record(){
    }

    public Record(
            String request, String response,
            String host, int port,
            String protocol, String url,
            String method, int status_code,
            String mime_type, int body_offset){
        this.oid = (int) Math.round(Math.floor(Math.random() * 10.0D));
        this.request=request;
        this.response=response;
        this.host=host;
        this.port=port;
        this.protocol=protocol;
        this.url=url;
        this.method=method;
        this.status_code=status_code;
        this.mime_type=mime_type;
        this.body_offset=body_offset;
    }

    public int getOid() {
        return oid;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getRequest() {
        return request;
    }

    public void setRequest(String request) {
        this.request = request;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public int getStatus_code() {
        return status_code;
    }

    public void setStatus_code(int status_code) {
        this.status_code = status_code;
    }

    public String getMime_type() {
        return mime_type;
    }

    public void setMime_type(String mime_type) {
        this.mime_type = mime_type;
    }

    public int getBody_offset() {
        return body_offset;
    }


    public void setBody_offset(int body_offset) {
        this.body_offset = body_offset;
    }

}
