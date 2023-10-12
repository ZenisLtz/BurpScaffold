package org.zenis.BurpScaffold.Service;

import com.j256.ormlite.support.ConnectionSource;
import org.zenis.BurpScaffold.Utils.IOUtils;

import java.sql.SQLException;

public class DatabaseService {
    private boolean connected;
    private ConnectionSource conn;

    public DatabaseService(){}

    public ConnectionSource getConn() {
        return conn;
    }

    public void setConn(ConnectionSource conn) {
        this.conn = conn;
    }

    public boolean isConnected(){
        return connected;
    }

    public void ConnectDB(String jdbcpath) throws SQLException, ClassNotFoundException {
        conn = IOUtils.connectToDatabase(jdbcpath);
        connected=true;
    }

    public void DisconnectDB() throws Exception {
        if (!connected || conn==null) {return; }
        IOUtils.disconnectDatabase(conn);
        connected=false;
    }
}
