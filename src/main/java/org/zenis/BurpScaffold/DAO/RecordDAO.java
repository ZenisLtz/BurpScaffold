package org.zenis.BurpScaffold.DAO;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import org.zenis.BurpScaffold.Entity.Record;

import java.sql.SQLException;
import java.util.List;

public class RecordDAO {

    private boolean connected = false;
    private Dao<Record, String> recordDao;

    public RecordDAO(ConnectionSource connectionSource) throws SQLException{
        recordDao = DaoManager.createDao(connectionSource, Record.class);
        TableUtils.createTableIfNotExists(connectionSource, Record.class);
        connected = true;
    }

    public Record getByID(int id) throws SQLException {
        return recordDao.queryForId(String.valueOf(id));
    }

    public boolean isConnected() {
        return connected;
    }

    public List<Record> getAllRecords() throws SQLException {
        return recordDao.queryForAll();
    }

    public void deleteAllRecords() throws SQLException {
        DeleteBuilder deleteBuilder = recordDao.deleteBuilder();
        deleteBuilder.delete();
    }

    public void deleteRecord(int oid) throws SQLException {
        DeleteBuilder deleteBuilder = recordDao.deleteBuilder();
        deleteBuilder.where().eq("oid", oid);
        deleteBuilder.delete();
    }

    public void createRecords(List<Record> rcdlist) throws SQLException {
        for(Record rcd: rcdlist) {
            recordDao.createOrUpdate(rcd);
        }
    }

    public void createRecord(Record rcd) throws SQLException {
        recordDao.create(rcd);
    }
}