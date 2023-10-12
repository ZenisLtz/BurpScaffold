package org.zenis.BurpScaffold.Service;

import burp.*;
import com.j256.ormlite.support.ConnectionSource;
import org.zenis.BurpScaffold.DAO.RecordDAO;
import org.zenis.BurpScaffold.Entity.Record;
import org.zenis.BurpScaffold.Utils.IOUtils;
import org.zenis.BurpScaffold.Utils.URLUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.zenis.BurpScaffold.Utils.AlgUtils.subList2Integer;

public class RecordService {
    private List<Integer> idList = new ArrayList<Integer>();
    private List<Integer> delCacheList = new ArrayList<Integer>();
    private List<Record> recordList = new ArrayList<Record>();
    private static List<Field> recordFields;

    static {
        try {
            recordFields = getTableColumnList();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
    }

    private RecordDAO rcdDAO;

    public RecordDAO getRcdDAO() {
        return rcdDAO;
    }

    public List<Integer> getIdList() {
        return idList;
    }

    public List<Record> getRecordList(){ return recordList; }

    public static List<Field> getTableColumnList() throws NoSuchFieldException {
        List<Field> fieldList = new LinkedList<>(Arrays.asList(Record.class.getDeclaredFields()));
        fieldList.remove(Record.class.getDeclaredField("oid"));
        fieldList.remove(Record.class.getDeclaredField("request"));
        fieldList.remove(Record.class.getDeclaredField("response"));
        return fieldList;
    }

    public RecordService(){}

    public void init(ConnectionSource conn) throws SQLException {
        rcdDAO = new RecordDAO(conn);
        if(!rcdDAO.isConnected()){
            return;
        }
        if (idList  != null || recordList != null){ clean();}
        recordList = rcdDAO.getAllRecords();
        for(int i=0;i<recordList.size();i++) {
            idList.add(recordList.get(i).getId());
        }
    }

    public int reloadRCDList() throws SQLException {
        if(!rcdDAO.isConnected()){
            return -1;
        }
        recordList.clear();
        recordList = rcdDAO.getAllRecords();
        return 0;
    }

    public int reload() throws SQLException {
        if(reloadRCDList()<0) {
             return -1;
        }
        resetIDList();
        return 0;
    }

    public void clean() {
        if(recordList.size()>0) { recordList.clear();}
        if(idList.size()>0) { idList.clear();}
        if(delCacheList.size()>0) { delCacheList.clear();}
    }

    public void cleanDelCache() {
        if(delCacheList.size()>0) { delCacheList.clear();}
    }

    public int deleteRecord(Record rcd){
        for (Record _rcd :recordList) {
            if(_rcd.getOid() == rcd.getOid()){
                recordList.remove(_rcd);
                delCacheList.add(_rcd.getOid());
//                resetIDInRecordList();
                return 0;
            }
        }
        return -1;
    }

    public List<Integer> addRecord(Record rcd){
        rcd.setId(recordList.size()+1);
        recordList.add(rcd);
        return filterSingle(rcd);
    }

    public List<Integer> filter(){
        return idList;
    };

    public List<Integer> filterSingle(Record rcd){
//        resetIDList();
        return idList;
    };

    public Record getRcdByID(Integer ID){
        if (ID == null ) return null;
        for(int i=0;i<recordList.size();i++) {
            Record rcd = recordList.get(i);
            if (rcd.getId()==ID){
                return rcd;
            }
        }
        return null;
    };

    public List<Integer> getIdListFromRcdList() {
        List<Integer> tmplist = new ArrayList<Integer>();
        for(int i=0;i<recordList.size();i++) {
            tmplist.add(recordList.get(i).getId());
        }
        return tmplist;
    }

    public List<Integer> getDifferencSets(){
        List<Integer> tmplist = getIdListFromRcdList();
        return subList2Integer(tmplist, idList);
    }

    public void syncFilterResult(){
        Map<Integer, Record> tempMap = recordList.parallelStream().collect(Collectors.toMap(Record::getId, Function.identity(), (oldData, newData) -> newData));
        Map<Integer, Record> filteredMap = tempMap.entrySet().stream()
                .filter(r -> idList.contains(r.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        recordList.clear();
        recordList = (List<Record>) filteredMap.values();
        resortRecordList();
        for (int i=0;i<recordList.size();i++){
            recordList.get(i).setId(i);
        }
        resetIDList();
    }

    public void saveDB() throws SQLException {
        rcdDAO.createRecord(recordList);
        for (Integer oid:delCacheList) {
            rcdDAO.deleteRecord(oid);
        }
    }

    public void resetIDList(){
        idList.clear();
        idList = getIdListFromRcdList();
    }

    public void resortRecordList(){
        recordList.stream().sorted((Comparator.comparing(item -> item.getId())));
    }

    public void resetIDInRecordList(){
        for(int i=0; i< recordList.size(); i++) {
            recordList.get(i).setId(i);
        }
    }

    public AbstractTableModel GenarateTable(){
        return new AbstractTableModel(){
            @Override
            public int getRowCount() {
                return idList.size();
            }

            @Override
            public int getColumnCount() {
                return recordFields.size();
            }

            @Override
            public String getColumnName(int colindex) {
                return recordFields.get(colindex).getName();
            }

            @Override
            public Class<?> getColumnClass(int colindex) {
                return recordFields.get(colindex).getClass();
            }

            @Override
            public Object getValueAt(int rowIndex, int colindex) {
                Field column = recordFields.get(colindex);
                column.setAccessible(true);
                Object retobj=null;
                Record rcd = getRcdByID(idList.get(rowIndex));
                if (rcd==null) {
                    return null;
                }
                try {
                    retobj = column.get(rcd);
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                    return null;
                }
                return retobj;
            }
        };
    }

    public void insertRequestResponse(IHttpRequestResponse messageInfo, IExtensionHelpers helpers) throws SQLException {
        if (messageInfo.getResponse() == null) return;
        IHttpService hs = messageInfo.getHttpService();
        IRequestInfo req = helpers.analyzeRequest(messageInfo);
        IResponseInfo resp = helpers.analyzeResponse(messageInfo.getResponse());
        Record rcd = new Record(
                new String(messageInfo.getRequest()), new String(messageInfo.getResponse()),
                hs.getHost(), hs.getPort(),
                hs.getProtocol(), req.getUrl().toString(),
                req.getMethod(), resp.getStatusCode(),
                resp.getStatedMimeType(), resp.getBodyOffset());
        this.addRecord(rcd);
    }

    public List<String> exportPath(int depth) throws MalformedURLException {
        String[] retArr = URLUtils.analysePath(recordList, depth);
        Arrays.sort(retArr);
        return Arrays.asList(retArr);
    }
}
