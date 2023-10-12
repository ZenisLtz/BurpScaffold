package org.zenis.BurpScaffold;

import com.j256.ormlite.support.ConnectionSource;
import org.junit.jupiter.api.Test;
import org.zenis.BurpScaffold.DAO.RecordDAO;
import org.zenis.BurpScaffold.Entity.Record;
import org.zenis.BurpScaffold.Utils.IOUtils;
import org.zenis.BurpScaffold.Utils.URLUtils;

import java.io.File;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.sql.SQLException;
import java.util.*;

public class RecordDAOTest {

    @Test
    public void TestMain(){
        System.out.println(System.getProperty("user.home")+ File.separator+"Desktop");
    }

    @Test
    public void TestArray() throws NoSuchFieldException {
        List<Field> mylist = Arrays.asList(Record.class.getDeclaredFields());
        mylist.remove(Record.class.getDeclaredField("oid"));
        mylist.remove(Record.class.getDeclaredField("response"));
        mylist.remove(Record.class.getDeclaredField("response"));
    }

    @Test
    public void TestURL() throws MalformedURLException {
        String[] urllist = {
            "https://helloworld.com/test123/favicon.ie9.ico?a=1&b=2",
            "https://edition.cnn.com/test123/dir1/dir2/",
            "https://edition.cnn.com/test123/dddd/tmptest",
            "https://edition.cnn.com:443/2022/08/01/politics/nancy-pelosi-taiwan-visit/index.html",
            "https://edition.cnn.com:443/favicon.ie9.ico",
            "https://edition.cnn.com:443/profiles/eric-cheung",
            "https://edition.cnn.com:443/profiles/alex-rogers",
            "https://www.huazhu.com:443/_next/static/css/154f335c21f2652d.css",
            "https://www.huazhu.com:443/_next/static/kZTK22aH1Ko6Ez4_vewuW/_middlewareManifest.js",
        };
        String[] retlist = URLUtils.analysePath(urllist);

        System.out.println(retlist);
    }

    @Test
    public void TestLoadDB() throws SQLException, ClassNotFoundException {
        ConnectionSource conn=null;
        String dbpath = "C:\\Users\\ZenisLee\\Desktop\\burpdev\\test.db";
        conn = IOUtils.connectToDatabase(dbpath);
        RecordDAO rcdDAO = new RecordDAO(conn);
        List<Record> rcdList = rcdDAO.getAllRecords();
        for(int i=0;i<rcdList.size();i++) {
            System.out.println(rcdList.get(i).getId());
        }
    }

    @Test
    public void TestCreateDB() throws SQLException, ClassNotFoundException {
        ConnectionSource conn=null;
        String dbpath = "C:\\Users\\ZenisLee\\Desktop\\burpdev\\test.db";
        conn = IOUtils.connectToDatabase(dbpath);
        RecordDAO rcdDAO = new RecordDAO(conn);

        Record rcd = rcdDAO.getByID(1);
//        rcd.setId(999);
//        rcdDAO.createRecord(rcd);
//
        Record rcd1 = new Record(
                rcd.getRequest(), rcd.getResponse(),
                rcd.getHost(), rcd.getPort(),
                rcd.getProtocol(), rcd.getUrl(),
                rcd.getMethod(), rcd.getStatus_code(),
                rcd.getMime_type(), rcd.getBody_offset());
        rcdDAO.createRecord(rcd1);
    }
}
