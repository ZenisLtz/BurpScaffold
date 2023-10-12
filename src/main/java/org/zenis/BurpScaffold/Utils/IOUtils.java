package org.zenis.BurpScaffold.Utils;

import burp.BurpExtender;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;

import javax.swing.*;
import java.io.OutputStream;
import java.io.PrintStream;
import java.sql.SQLException;

public class IOUtils {
    public static void report(BurpExtender burpExtender, OutputStream stdout, Throwable t, String  title) {
        if (title != null) JOptionPane.showMessageDialog(burpExtender, t.getMessage(), title, JOptionPane.ERROR_MESSAGE);
        t.printStackTrace(new PrintStream(stdout));
    }

    public static void reportError(BurpExtender burpExtender, OutputStream stderr, Throwable t, String  title) {
        if (title != null) JOptionPane.showMessageDialog(burpExtender, t.getMessage(), title, JOptionPane.ERROR_MESSAGE);
        t.printStackTrace(new PrintStream(stderr));
    }

    public static ConnectionSource connectToDatabase(final String dbFile) throws SQLException, ClassNotFoundException {
        Class.forName("org.sqlite.JDBC");
        return new JdbcConnectionSource("jdbc:sqlite:" + dbFile);
    }

    public static void disconnectDatabase(ConnectionSource conn) throws Exception {
        conn.close();

    }
}
