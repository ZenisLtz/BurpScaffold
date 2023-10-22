package org.zenis.BurpScaffold;

import burp.*;
import org.zenis.BurpScaffold.Service.DatabaseService;
import org.zenis.BurpScaffold.Service.RecordService;
import org.zenis.BurpScaffold.Service.TableService;
import org.zenis.BurpScaffold.Utils.IOUtils;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.MalformedURLException;
import java.sql.SQLException;
import java.util.List;

public class UIComponent {

    private BurpExtender burpExtender;

    private IBurpExtenderCallbacks callbacks;
    private JPanel parentJpanel;
    private JSplitPane splitPane;

    private JLabel lbDbFile = new JLabel("(no database opened yet)");

    private JButton btnDbSelect = new JButton("Select database");
    private JButton btnDbClose = new JButton("Close database");
    private JButton btnDbSave = new JButton("Save To Database");
    private JButton btnDBReload = new JButton("Reload DB");
    private JButton btnDBClean = new JButton("Clean DB");
    private JButton btnTblSave = new JButton("Save Table");
    private JButton btnTblClean = new JButton("Clean Table");
    private JButton btnTblReset = new JButton("Reset Filter");
    private JButton btnURLExport = new JButton("Export Path");

    private PrintWriter stdout;
    private OutputStream stderr;

    public UIComponent(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks, PrintWriter stdout, OutputStream stderr) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.stdout = stdout;
        this.stderr = stderr;

        parentJpanel = new JPanel();
        parentJpanel.setLayout(new BoxLayout(parentJpanel, BoxLayout.PAGE_AXIS));
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

    }

    public JPanel getParentJpanel() {
        return parentJpanel;
    }

    public JSplitPane getSplitPane() {
        return splitPane;
    }

    public void registerGetSiteMap() {
        RecordService rcdSVC = burpExtender.getRcdSVC();
        TableService tblSVC = burpExtender.getTblSVC();
        IExtensionHelpers helpers = burpExtender.getHelpers();

        JTextArea txtSiteUrl = new JTextArea();
        JPanel pannelGetSiteMap = new JPanel();
        pannelGetSiteMap.setLayout(new BoxLayout(pannelGetSiteMap, BoxLayout.LINE_AXIS));
        pannelGetSiteMap.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        pannelGetSiteMap.add(new JLabel("SiteURL: "));
        pannelGetSiteMap.add(txtSiteUrl);

        JButton btnGetSiteMap = new JButton("Get SiteMap");
        btnGetSiteMap.addActionListener(event -> {
            IHttpRequestResponse[] httpReqRepList = callbacks.getSiteMap(txtSiteUrl.getText());
            for (IHttpRequestResponse httpReqRep : httpReqRepList) {
                try {
                    rcdSVC.insertRequestResponse(httpReqRep, helpers);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            tblSVC.resetTable(rcdSVC);
        });

        pannelGetSiteMap.add(btnGetSiteMap);
        parentJpanel.add(pannelGetSiteMap);
    }

    public void registerBcontrols() {
        DatabaseService dbSVC = burpExtender.getDbSVC();
        RecordService rcdSVC = burpExtender.getRcdSVC();
        TableService tblSVC = burpExtender.getTblSVC();

        JPanel databaseControls = new JPanel();
        databaseControls.setLayout(new BoxLayout(databaseControls, BoxLayout.LINE_AXIS));

        btnDbSelect.addActionListener(event -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showSaveDialog(burpExtender) != JFileChooser.APPROVE_OPTION) return;
            File f = fc.getSelectedFile();
            try {
                if (dbSVC.isConnected()) {
                    dbSVC.DisconnectDB();
                }
                dbSVC.ConnectDB(f.getPath());
                rcdSVC.init(dbSVC.getConn());

                tblSVC.setEnable(true);
                tblSVC.GenarateTable(rcdSVC);
                lbDbFile.setText(f.getPath());

                btnDbClose.setEnabled(true);
                btnDBReload.setEnabled(true);
                btnTblClean.setEnabled(true);
                btnTblSave.setEnabled(true);
                btnDBClean.setEnabled(true);
                btnTblReset.setEnabled(true);
                btnURLExport.setEnabled(true);
            } catch (Exception e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't open database");
            }
        });

        btnDBReload.setEnabled(false);
        btnDBReload.addActionListener(event -> {
            try {
                tblSVC.reloadDB(rcdSVC);
            } catch (SQLException e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't reload table from database");
            }
        });

        btnDbClose.setEnabled(false);
        btnDbClose.addActionListener(event -> {
            try {
                int result = JOptionPane.showOptionDialog(null,
                        new Object[] {"Are you sure to close the current database?"},
                        "class database",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        null,
                        null);
                if (result != JOptionPane.OK_OPTION) {
                    return;
                }
                dbSVC.DisconnectDB();
                tblSVC.cleanTable(rcdSVC);

                btnDbSelect.setEnabled(true);
                btnDbClose.setEnabled(false);
                btnDBReload.setEnabled(false);
                btnTblClean.setEnabled(false);
                btnTblSave.setEnabled(false);
                btnDBClean.setEnabled(false);
                btnTblReset.setEnabled(false);
                btnURLExport.setEnabled(false);

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            lbDbFile.setText("(no database opened yet)");

        });

        btnTblClean.setEnabled(false);
        btnTblClean.addActionListener(event -> {
            try {
                tblSVC.cleanTable(rcdSVC);
            } catch (Exception e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't clean table");
            }
        });

        btnTblSave.setEnabled(false);
        btnTblSave.addActionListener(event -> {
            try {
                int result = JOptionPane.showOptionDialog(null,
                        new Object[] {"Are you sure to save current table?"},
                        "Save current table to database",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        null,
                        null);
                if (result == JOptionPane.OK_OPTION) {
                    tblSVC.saveTable(rcdSVC);
                }
            } catch (Exception e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't save table");
            }
        });

        btnDBClean.setEnabled(false);
        btnDBClean.addActionListener(event -> {
            try {
                int result = JOptionPane.showOptionDialog(null,
                        new Object[] {"Are you sure to clean current database?"},
                        "Clean current database",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        null,
                        null);
                if (result == JOptionPane.OK_OPTION) {
                    tblSVC.cleanDB(rcdSVC);
                }
            } catch (Exception e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't clean database");
            }
        });

        btnTblReset.setEnabled(false);
        btnTblReset.addActionListener(event -> {
            try {
                tblSVC.resetTable(rcdSVC);
            } catch (Exception e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't reset table");
            }
        });

        btnURLExport.setEnabled(false);
        btnURLExport.addActionListener(event -> {
            try {

                JLabel outputpathLabel = new JLabel("Input your export path:");
                JTextField outputpathfield = new JTextField();
                outputpathfield.setText(System.getProperty("user.home") + File.separator + "Desktop" + File.separator + "output.txt");
                JLabel depthLabel = new JLabel("Input url path depth: ");
                JTextField depthfield = new JTextField();
                depthfield.setText("1");

                Object[] options = {"Export", "Cancel"};
                String message = "Export URL";
                int result = JOptionPane.showOptionDialog(null,
                        new Object[] {message, outputpathLabel, outputpathfield, depthLabel, depthfield},
                        "Export URL Path.",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        options,
                        options[0]);
                if (result == JOptionPane.OK_OPTION) {
                    try {
                        int depth = Integer.valueOf(depthfield.getText());
                        List<String> pathlist = rcdSVC.exportPath(depth);
                        String outputfinal="";
                        String output = outputpathfield.getText();
                        File outputFile = new File(output);
                        if (outputFile.isDirectory()){
                            if (output.endsWith("\\") || output.endsWith("/")) outputfinal=output+"output.txt";
                            else  outputfinal=output+"/output.txt";
                        } else if(!outputFile.exists()){
                            outputFile.createNewFile();
                            outputfinal=output;
                        }

                        FileWriter writer = new FileWriter(outputfinal);
                        for (String path : pathlist) {
                            writer.write(path + System.lineSeparator());
                        }
                        writer.close();
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                IOUtils.reportError(burpExtender, stderr, e, "Couldn't export url path");
            }
        });

        databaseControls.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        databaseControls.add(new JLabel("Database file: "));
        databaseControls.add(lbDbFile);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnDbSelect);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnDbClose);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnDBReload);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnDBClean);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnTblReset);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnTblClean);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnTblSave);
        databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
        databaseControls.add(btnURLExport);
        parentJpanel.add(databaseControls);

        JTable table = tblSVC.init(callbacks, rcdSVC);

        JTabbedPane tabs = new JTabbedPane();
        splitPane.setTopComponent(new JScrollPane(table));
        splitPane.setBottomComponent(tabs);

        tabs.addTab("Request", tblSVC.getRequestViewer().getComponent());
        tabs.addTab("Response", tblSVC.getResponseViewer().getComponent());

    }




}
