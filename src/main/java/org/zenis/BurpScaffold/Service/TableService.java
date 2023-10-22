package org.zenis.BurpScaffold.Service;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;
import org.zenis.BurpScaffold.Entity.Record;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class TableService {

    private JTable table;
    BurpExtender burpExtender;
    IMessageEditor requestViewer;
    IMessageEditor responseViewer;

    public TableService(BurpExtender burpExtender) {
        this.table = new JTable();
        this.burpExtender = burpExtender;
        IMessageEditor requestViewer;
        IMessageEditor responseViewer;
    }

    public JTable init( IBurpExtenderCallbacks callbacks, RecordService rcdSVC){

        requestViewer = callbacks.createMessageEditor(burpExtender, false);
        responseViewer = callbacks.createMessageEditor(burpExtender, false);

        table.getSelectionModel().addListSelectionListener(new SharedListSelectionHandler());

        table.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showTablePopup(callbacks, e, rcdSVC);
            }

            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showTablePopup(callbacks, e, rcdSVC);
            }
        });
        table.setAutoCreateRowSorter(true);
        table.setEnabled(false);
        return table;
    }

    private void showTablePopup(IBurpExtenderCallbacks callbacks, MouseEvent e, RecordService rcdSVC) {
        JPopupMenu pm = new JPopupMenu();
        if (pm.getComponentCount() != 0) pm.addSeparator();

        addToPopup(pm, "copy url", event -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(getSelectedRcd(rcdSVC).getUrl()), null);
        });
        addToPopup(pm, "delete this Record", event -> rcdSVC.deleteRecord(getSelectedRcd(rcdSVC)));
//        addToPopup(pm, "Hide this Record", event -> rcdSVC.hideRecord(tblSVC.getSelectedRcd(rcdSVC)));
        addToPopup(pm, "Send request to Comparer", event -> callbacks.sendToComparer(getSelectedRcd(rcdSVC).getRequest().getBytes()));
        addToPopup(pm, "Send response to Comparer", event -> callbacks.sendToComparer(getSelectedRcd(rcdSVC).getResponse().getBytes()));
        addToPopup(pm, "Send request to Repeater", event -> {
            Record rcd = getSelectedRcd(rcdSVC);
            boolean ishttps = false;
            if ("https".equals(rcd.getProtocol())) {
                ishttps = true;
            }
            callbacks.sendToRepeater(
                    rcd.getHost(),
                    rcd.getPort(),
                    ishttps,
                    rcd.getRequest().getBytes(),
                    null);
        });
        pm.show(e.getComponent(), e.getX(), e.getY());
    }

    private static void addToPopup(JPopupMenu pm, String title, ActionListener al) {
        final JMenuItem mi = new JMenuItem(title);
        mi.addActionListener(al);
        pm.add(mi);
    }

    class SharedListSelectionHandler implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent e) {
            requestViewer.setMessage(burpExtender.getRequest(), true);
            responseViewer.setMessage(burpExtender.getResponse(), false);
        }
    }

    public void cleanTable(RecordService rcdSVC) {
        rcdSVC.clean();
        table.setModel(new AbstractTableModel() {
            @Override public int getRowCount() { return 0; }
            @Override public int getColumnCount() { return Record.class.getDeclaredFields().length-1; }
            @Override public String  getColumnName(int column) { return Record.class.getDeclaredFields()[column+1].getName(); }

            @Override
            public Object getValueAt(int row, int column) {
                return "";
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return Record.class.getDeclaredFields()[columnIndex+1].getClass();
            }
        });
    }

    public void resetTable(RecordService rcdSVC){
        rcdSVC.resetIDList();
        GenarateTable(rcdSVC);
        formatTable();
    }
    void formatTable(){
        SetWidth();
        setSortation();
    }

    public void setEnable(boolean flag){
        table.setEnabled(flag);
    }

    public void saveFilteredTable(RecordService rcdSVC){
        rcdSVC.syncFilterResult();
        GenarateTable(rcdSVC);
        formatTable();
    }

    public void saveTableIncremental(){}

    public void syncFilterResult(RecordService rcdSVC){
        rcdSVC.syncFilterResult();
        GenarateTable(rcdSVC);
        formatTable();
    }

    public void saveTable(RecordService rcdSVC) {
        try {
            rcdSVC.saveDB();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void reloadDB(RecordService rcdSVC) throws SQLException {
        rcdSVC.reload();
        GenarateTable(rcdSVC);
        formatTable();
    }

    public void cleanDB(RecordService rcdSVC) {
        try {
            rcdSVC.getRcdDAO().deleteAllRecords();
            rcdSVC.cleanDelCache();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public IMessageEditor getResponseViewer() {
        return responseViewer;
    }

    public IMessageEditor getRequestViewer() {
        return requestViewer;
    }

    public Integer getSelectedId() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow == -1) return null;
        return (Integer)table.getValueAt(selectedRow, table.convertColumnIndexToView(0));
    }

    public Record getSelectedRcd(RecordService rcdSVC) {
        return rcdSVC.getRcdByID(getSelectedId());
    }

    void SetWidth() {
        if (table.getColumnCount() > 0) {
            table.getColumnModel().getColumn(0).setMaxWidth(50);
            table.getColumnModel().getColumn(4).setMinWidth(800);
        }
    }
    void setSortation(){
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(sorter);
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();

        int columnIndexToSort = 0;
        sortKeys.add(new RowSorter.SortKey(columnIndexToSort, SortOrder.ASCENDING));

        sorter.setSortKeys(sortKeys);
        sorter.sort();
    }

    public void GenarateTable(RecordService rcdSVC) {
        table.setModel(new AbstractTableModel() {
            @Override
            public int getRowCount() {
                return rcdSVC.getIdList().size();
            }

            @Override
            public int getColumnCount() {
                return rcdSVC.getRecordFields().size();
            }

            @Override
            public String getColumnName(int colindex) {
                return rcdSVC.getRecordFields().get(colindex).getName();
            }

            @Override
            public Class<?> getColumnClass(int colindex) {
                if(rcdSVC.getRecordFields().get(colindex).getType() == int.class){
                    return Integer.class;
                }
                return rcdSVC.getRecordFields().get(colindex).getType();
            }

            @Override
            public Object getValueAt(int rowIndex, int colindex) {
                Field column = rcdSVC.getRecordFields().get(colindex);
                column.setAccessible(true);
                Object retobj = null;
                Record rcd = rcdSVC.getRcdByID(rcdSVC.getIdList().get(rowIndex));
                if (rcd == null) {
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
        });
        formatTable();
    }
}
