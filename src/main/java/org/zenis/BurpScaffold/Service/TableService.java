package org.zenis.BurpScaffold.Service;

import org.zenis.BurpScaffold.Entity.Record;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.sql.SQLException;

public class TableService {

    private JTable table;

    public TableService(JTable table) {
        this.table = table;
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
        table.setModel(rcdSVC.GenarateTable());
    }

    public void saveFilteredTable(RecordService rcdSVC){
        rcdSVC.syncFilterResult();
        table.setModel(rcdSVC.GenarateTable());
    }

    public void saveTableIncremental(){}

    public void syncFilterResult(RecordService rcdSVC){
        rcdSVC.syncFilterResult();
        table.setModel(rcdSVC.GenarateTable());
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
        table.setModel(rcdSVC.GenarateTable());
    }

    public void cleanDB(RecordService rcdSVC) {
        try {
            rcdSVC.getRcdDAO().deleteAllRecords();
            rcdSVC.cleanDelCache();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public Integer getSelectedId() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow == -1) return null;
        return (Integer)table.getValueAt(selectedRow, table.convertColumnIndexToView(0));
    }

    public Record getSelectedRcd(RecordService rcdSVC) {
        return rcdSVC.getRcdByID(getSelectedId());
    }

}
