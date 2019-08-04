package Backend;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.swing.JOptionPane;
import javax.swing.table.DefaultTableModel;

public class MySQLconnection {
	private static final String MySQLjdbc = "jdbc:mysql://localhost:3306/cbmission";
	private static final String MySQLuser = "root"; //Usually it's root
	private static final String MySQLpass = "1234";
	private static DefaultTableModel model = null;
	private static Connection myConn = null;
	private static Statement myStmt = null;
	private static ResultSet myRs = null;
	private static final String[] columnNames = {"IP","DOMAIN","SCANS","DATE"};
	private static Object[][] data;
	public static String stringExecute(String query){
		try {
			myRs = myStmt.executeQuery(query);
			myRs.next();
			return myRs.getString(1);
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}
	public static void execute(String query){
		try {
			myStmt.execute(query);
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	public static void createTableModel(){
		model = new DefaultTableModel(data, columnNames) {
			private static final long serialVersionUID = 1L;
			@Override
		    public boolean isCellEditable(int row, int column) {
		       return false;
		    }
		};
		try{
			myConn = DriverManager.getConnection(MySQLjdbc,MySQLuser,MySQLpass);
			myStmt = myConn.createStatement();
			buildModel();
		}catch(Exception e){
			JOptionPane.showMessageDialog(null, e.getMessage());
		}
	}
	public static DefaultTableModel getTableModel(){
		return model;
	}
	public static void buildModel(){
		try {
			myRs = myStmt.executeQuery("select * from ips");
			while (myRs.next()) {
				model.addRow(new Object[]{myRs.getString("ip"),myRs.getString("domain"),myRs.getString("scans"),myRs.getString("date")});
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static void clearRows(){
		model.setRowCount(0);
	}
}
