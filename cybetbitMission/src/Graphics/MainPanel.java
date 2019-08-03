package Graphics;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
//import java.sql.Date;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.SwingWorker;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import org.json.JSONException;
import org.json.JSONObject;

import Backend.MySQLconnection;
import HTTPports.HTTPget;


public class MainPanel extends JPanel implements ActionListener{
	private static final long serialVersionUID = 1L;
//	private DefaultTableModel model = null;
//	private Connection myConn = null;
//	private Statement myStmt = null;
//	private ResultSet myRs = null;
//	private String[] columnNames = {"IP","DOMAIN","SCANS","DATE"};
//	private Object[][] data;
	private final JPanel topPanel = new JPanel(),powerPanel = new JPanel(),logPanel = new JPanel(),buttomPanel = new JPanel();
	private static final JTextPane logs = new JTextPane();
	private final button power = new button("/Images/power.png","/Images/power2.png");
	private static ArrayList<String> IPs = new ArrayList<String>();
	public MainPanel(){
		setBackground(Color.white);
		setLayout(new GridLayout(2,1));
		
		GridBagConstraints t = new GridBagConstraints();
		
		topPanel.setLayout(new GridBagLayout());
		topPanel.setOpaque(false);
		powerPanel.setOpaque(false);
		logPanel.setOpaque(false);
		power.addActionListener(this);
		
		powerPanel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridx = 1;
		powerPanel.add(power,c);
		
		t.gridx = 0;
		t.weightx = 0.3;
		topPanel.add(powerPanel,t);
		
		logPanel.setBorder(BorderFactory.createTitledBorder(null, "Logs", TitledBorder.LEFT, TitledBorder.TOP, new Font("Monospace",Font.BOLD,12), Color.RED));
		logs.setPreferredSize(new Dimension(450,190));
//		logs.setLineWrap(true);
		logs.setEditable(false);
		DefaultCaret caret = (DefaultCaret) logs.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		JScrollPane logsScroll = new JScrollPane(logs);
		logPanel.add(logsScroll);
		
		t.weightx = 0.7;
		t.gridx = 1;
		topPanel.add(logPanel,t);
		
		add(topPanel);
		
		
		buttomPanel.setBorder(BorderFactory.createTitledBorder(null, "malicious IPs", TitledBorder.LEFT, TitledBorder.TOP, new Font("Monospace",Font.BOLD,12), Color.RED));
		JTable table = new JTable();
		MySQLconnection.createTableModel();
//		model = new DefaultTableModel(data, columnNames) {
//			private static final long serialVersionUID = 1L;
//			@Override
//		    public boolean isCellEditable(int row, int column) {
//		       return false;
//		    }
//		};
//		try{
//			myConn = DriverManager.getConnection("jdbc:mysql://localhost:3306/cbmission","root","1234");
//			myStmt = myConn.createStatement();
//			myRs = myStmt.executeQuery("select * from ips");
//			while (myRs.next()) {
//				model.addRow(new Object[]{myRs.getString("ip"),myRs.getString("domain"),myRs.getString("scans"),myRs.getString("date")});
//			}
//		}catch(Exception e){
//			JOptionPane.showMessageDialog(null, e.getMessage());
//		}
		table.setModel(MySQLconnection.getTableModel());
		table.setFillsViewportHeight(true);
		JScrollPane scrollPane = new JScrollPane(table);
		DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
		centerRenderer.setHorizontalAlignment( JLabel.CENTER );
		for (int i=0;i<4;i++) table.getColumnModel().getColumn(i).setCellRenderer( centerRenderer );
		add(scrollPane);
	}
	@Override
	public void actionPerformed(ActionEvent e) {

		if(e.getSource() == power){
			power.setEnabled(false);
			
			
			SwingWorker<Boolean , Integer> sw = new SwingWorker<Boolean, Integer>()  {
				@Override
				protected Boolean doInBackground(){
					
					
					setLog("Parsing IP file..","regular");
					try {
						parseIPS();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					
					String URL = "https://www.virustotal.com/vtapi/v2/url/report";
					String urlParams = "apikey=cb7d8204281a2db9725f797bad84968c985ed0ef240a8896b053678559d7c3d6&resource=";
					for(int i=0;i<IPs.size();i++){
						String response = "";
						HTTPget getResponse = null;
						try {
							getResponse = new HTTPget(URL,urlParams+IPs.get(i));
							response = getResponse.createConnection();
						} catch (IOException e) {
							e.printStackTrace();
						}
						
						if(!response.equals("200 OK")){
							if(response.equals("204 No Content")){
//								getSecondsToNewRequest();
//								System.out.println(IPs.get(i));
								timer();
								i--;
								continue;
							}
							setLog(IPs.get(i)+" Virustotal responded - "+response,"regular");
						}
						else{
							updateSysParam();
							//Virustotal
							///response_code: if the item you searched for was not present in VirusTotal's dataset this result will be 0. 
							///If the requested item is still queued for analysis it will be -2. 
							///If the item was indeed present and it could be retrieved it will be 1. Any other case is detailed in the full reference.
							String body = "";
							try {
								body = getResponse.getSource();
							} catch (IOException e1) {
								e1.printStackTrace();
							}
							System.out.println(body);
							JSONObject jsonobj = null;
							int response_code = 3;
							try {
								jsonobj = new JSONObject(body);
								response_code = (int)jsonobj.get("response_code");
							} catch (JSONException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							
							
							switch(response_code){
							case 0:
								setLog(IPs.get(i)+" was not present in VirusTotal's dataset","regular");
								break;
							case 1:
//								System.out.println(IPs.get(i));
								int positives;
								try {
									positives = (int)jsonobj.get("positives");
									if(positives > 0){
										addIP(IPs.get(i),getDomain(IPs.get(i)),getEfectedScans((JSONObject)jsonobj.get("scans")));
										setLog(IPs.get(i)+" is a malicious IP and added to the database.","red");
									}
									else
										setLog(IPs.get(i)+" is a clean IP","good");
								} catch (JSONException e) {
									e.printStackTrace();
								}
								break;
							case -2:
								setLog(IPs.get(i)+" is still queued for analysis","regular");
								break;
							default:
								System.out.println("wrong response_code value");
								break;
							}
						}
						
					}
					
					
					return true;
				} 
				@Override
				protected void done(){
					power.setEnabled(true);
				}
				
	        };
	        
	        sw.execute();
		}
	}
	public static void parseIPS() throws IOException{
		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Tony\\javaProjects\\cybetbitMission\\src\\Graphics\\IPs.txt"));
		try {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		    }
		    everything = sb.toString();
		} finally {
		    br.close();
		}
		int index = 0;
		for(int i=0;i<everything.length();i++){
			if(everything.charAt(i) == ',' || i == everything.length()-1){
				IPs.add(everything.substring(index,i));
				index = i+1;
			}
		}
	}
	public synchronized static void setLog(String log,String type){
		StyledDocument doc = logs.getStyledDocument();

        Style style = logs.addStyle("I'm a Style", null);
		if(type.equals("red")){
			StyleConstants.setForeground(style, Color.red);
			try { doc.insertString(doc.getLength(), log+"\n",style); }
	        catch (BadLocationException e){}
		}else if(type.equals("regular")){
			StyleConstants.setForeground(style, Color.black);
			try { doc.insertString(doc.getLength(), log+"\n",style); }
	        catch (BadLocationException e){}
		}else if(type.equals("good")){
			StyleConstants.setForeground(style, Color.GREEN);
			try { doc.insertString(doc.getLength(), log+"\n",style); }
	        catch (BadLocationException e){}
		}
	}
	public void timer(){
		int secondsLeft = (int)getSecondsToNewRequest();
		setLog("The scan will continue in "+secondsLeft+" seconds","regular");
		try {
			Thread.sleep(secondsLeft*1000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void addIP(String IP,String domain,String scans){
		String booleanQuery = "SELECT EXISTS (SELECT 1 FROM ips WHERE IP = '"+IP+"')";
		String insertQuery = "insert into ips " + " (IP, DOMAIN, SCANS, DATE)"
				+ " values ('"+IP+"', '"+domain+"', '"+scans+"', '"+getCurrentDateTime()+"')";
		String updateQuery = "UPDATE ips SET DOMAIN = '"+domain+"', SCANS = '"+scans+"', DATE = '"+getCurrentDateTime()+"' WHERE IP = '"+IP+"';";
		
		if(MySQLconnection.stringExecute(booleanQuery).equals("1"))
			MySQLconnection.execute(updateQuery);
		else
			MySQLconnection.execute(insertQuery);
		refreshTable();
		
	}
	public String getDomain(String IP){
		//https://hackertarget.com/reverse-dns-lookup/
		String url = "https://api.viewdns.info/reversedns/?ip="+IP+"&apikey=99e63ef1f39f9dd85f52c2ca7a70fac626cb863c&output=json",status = "";
		HTTPget viewdns = new HTTPget(url);
		try {
			status = viewdns.createConnectionNoParams();
//			System.out.println(status);
			if(status.equals("200 OK")){
				String source = viewdns.getSource();
				JSONObject body = new JSONObject(source);
				JSONObject reponseDetails = body.getJSONObject("response");
				
//				System.out.println(source);
				return reponseDetails.getString("rdns");
			}
		} catch (IOException | JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "NO DOMAIN";
	}
	public String getEfectedScans(JSONObject source){
		String effected = "";
		Iterator<String> keys = source.keys();
		JSONObject tempJSON = null;
		while(keys.hasNext()) {
		    String key = keys.next();
		    try {
				tempJSON = source.getJSONObject(key);
				boolean check = (boolean)tempJSON.get("detected");
				if(check){
					effected += key+":"+source.get(key)+"\n";
				}
			} catch (JSONException e) {
				e.printStackTrace();
			}
		    
		}

		return effected;
	}
	public String getCurrentDateTime(){
		SimpleDateFormat formatter= new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date date = new Date(System.currentTimeMillis());
		return formatter.format(date);
	}
	public void refreshTable(){
		MySQLconnection.clearRows();
		MySQLconnection.buildModel();
		buttomPanel.revalidate();
		
	}
	public long getSecondsToNewRequest(){
		String query = "SELECT value FROM system_params WHERE name = 'LastTimeRequest'";
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date currentDatetime = null, LastUpdateDatetime = null;
		
		try {
			currentDatetime = format.parse(getCurrentDateTime());
			LastUpdateDatetime = format.parse(MySQLconnection.stringExecute(query));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
//		System.out.println("cur:"+currentDatetime.getTime()+"last:"+LastUpdateDatetime.getTime());
		
		long diff = currentDatetime.getTime() - LastUpdateDatetime.getTime();
		long secondsDiff = diff / 1000 % 60;
		
//		System.out.println("getSecondsToNewRequest worked");
		return 60-secondsDiff;
	}
	public void updateSysParam(){
		String insertQuery = "UPDATE system_params SET value = '"+getCurrentDateTime()+"' WHERE name = 'LastTimeRequest'";
		MySQLconnection.execute(insertQuery);
	}
}
