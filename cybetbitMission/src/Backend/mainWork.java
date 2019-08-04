package Backend;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

import org.json.JSONException;
import org.json.JSONObject;

import Graphics.MainPanel;
import HTTPports.HTTPget;

public class mainWork {
	private static final String URL = "https://www.virustotal.com/vtapi/v2/url/report";
	private static final String urlParams = "apikey=cb7d8204281a2db9725f797bad84968c985ed0ef240a8896b053678559d7c3d6&resource=";
	private static final ArrayList<String> IPs = new ArrayList<String>();
	private static final SimpleDateFormat formatter= new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	public static void Do(){
		MainPanel.setLog("Parsing IP file..","regular");
		try {
			parseIPS();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		for(int i=0;i<IPs.size();i++){
			String apiResponse = getReponse(IPs.get(i));
			int response_code = getResponseCode(apiResponse);
			
			switch(response_code){
				case 0:
					MainPanel.setLog(IPs.get(i)+" was not present in VirusTotal's dataset","regular");
					break;
				case 1:
					if(itsMaliciousIP(apiResponse)){
						addIP(IPs.get(i),getDomain(IPs.get(i)),getEfectedScans(getScans(apiResponse)));
						MainPanel.setLog(IPs.get(i)+" is a malicious IP and added to the database.","red");
					}
					else
						MainPanel.setLog(IPs.get(i)+" is a clean IP","good");
					break;
				case -2:
					MainPanel.setLog(IPs.get(i)+" is still queued for analysis","regular");
					break;
				default:
					System.out.println("wrong response_code value");
					break;
			}
		}
	}
	
	public static int getResponseCode(String source){
		JSONObject jsonobj = null;
//		System.out.println(source);
		int response_code = 3;
		try {
			jsonobj = new JSONObject(source);
			response_code = (int)jsonobj.get("response_code");
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return response_code;
	}
	public static String getReponse(String IP){
		String response = "";
		HTTPget getResponse = null;
		try {
			getResponse = new HTTPget(URL,urlParams+IP);
			response = getResponse.createConnection();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//204 - Request rate limit exceeded. 
		//You are making more requests than allowed. 
		//You have exceeded one of your quotas (minute, daily or monthly). 
		//Daily quotas are reset every day at 00:00 UTC.
		while(response.equals("204 No Content")){
			timer();
			try {
				response = getResponse.createConnection();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		
		
		if(!response.equals("200 OK")){
			MainPanel.setLog(IP+" Virustotal responded - "+response,"regular");
			return response;
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
			return body;
		}
		
	}
	public static boolean itsMaliciousIP(String source){
		JSONObject jsonobj = null;
		int positives = 0;
		try {
			jsonobj = new JSONObject(source);
			positives = (int)jsonobj.get("positives");
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return positives > 0;
	}
	public static JSONObject getScans(String source){
		JSONObject jsonobj = null;
			try {
				jsonobj = new JSONObject(source);
				return (JSONObject)jsonobj.get("scans");
			} catch (JSONException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return null;
	}
	public static void parseIPS() throws IOException{
		String everything = "";
		BufferedReader br = new BufferedReader(new FileReader(System.getProperty("user.home") + "/Desktop"+"/IPs.txt"));
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
	public static void timer(){
		int secondsLeft = (int)getSecondsToNewRequest();
		MainPanel.setLog("The scan will continue in "+secondsLeft+" seconds","regular");
		try {
			Thread.sleep(secondsLeft*1000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static void addIP(String IP,String domain,String scans){
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
	public static String getDomain(String IP){
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
	public static String getEfectedScans(JSONObject source){
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
	public static String getCurrentDateTime(){
		Date date = new Date(System.currentTimeMillis());
		return formatter.format(date);
	}
	public static void refreshTable(){
		MySQLconnection.clearRows();
		MySQLconnection.buildModel();
		MainPanel.refreshButtomPanel();
		
	}
	public static long getSecondsToNewRequest(){
		String query = "SELECT value FROM system_params WHERE name = 'LastTimeRequest'";
		Date currentDatetime = null, LastUpdateDatetime = null;
		
		try {
			currentDatetime = formatter.parse(getCurrentDateTime());
			LastUpdateDatetime = formatter.parse(MySQLconnection.stringExecute(query));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		long diff = currentDatetime.getTime() - LastUpdateDatetime.getTime();
		long secondsDiff = diff / 1000 % 60;
		return 60-secondsDiff;
	}
	public static void updateSysParam(){
		String insertQuery = "UPDATE system_params SET value = '"+getCurrentDateTime()+"' WHERE name = 'LastTimeRequest'";
		MySQLconnection.execute(insertQuery);
	}
}
