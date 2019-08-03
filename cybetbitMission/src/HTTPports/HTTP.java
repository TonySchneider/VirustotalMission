package HTTPports;

import java.net.*;
import java.util.List;
import java.io.*;

public abstract class HTTP implements IHTTP {
	protected String strURL;
	protected URL url = null;
	protected HttpURLConnection conn = null;  
//	protected List<String> cookies = null;
	
	
	public HTTP(String url){
		this.strURL = url;  
	}
//	public HTTP(String url,List<String> cookies){
//		strURL = url;  
//		this.cookies = cookies;
//	}
	public String getStrURL(){return this.strURL;}
	public URL getURL(){return this.url;}
	public void setURL(URL url){this.url = url;}
	public void setConn(HttpURLConnection conn){this.conn = conn;}
//	public List<String> getCookies(){return this.cookies;}
//	public void setCookies(List<String> cookies){this.cookies = cookies;}
	public HttpURLConnection getConn(){return this.conn;}
	public String createConnection() throws IOException{
		url = new URL(strURL);
		conn= (HttpURLConnection) url.openConnection();
//		if(cookies != null){
//			for (String cookie : cookies) {
//				conn.setRequestProperty("Cookie", cookie.split(";", 1)[0]);
//			}
//		}
		return "";
	}
	public String getRespondeStatus() throws IOException{return this.conn.getResponseCode()+" "+this.conn.getResponseMessage();}
}
