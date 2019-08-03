package HTTPports;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;


public class HTTPpost extends HTTP {
	private byte[] HTTPdata;
	private int HTTPdataLength;
	public HTTPpost(String url, String urlParameters) throws UnsupportedEncodingException {
		super(url);
		HTTPdata = (urlParameters).getBytes(StandardCharsets.UTF_8);
		HTTPdataLength = HTTPdata.length;
	}
//	public HTTPpost(String url, List<String> cookies, String urlParameters) {
//		super(url,cookies);
//		HTTPdata = urlParameters.getBytes(StandardCharsets.UTF_8);
//		HTTPdataLength = HTTPdata.length;
//	}
	public String createConnection() throws IOException{
		super.createConnection();
		this.conn.setDoOutput(true);
		this.conn.setInstanceFollowRedirects(false);
		this.conn.setRequestMethod("POST");
		this.conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
		this.conn.setRequestProperty("charset", "utf-8");
		this.conn.setRequestProperty("Content-Length", Integer.toString(HTTPdataLength));
		this.conn.setUseCaches(false);
		try(DataOutputStream wr = new DataOutputStream(this.conn.getOutputStream())) {
		   wr.write(HTTPdata);
		   wr.flush();
		}
		return getRespondeStatus();
	}
}
