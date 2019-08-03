package HTTPports;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class HTTPget extends HTTP {
	private byte[] HTTPdata;
	private int HTTPdataLength;
	public HTTPget(String url) {
		super(url);
	}
	public HTTPget(String url, String urlParameters) throws UnsupportedEncodingException {
		super(url);
		HTTPdata = (urlParameters).getBytes(StandardCharsets.UTF_8);
		HTTPdataLength = HTTPdata.length;
	}
	public String createConnection() throws IOException{
		super.createConnection();
		//Sets whether HTTP redirects (requests with response code 3xx) should be automatically followed by this HttpURLConnection instance.
//		this.conn.setInstanceFollowRedirects(false);
		this.conn.setDoOutput(true);
//		this.conn.setRequestMethod("GET");
		this.conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
		this.conn.setRequestProperty("charset", "utf-8");
		this.conn.setRequestProperty("Content-Length", Integer.toString(HTTPdataLength));
//		this.conn.setUseCaches(false);
		try(DataOutputStream wr = new DataOutputStream(this.conn.getOutputStream())) {
		   wr.write(HTTPdata);
		   wr.flush();
		}
		return getRespondeStatus();
	}
	public String createConnectionNoParams() throws IOException{
		super.createConnection();
		this.conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
		return getRespondeStatus();
	}
	public String getSource() throws IOException{
		BufferedReader in = new BufferedReader(new InputStreamReader(getConn().getInputStream()));
        String inputLine,source = "";
        while ((inputLine = in.readLine()) != null) 
        	source = source + inputLine + "\n";
        in.close();
        return source;
	}
}
