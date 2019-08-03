package HTTPports;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

public interface IHTTP {
	public String getStrURL();
	public URL getURL();
//	public List<String> getCookies();
//	public void setCookies(List<String> cookies);
	public String createConnection() throws IOException;
	public void setURL(URL url);
	public void setConn(HttpURLConnection conn);
	public HttpURLConnection getConn();
}
