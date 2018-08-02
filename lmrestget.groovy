//imports needed classes, defines creds and lm portal account, constructs url, specify rest endpoint (e.g., /devices/devices), prints stdout (println)

import org.apache.http.HttpEntity
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
	
//define credentials and url
def accessId = '################';
def accessKey = '#####################';
def account = '########';
def resourcePath = "/device/devices"
def url = "https://" + account + ".logicmonitor.com" + "/santaba/rest" + resourcePath;

//get current time
epoch = System.currentTimeMillis();

//calculate signature
requestVars = "GET" + epoch + resourcePath;

hmac = Mac.getInstance("HmacSHA256");
secret = new SecretKeySpec(accessKey.getBytes(), "HmacSHA256");
hmac.init(secret);
hmac_signed = Hex.encodeHexString(hmac.doFinal(requestVars.getBytes()));
signature = hmac_signed.bytes.encodeBase64();

// HTTP Get
CloseableHttpClient httpclient = HttpClients.createDefault();
httpGet = new HttpGet(url);
httpGet.addHeader("Authorization" , "LMv1 " + accessId + ":" + signature + ":" + epoch);
response = httpclient.execute(httpGet);
responseBody = EntityUtils.toString(response.getEntity());
code = response.getStatusLine().getStatusCode();

// Print Response
println "Status:" + code;
println "Body:" + responseBody;

httpclient.close();