import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import java.util.TimeZone;

public class BatchSMS
{
    private final static String CHARSET_UTF8 = "utf8";

    public static void main(String[] args) throws Exception {

        // Added Git to check Bitbucket

        String accessKeyId = "";
        String accessSecret = "";

        String domain = "sms-intl.ap-southeast-1.aliyuncs.com";

        //java.text.SimpleDateFormat df = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        java.text.SimpleDateFormat df = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        df.setTimeZone(new java.util.SimpleTimeZone(0, "GMT"));// set time zone
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();

        //1.system parameters
        paras.put("SignatureMethod", "HMAC-SHA1");
        paras.put("SignatureNonce", java.util.UUID.randomUUID().toString().replaceAll("-",""));
        paras.put("AccessKeyId", accessKeyId);
        paras.put("SignatureVersion", "1.0");
        String ddd = df.format(new java.util.Date());
        System.out.println(ddd);
        paras.put("Timestamp", ddd);
        //paras.put("Timestamp", getGMT());
        paras.put("Format", "JSON");

        //2.business API parameters
        paras.put("Action","BatchSendMessageToGlobe");
        paras.put("Version", "2018-05-01");
        paras.put("To", "[\"919820099496\", \"919326058699\"]");
        paras.put("Message","[\"Nikesh have a test batch.\", \"From Nikesh\"]");
        //paras.put("From", "Alibaba");
        paras.put("Type", "NOTIFY"); //3.remove Key signature
        if (paras.containsKey("Signature")) paras.remove("Signature");

        //4.orderd by Key
        java.util.TreeMap<String, String> sortParas = new java.util.TreeMap<String, String>(); sortParas.putAll(paras);

        //5.construct the request string to be signed
        java.util.Iterator<String> it = sortParas.keySet().iterator(); StringBuilder sortQueryStringTmp = new StringBuilder();
        while (it.hasNext()) {
            String key = it.next();
            sortQueryStringTmp.append("&").append(specialUrlEncode(key)).append("=").append(specialUrlEncode(paras.get(key)));
        }

        String sortedQueryString = sortQueryStringTmp.substring(1);// remove one more & System.out.println(sortedQueryString);
        StringBuilder stringToSign = new StringBuilder();
        stringToSign.append("GET").append("&"); stringToSign.append(specialUrlEncode("/")).append("&");
        stringToSign.append(specialUrlEncode(sortedQueryString));
        System.out.println(stringToSign);

        //step 4:signature
        // The signature adopts HmacSHA1 + Base64, and the encoding adopts UTF-8

        String sign = sign(accessSecret + "&", stringToSign.toString()); System.out.println(sign);

        //6.special URL encoding
        String signature = specialUrlEncode(sign);// zJDF%2BLrzhj%2FThnlvIToysFRq6t4%3D System.out.println(signature);
        // The final completed GET Request HTTP URL
        System.out.println("http://"+domain+"/?Signature=" + signature + sortQueryStringTmp);
        String url = "http://"+domain+"/?Signature=" + signature + sortQueryStringTmp;

        //HttpPost httpPost = new HttpPost(url);
        HttpGet httpPost = new HttpGet(url);


        String result = access(httpPost);
        System.out.println(result);
    }

    private static String access(HttpRequestBase httpRequest) {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpResponse response;
        String result;
        try {
            httpRequest.setHeader("accept-encoding", "UTF-8");
            response = client.execute(httpRequest);
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity httpEntity = response.getEntity();
                result = EntityUtils.toString(httpEntity);
            } else {
                System.out.println(response.getStatusLine().getStatusCode());
                HttpEntity httpEntity = response.getEntity();
                result = EntityUtils.toString(httpEntity);
                System.out.println(result);
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return result;
    }

    public static String specialUrlEncode(String value) throws Exception {
        return java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20").replace("*",
                "%2A").replace("%7E", "~");
    }


    public static String sign(String accessSecret, String stringToSign) throws Exception { javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1"); mac.init(new javax.crypto.spec.SecretKeySpec(accessSecret.getBytes("UTF-8"),
            "HmacSHA1"));
        byte[] signData = mac.doFinal(stringToSign.getBytes("UTF-8")); return new sun.misc.BASE64Encoder().encode(signData);
    }

}