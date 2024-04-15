import javax.naming.InitialContext;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;
import javax.naming.Context;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.ObjectInputStream;
import java.lang.Runtime;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Random;
import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.beans.XMLDecoder;
import ognl.Ognl;
import ognl.OgnlContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;


public class DetectorTestCases {

    public void Overly_Broad_Path(){
        String sessionID = "";
        Cookie cookie = new Cookie("sessionID", sessionID);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
		cookie.setPath("/");      // Sink
    }

    public void Cookie_Not_Sent_Over_SSL(){
        Cookie cookie = new Cookie(); // Sink
		cookie.setSecure(false); // setSecure to be false
        cookie.setHttpOnly(true);
    }

    public void Http_Only_Not_Set(){
        Cookie cookie = new Cookie(); // Sink
		cookie.setHttpOnly(false); // setHttpOnly to be false
        cookie.setSecure(true);
    }

    public void Overly_Broad_Domain(){
        Cookie cookie = new Cookie();
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setDomain(".example.com");; // Sink 
    }

    public void SQL_Injection(HttpServletRequest request){
        Connection conn = DriverManager.getConnection("","user","pass");
        Statement state = conn.createStatement();
        String id = request.getParameter("Id");
        String sql="SELECT*FROM user WHERE id="+id+"";
        state.executeQuery(sql); // Sink
    }

    public void Command_Injection(HttpServletRequest request){
        String command = request.getParameter("cmd");
		Runtime.getRuntime().exec(command); // Sink
    }

    public void LDAP_Injection(HttpServletRequest request){
        String value = request.getParameter("value");
        Hashtable<String,String> env = new Hashtable<>();
        env.put("factory", "");
        env.put("url","");
        DirContext ctx = new InitialDirContext(env);
        String filter = "(cn=)"+value+")";
        NamingEnumeration<SearchResult> result = ctx.search("",filter,null); // Sink
    }

    public void Path_Traversal(HttpServletRequest request){
        String name = request.getParameter("name");
        File file = new File(name); // Sink
    }

    public void Trust_Boundary_Violation(HttpServletRequest request){
        String params = request.getParameter("params");
        HttpSession session = request.getSession();
        Map<String, Object> dataMap = new HashMap<String, Object>();
        dataMap.put("REPEAT_PARAMS", params);
        Map<String, Object> sessionMap = new HashMap<String, Object>();
        sessionMap.put("url", dataMap);
        session.setAttribute("SESSION_REPEAT_KEY", sessionMap); // Sink
    }

    public void XPath_Injection(HttpServletRequest request){
        String query = request.getParameter("query");
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        XPathExpression expr = xpath.compile(query); // Sink
    }

    public void Cross_Site_Scripting_Reflected(HttpServletRequest request, HttpServletResponse response){
        String param = request.getParameter("param");
        String value = param;
        response.getWriter().print(value);  // Sink
    }

    public void Cross_Site_Scripting_Stored(HttpServletRequest request, HttpServletResponse response){
        Connection conn = DriverManager.getConnection("","user","pass");
        Statement state = conn.createStatement();
        String sql="SELECT*FROM user WHERE id=1";
        ResultSet rs = state.executeQuery(sql);
        String name = rs.getString("name");
        response.getWriter().print(name);  // Sink
    }

    public void Expression_Injection(HttpServletRequest request){
        OgnlContext ctx = new OgnlContext();
        String expression = request.getParameter("input");
        Object expr = Ognl.parseExpression(expression); // Sink
        Object value = Ognl.getValue(expr, ctx, ctx.getRoot());
        System.out.println("Value: " + value); 
    }

    public void Unsafe_Deserization(HttpServletRequest request){
        String filepath = request.getParameter("file");
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filepath)); 
        ois.readObject(); // Sink
    }

    public void Xml_Injection(HttpServletRequest request){
        String path = request.getParameter("path");
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(new FileInputStream(path+"/Test.xml")));// Sink
        Object result = decoder.readObject(); 
    }

    public void Server_Side_Request_Forgery(HttpServletRequest request){
        URL url = new URL(request.getParameter("url"));
        URLConnection connection = url.openConnection(); // Sink
    }

    public void Open_Redirect(HttpServletRequest request, HttpServletResponse response){
        String data = request.getParameter("content");
        response.addHeader("content",data); // Sink

    }

    public void Log_Forging(HttpServletRequest request) {
        Logger logger = LoggerFactory.getLogger(DetectorTestCases.class);
        String value = request.getParameter("value");
        logger.info(value); // Sink
    }

    public void XML_External_Entity_Injection(HttpServletRequest request){
        String file = request.getParameter("file");
        XMLInputFactory xif = XMLInputFactory.newInstance();
        XMLStreamReader xsr = xif.createXMLStreamReader(new FileInputStream(file)); // Sink
    }

    public void JNDI_Reference_Injection(HttpServletRequest request){
        String dir = request.getParameter("dir");
        Context context = new InitialContext();
        DataSource ds = (DataSource) context.lookup(dir); // Sink
    }

    public void Insecure_Randomness(){
        Random random = new Random();
        int num = random.nextInt(10); // Sink
        System.out.println(num);
    }

    public void Weak_Encryption(){
        byte[] iv = {
            (byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
	    	(byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3033
	    };
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");
        SecretKey key = KeyGenerator.getInstance("DES").generateKey(); // Sink
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        c.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    }

    public void Weak_Hash(){
        MessageDigest algorithm;
        try{
            algorithm = MessageDigest.getInstance("MD5"); // Sink
            algorithm.reset();
            algorithm.update(s.getBytes("UTF-8"));
            byte[] messageDigest = algorithm.digest();
        }catch(Exception e){
        }
    }
}