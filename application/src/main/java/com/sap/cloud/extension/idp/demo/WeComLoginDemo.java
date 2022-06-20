package com.sap.cloud.extension.idp.demo;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sap.cloud.sdk.cloudplatform.connectivity.DefaultHttpDestination;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpDestination;

/**
 * Servlet implementation class WeComOAuth2Service
 */
@WebServlet(name = "WeComService", urlPatterns = { "/oauth2/client/WeComLoginDemo" })
public class WeComLoginDemo extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = LoggerFactory.getLogger(WeComLoginDemo.class);   
    /**
     * @see HttpServlet#HttpServlet()
     */
    public WeComLoginDemo() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String code = request.getParameter("code");
		logger.info("WeCom code->"+code);
		response.getWriter().append("WeCom code: ").append(code).println();
		Map<String, String> output = new HashMap<String, String>();
		boolean result4Token = getTokenByCode(code, output);
		if(result4Token) {
			String token = output.get("token");
			response.getWriter().append("WeCom token: ").append(token).println();
			boolean result4User = getUserByToken(code, token, output);
			if(result4User) {
				String userId = output.get("userId");
				response.getWriter().append("WeCom user: ").append(userId).println();
			}
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}
	
	private boolean getTokenByCode(String code, Map<String, String> output) {
		try {
			HttpDestination weComTokenDest = DestinationAccessor.getDestination("WeCom_TokenService").asHttp();
			URI uri = weComTokenDest.getUri();
			//DefaultHttpDestination d = DefaultHttpDestination.builder(uri).property("URL.queries.corpid", "ww8c0910bda01c1ec5").property("URL.queries.corpsecret", "oh--oLwfBBT76biBUtxtBRggHK4ILdQ_7nea-d8jJAs").build();
			//HttpClient httpClient = HttpClientAccessor.getHttpClient(d);
			HttpClient httpClient = HttpClientAccessor.getHttpClient(weComTokenDest);
			HttpGet httpget = new HttpGet(uri.toURL().toString());
			logger.info("WeCom token service url->"+uri.toURL().toString());
			HttpResponse tokenResp = httpClient.execute(httpget);
			int statusCode = tokenResp.getStatusLine().getStatusCode();
			String tokenRespBody = "";
			if(statusCode == HttpStatus.SC_OK) {
				HttpEntity entity = tokenResp.getEntity();
				if(entity != null) {
					tokenRespBody = EntityUtils.toString(entity);
					logger.info("WeCom token service response->"+tokenRespBody);
					ObjectMapper objectMapper = new ObjectMapper();
					Map<String, Object> jsonMap = objectMapper.readValue(tokenRespBody,new TypeReference<Map<String,Object>>(){});
					String accessToken = jsonMap.get("access_token").toString();
					output.put("token", accessToken);
					return true;
				}
			} else {
			    logger.error("Unexpected response status: " + statusCode);
			}
		} catch (Exception e) {
			logger.error(code, e);
		} 
		return false;
	}
	
	private boolean getUserByToken(String code, String token, Map<String, String> output) {
		try {
			HttpDestination weComUserDest = DestinationAccessor.getDestination("WeCom_UserService").asHttp();
			URI uri = weComUserDest.getUri();
			DefaultHttpDestination d = DefaultHttpDestination.builder(uri).property("URL.queries.code", code).property("URL.queries.access_token", token).build();
			HttpClient httpClient = HttpClientAccessor.getHttpClient(d);
			HttpGet httpget = new HttpGet(uri.toURL().toString());
			logger.info("WeCom user service url->"+uri.toURL().toString());
			HttpResponse tokenResp = httpClient.execute(httpget);
			int statusCode = tokenResp.getStatusLine().getStatusCode();
			String userRespBody = "";
			if(statusCode == HttpStatus.SC_OK) {
				HttpEntity entity = tokenResp.getEntity();
				if(entity != null) {
					userRespBody = EntityUtils.toString(entity);
					logger.info("WeCom user service response->"+userRespBody);
					ObjectMapper objectMapper = new ObjectMapper();
					Map<String, Object> jsonMap = objectMapper.readValue(userRespBody,new TypeReference<Map<String,Object>>(){});
					String userId = jsonMap.get("UserId").toString();
					output.put("userId", userId);
					return true;
				}
			} else {
			    logger.error("Unexpected response status: " + statusCode);
			}
		} catch (Exception e) {
			logger.error(code, e);
		} 
		return false;
	}

}
