package com.sap.cloud.extension.idp.service.wecom;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml.saml2.core.Response;

import com.sap.cloud.extension.idp.identity.User;
import com.sap.cloud.extension.idp.utils.opensaml.OpenSAMLUtils;

/**
 * Servlet implementation class WeComPostBinding
 */
@WebServlet("/saml2/idp/SingleSignOnService/WeCom")
public class WeComSingleSignOnService extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public WeComSingleSignOnService() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String code = request.getParameter("code");
		WeComUserService userService = new WeComUserService();
		User user = userService.getUserByCode(code);
		Response samlResponse = OpenSAMLUtils.buildResponse(user);
		String samlResponseString = OpenSAMLUtils.transSAMLObject2String(samlResponse);
		String encodedString = Base64.getEncoder().encodeToString(samlResponseString.getBytes());
		request.setAttribute("ACService", "https://agm5kinb9.accounts.sapcloud.cn/saml2/idp/acs/agm5kinb9.accounts.sapcloud.cn");
		request.setAttribute("SAMLResponse", encodedString);
		request.getRequestDispatcher("/idp_post_binding.jsp").forward(request, response);
		//response.getWriter().append("Served at: ").append(samlResponse.toString());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}
