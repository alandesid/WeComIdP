<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Please wait for a moment...</title>
</head>
<body>
 <form method="post" action="https://sp.example.com/SAML2/SSO/POST" > 
 <input type="hidden" name="SAMLResponse" value="<%=request.getAttribute("SAMLResponse")%>" /> 
 <input type="hidden" name="RelayState" value="" />
 <input type="submit" value="Submit" /></form>
</body>
</html>