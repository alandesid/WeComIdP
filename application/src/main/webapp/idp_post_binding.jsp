<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Please wait for a moment...</title>
</head>
<body onload="document.login.submit()">
	<form name="login" method="post" action="<%=request.getAttribute("ACService")%>">
		<input type="hidden" name="SAMLResponse" value="<%=request.getAttribute("SAMLResponse")%>" /> 
		<input type="hidden" name="RelayState" value="" /> 
		<input type="submit" value="Submit" />
	</form>
</body>
</html>