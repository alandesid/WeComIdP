<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://wwcdn.weixin.qq.com/node/wework/wwopen/js/wwLogin-1.2.4.js"></script>
<title>WeChat Login</title>
</head>
<body style="text-align:center;">
    <h1>你好！</h1>
    <p>请使用 <strong>企业微信</strong> 客户端进行扫码授权</p>
	<div id="qr_login"></div>
	<script>
	  	var url = 'https://wecomidp-impressive-cheetah-gc.cfapps.ap21.hana.ondemand.com/oauth2/client/WeComLoginDemo';
	  	var wwLogin = new WwLogin({
	      "id": "qr_login",
	      "appid": "ww8c0910bda01c1ec5",
	      "agentid": "1000002",
	      "redirect_uri": encodeURI(url),
	      "state": "btp",
	      "href": "",
	      "lang": "zh",
	});
	</script>
</body>
</html>