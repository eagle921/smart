<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ page session="false" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>登录页</title>
<link rel="shortcut icon" href="<%=request.getContextPath()%>/statics/img/favicon.ico" />
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/statics/css/public.css" />
<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/statics/css/page.css" />
<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/jquery.min.js"></script>
<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/public.js"></script>
<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/login.js"></script>
<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/base64.js"></script>

<style>
	/*验证码*/
    .img { width: 130px; height: 44px; float: right; _display: inline; cursor: pointer; margin-left: 20px; }
</style>
</head>
<body>

	<!-- 登录body -->
	<div class="logDiv">
		<div class="banner"><img class="logBanner" src="<%=request.getContextPath()%>/statics/img/logBanner.png" /></div>
		<div class="logGet">
			<!-- 头部提示信息 -->
			<div class="logD logDtip">
				<p class="p1">贵州省政企系统</p>
			</div>
			<form method="post" action="<c:url value="/login/submitcs.do"/>" onSubmit="return check(this);">
				<!-- 输入框 -->
				<div class="lgD">
					<img class="img1" src="<%=request.getContextPath()%>/statics/img/logName.png" />
					<input type="hidden" class="userName" name="userName"/>
					<input type="text" class="userName-txt" onblur="setUserName();" placeholder="输入用户名" />
				</div>
				<div class="lgD">
					<img class="img1" src="<%=request.getContextPath()%>/statics/img/logPwd.png" />
					<input type="hidden" class="passWord" name="passWord"/>
					<input type="password" class="passWord-txt" onblur="setPassWord();"  placeholder="输入用户密码" />
				</div>
				<div class="lgD reg-box">
					<input style="width: 150px;text-indent: 1rem;" class="photokey" name="loginCode" type="text" value="" placeholder="请输入验证码" />
					<img class="img" id="imgObj" alt="验证码" src="${pageContext.request.contextPath}/login/getCode.do" onclick="changeImg()">
					<!-- <span class="add phoKey"></span> -->
				</div>
				<div class="logC">
					<button >登录</button>
				</div> 
				<div id="login-error" style="color: #F00;margin-top:10px;text-align: center;">${error }</div>
			 </form>
		</div>
		<!-- 登录页面底部 -->
		<div class="logFoot">
			<p class="p1">中国移动通信集团贵州有限公司</p>
		</div>
		<!-- 登录页面底部end -->
	</div>
	<!-- 登录body  end -->

   
</body>
</html>
