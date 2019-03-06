<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<%@ page session="false" %>
<!DOCTYPE html>
<html>
	<head>
		<link rel="shortcut icon" href="<%=request.getContextPath()%>/statics/img/favicon.ico" />
		<meta charset="utf-8" />
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="initial-scale=1.0, user-scalable=no, width=device-width">
		<title>首页</title>
		<link rel="stylesheet" href="<%=request.getContextPath()%>/statics/js/layui/css/layui.css" />
		<link rel="stylesheet" href="<%=request.getContextPath()%>/statics/css/style.css" />
		<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/jquery-1.8.3.min.js"></script>
		<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/template.js"></script>
		<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/layui/layui.js"></script>
		<script type="text/javascript" src="<%=request.getContextPath()%>/statics/js/config.js"></script>
	</head>
	<body>
		<div class="container">
			
			<div class="header">
				<div class="display-table" style="width: 100%;">
					<div class="logo-box display-cell">
						<div class="logo"><img src="<%=request.getContextPath()%>/statics/img/gmcc-logo.png" width="120" height="38"></div>
					</div>
					<div class="display-cell login-status">
						<img class="user-logo" src="<%=request.getContextPath()%>/statics/img/user.png" />
						<a>${staffname }</a>
						<a href="<%=request.getContextPath()%>/logout">注销</a>	
					</div>
				</div>
				
				<!-- 头部显示框 -->
				<div class="menu-box display-table" style="width: 100%;">
					<div class="display-cell welcome">${staffname }&nbsp;&nbsp;&nbsp;欢迎您！</div>
					<ul class="display-cell menu">
						<li 
							<shiro:hasPermission name="ReservationOrderManagement">
								class="active"><a href="<%=request.getContextPath()%>/modules/order/orderManage.jsp?" target="iframePage">订单管理</a>
							</shiro:hasPermission>
							<shiro:lacksPermission name="ReservationOrderManagement">
								<shiro:hasPermission name="ReservationOrderQuery">
									class="active"><a href="<%=request.getContextPath()%>/modules/order/orderlist.jsp" target="iframePage">订单管理</a>
								</shiro:hasPermission>
								<shiro:lacksPermission name="ReservationOrderQuery">
									<shiro:hasPermission name="H5AccessLogQuery">
										class="active"><a href="<%=request.getContextPath()%>/modules/order/H5LogManagementList.jsp" target="iframePage">订单管理</a>
									</shiro:hasPermission>
									<shiro:lacksPermission name="H5AccessLogQuery">
										>
									</shiro:lacksPermission>
								</shiro:lacksPermission>
							</shiro:lacksPermission>
						</li>   
						
						<li <shiro:lacksPermission name="ReservationOrderManagement">
								<shiro:lacksPermission name="ReservationOrderQuery">  
									<shiro:lacksPermission name="H5AccessLogQuery"> 
										class="active"
									</shiro:lacksPermission>
								</shiro:lacksPermission>
							</shiro:lacksPermission>>
							
						    <shiro:hasPermission name="UserManagement">
								<a href="<%=request.getContextPath()%>/modules/system/userManagementList.jsp" target="iframePage">系统管理</a>
							</shiro:hasPermission>
							<shiro:lacksPermission name="UserManagement">
								<shiro:hasPermission name="AuthorityManagement">
							    	<a href="<%=request.getContextPath()%>/modules/system/authorityManagementList.jsp" target="iframePage">系统管理</a>
								</shiro:hasPermission>
								<shiro:lacksPermission name="AuthorityManagement">
									<shiro:hasPermission name="RoleManagement">
									    <a href="<%=request.getContextPath()%>/modules/system/roleManagementList.jsp" target="iframePage">系统管理</a>
									</shiro:hasPermission>
									<shiro:lacksPermission name="RoleManagement">
										<shiro:hasPermission name="SystemLog">
											<a href="<%=request.getContextPath()%>/modules/system/logManagementList.jsp" target="iframePage">系统管理</a>
										</shiro:hasPermission>
									</shiro:lacksPermission>
								</shiro:lacksPermission> 
							</shiro:lacksPermission> 	
						</li>
					</ul>
				</div>
			</div>
			
			<!-- 左边显示框 -->
			<div class="main-content">
				<div class="left-content">
				
				<div class="layout-slider
					<shiro:hasPermission name="ReservationOrderManagement"> 
						slider-active
					</shiro:hasPermission>
					<shiro:hasPermission name="ReservationOrderQuery"> 
						slider-active
					</shiro:hasPermission>
					<shiro:hasPermission name="H5AccessLogQuery"> 
						slider-active
					</shiro:hasPermission>">
						<ul>
							<shiro:hasPermission name="ReservationOrderManagement"> 
								<li class="menu-item menu-level-1 active">
									<a href="<%=request.getContextPath()%>/modules/order/orderManage.jsp" target="iframePage">预约订单管理</a>
								</li>
							</shiro:hasPermission>
							<shiro:hasPermission name="ReservationOrderQuery"> 
								<li class="menu-item menu-level-1 
									<shiro:lacksPermission name="ReservationOrderManagement">
										 active
									</shiro:lacksPermission>">
									<a href="<%=request.getContextPath()%>/modules/order/orderlist.jsp" target="iframePage">预约订单查询</a>
								</li>
							</shiro:hasPermission>
							<shiro:hasPermission name="H5AccessLogQuery"> 
								<li class="menu-item menu-level-1
									<shiro:lacksPermission name="ReservationOrderManagement">
										 <shiro:lacksPermission name="ReservationOrderQuery">
											 active
										 </shiro:lacksPermission>
									</shiro:lacksPermission>">
									<a href="<%=request.getContextPath()%>/modules/order/H5LogManagementList.jsp" target="iframePage">H5访问日志查询</a>
								</li>
							</shiro:hasPermission>
						</ul>
					</div>
					
					<div class="layout-slider
						<shiro:lacksPermission name="ReservationOrderManagement"> 
							slider-active
						</shiro:lacksPermission>
						<shiro:lacksPermission name="ReservationOrderQuery"> 
							slider-active
						</shiro:lacksPermission>
						<shiro:lacksPermission name="H5AccessLogQuery"> 
							slider-active
						</shiro:lacksPermission>">
						<ul>
						    <shiro:hasPermission name="UserManagement"> 
								<li class="menu-item menu-level-1 active">
									<a href="<%=request.getContextPath()%>/modules/system/userManagementList.jsp" target="iframePage">用户管理</a>
								</li>
							</shiro:hasPermission>
							<shiro:hasPermission name="AuthorityManagement"> 
								<li class="menu-item menu-level-1
									<shiro:lacksPermission name="UserManagement">
										active
									</shiro:lacksPermission>">
									<a href="<%=request.getContextPath()%>/modules/system/authorityManagementList.jsp" target="iframePage">权限管理</a>
								</li>
							</shiro:hasPermission>
							<shiro:hasPermission name="RoleManagement"> 
								<li class="menu-item menu-level-1
									<shiro:lacksPermission name="UserManagement">
										<shiro:lacksPermission name="AuthorityManagement">
											active
										</shiro:lacksPermission>
									</shiro:lacksPermission>">
									<a href="<%=request.getContextPath()%>/modules/system/roleManagementList.jsp" target="iframePage">角色管理</a>
								</li>
							</shiro:hasPermission>
							<shiro:hasPermission name="SystemLog"> 
								<li class="menu-item menu-level-1
									<shiro:lacksPermission name="UserManagement">
										<shiro:lacksPermission name="AuthorityManagement">
											<shiro:lacksPermission name="RoleManagement">
												active
											</shiro:lacksPermission>
										</shiro:lacksPermission>
									</shiro:lacksPermission>">
									<a href="<%=request.getContextPath()%>/modules/system/logManagementList.jsp" target="iframePage">系统日志</a>
								</li>
							</shiro:hasPermission>
						</ul>
					</div> 
				</div>
				
				<!-- 右边显示框 -->
				<div class="right_content">
					<shiro:hasPermission name="ReservationOrderManagement">
						<iframe src="<%=request.getContextPath()%>/modules/order/orderManage.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
					</shiro:hasPermission>
					<shiro:lacksPermission name="ReservationOrderManagement">
						<shiro:hasPermission name="ReservationOrderQuery">
						    <iframe src="<%=request.getContextPath()%>/modules/order/orderlist.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
						</shiro:hasPermission>
						<shiro:lacksPermission name="ReservationOrderQuery">
							<shiro:hasPermission name="H5AccessLogQuery">
								<iframe src="<%=request.getContextPath()%>/modules/order/H5LogManagementList.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
							</shiro:hasPermission>
							<shiro:lacksPermission name="H5AccessLogQuery">
								<shiro:hasPermission name="UserManagement">
									<iframe src="<%=request.getContextPath()%>/modules/system/userManagementList.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
								</shiro:hasPermission>
								<shiro:lacksPermission name="UserManagement">
								    <shiro:hasPermission name="AuthorityManagement">
									    <iframe src="<%=request.getContextPath()%>/modules/system/authorityManagementList.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
									</shiro:hasPermission>
									<shiro:lacksPermission name="AuthorityManagement">
										<shiro:hasPermission name="RoleManagement">
											<iframe src="<%=request.getContextPath()%>/modules/system/roleManagementList.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
										</shiro:hasPermission>
										<shiro:lacksPermission name="RoleManagement">
											<shiro:hasPermission name="SystemLog">
												<iframe src="<%=request.getContextPath()%>/modules/system/logManagementList.jsp" name="iframePage" id="iframePage" scrolling="no" onload="this.style.display='block';this.height=iframePage.document.body.scrollHeight+1;$('.copyright').show();" frameborder="no"></iframe>
											</shiro:hasPermission>
											<shiro:lacksPermission name="SystemLog">
												没权限,请联系管理员!
											</shiro:lacksPermission>
										</shiro:lacksPermission>
									</shiro:lacksPermission>
								</shiro:lacksPermission>
							</shiro:lacksPermission>
						</shiro:lacksPermission>
					</shiro:lacksPermission>
					<div class="copyright txt-align-c">
						中国移动通信集团贵州有限公司
					</div>
				</div>
			</div>
		</div>
	</body>
</html>


<script type="text/javascript">  
	$(document).ready(function() {
		// 样式控制
		$(".menu li").click(function() {
			//if(!$(this).hasClass("active")) {
				$(this).addClass("active").siblings().removeClass("active");
				var index = $(this).index();
				$(".layout-slider").eq(index).addClass("slider-active").siblings().removeClass("slider-active");
				$(".layout-slider").eq(index).find(".menu-item").eq(0).addClass("active").siblings().removeClass("active");
			//}
		});
	
		$(".menu-item").click(function() {
			var isactive = $(this).hasClass("active");
			if(!isactive) {
				$(this).addClass("active").siblings().removeClass("active");
			}
		});
	});
</script>
