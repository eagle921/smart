package com.cmos.smart.auth.domain;

import com.cmos.mma.beans.User;
import com.cmos.mma.service.impl.ShiroUserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;


/**
 */
public class MyShiro extends AuthorizingRealm {

	@Autowired
	private ShiroUserService shiroUserService;

 
	/**
	 * 权限认证，获取登录用户的权限
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
		String loginName = (String) principalCollection.fromRealm(getName()).iterator().next();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		
		//根据用户name查询角色（tb_role），放入到Authorization里。
		Set<String> roles = shiroUserService.findRoleByName(loginName);
		info.setRoles(roles);

		//根据用户name查询权限（tb_permission），放入到Authorization里。
		Set<String> permissions = shiroUserService.findPermissionsByName(loginName);
		info.setStringPermissions(permissions);
		
		return info;
	}

	/**
	 * 登录认证，创建用户的登录信息
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
		// 判断用户登录状态
		User user = shiroUserService.findByName(token.getUsername());
		if (user != null) {
			// 保存用户登录信息到认证中
			return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
		}
		return null;
	}

}