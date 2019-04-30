package com.test.web1.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class MainsiteErrorController implements ErrorController {

    private static final String ERROR_PATH = "/error";

    @RequestMapping(value=ERROR_PATH)
    public String handleError(){
        return "403";
    }

    @Override
    public String getErrorPath() {
        // TODO Auto-generated method stub
        return ERROR_PATH;
    }

    @RequestMapping(value="/deny")
    public String handleDeny(){
        return "deny";
    }

    @RequestMapping("/tosignout")
    public String tosso() {
        return "tosignout";
    }

    /**
     * 使用一个重定向链接 "redirect:/#/"  来刷新当前访问页面，从而触发系统检查用户的授权状态，如果用户未被授权，则引导用户到登录认证服务器中登录
     * @return
     */
    @RequestMapping("/login")
    public String login() {
        return "redirect:/#/";
    }

    @RequestMapping("/")
    public String index(ModelMap model, Principal user) throws Exception{
        model.addAttribute("user", user);
        return "home";
    }

}
