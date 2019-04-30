package com.test.web2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.ComponentScan;

/**
 * 在客户端中要使用资源服务器的共享信息，可以使用 Spring Cloud Zuul 提供的一个路由服务来实现
 * @EnableZuulProxy 用来启用 Zuul 路由代理服务
 */
@SpringBootApplication
@EnableZuulProxy
@ComponentScan(basePackages = "com.test")
public class Web2Application {
    public static void main(String[] args) {
        SpringApplication.run(Web2Application.class, args);
    }
}
