package com.chequer.axboot.initialzr;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.WebApplicationInitializer;

@Configuration
public class AXBootInitialzrApplicationInitializer extends SpringBootServletInitializer implements WebApplicationInitializer {

    public static final Class<?>[] APPLICATION_SOURCES = new Class<?>[]{AXBootInitialzrApplication.class};

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        this.setRegisterErrorPageFilter(false);
        return application.sources(APPLICATION_SOURCES);
    }

    public static void main(String[] args) {
        SpringApplication.run(APPLICATION_SOURCES, args);
    }
}
