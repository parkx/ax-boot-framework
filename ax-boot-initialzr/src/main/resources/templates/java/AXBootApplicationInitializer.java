package ${basePackage};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AXBootApplicationInitializer extends SpringBootServletInitializer {

    public static final Class<?>[] APPLICATION_SOURCES = new Class<?>[]{AXBootApplication.class};

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(APPLICATION_SOURCES);
    }

    public static void main(String[] args) {
        SpringApplication.run(APPLICATION_SOURCES, args);
    }
}
