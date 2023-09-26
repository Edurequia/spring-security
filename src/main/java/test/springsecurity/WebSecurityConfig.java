package test.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
    @Configuration
    public class WebSecurityConfig {

        @Bean
        public InMemoryUserDetailsManager userDetailsService(){
            UserDetails user = User.withUsername("user")
                    .password("{noop}user123")
                    .roles("USERS")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    .password("{noop}admin123")
                    .roles("MANAGERS")
                    .build();


            return new InMemoryUserDetailsManager(user, admin);
        }
    }
