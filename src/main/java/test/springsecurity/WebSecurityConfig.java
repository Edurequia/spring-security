package test.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
    @Configuration
    public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/").permitAll()
                                .requestMatchers(HttpMethod.POST, "/login").permitAll()
                                .requestMatchers("/managers").hasRole("MANAGERS")
                                .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS")
                                .anyRequest().authenticated()
                )
                .formLogin(withDefaults()); // Configuração de login padrão

        return http.build();
    }


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
