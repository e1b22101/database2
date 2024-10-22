package team5.database2.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class Sample3AuthConfiguration {
  /**
   * 認可処理に関する設定（認証されたユーザがどこにアクセスできるか）
   *
   * @param http
   * @return
   * @throws Exception
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.formLogin(login -> login
        .permitAll())
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/")) // ログアウト後に / にリダイレクト
        .authorizeHttpRequests(authz -> authz
            .requestMatchers(AntPathRequestMatcher.antMatcher("/sample3/**"))
            .authenticated() // /sample3/以下は認証済みであること
            .requestMatchers(AntPathRequestMatcher.antMatcher("/sample4/**"))
            .authenticated() // /sample4/以下は認証済みであること
            .requestMatchers(AntPathRequestMatcher.antMatcher("/sample5/**"))
            .authenticated() // /sample4/以下は認証済みであること
            .requestMatchers(AntPathRequestMatcher.antMatcher("/sample58*"))
            .authenticated() // /sample4/以下は認証済みであること
            .requestMatchers(AntPathRequestMatcher.antMatcher("/**"))
            .permitAll())// 上記以外は全員アクセス可能
        .csrf(csrf -> csrf
            .ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/*")))// h2-console用にCSRF対策を無効化
        .headers(headers -> headers
            .frameOptions(frameOptions -> frameOptions
                .sameOrigin()));
    return http.build();
  }

  /**
   * 認証処理に関する設定（誰がどのようなロールでログインできるか）
   *
   * @return
   */
  @Bean
  public InMemoryUserDetailsManager userDetailsService() {

    // ユーザ名，パスワード，ロールを指定してbuildする
    // このときパスワードはBCryptでハッシュ化されているため，{bcrypt}とつける
    // ハッシュ化せずに平文でパスワードを指定する場合は{noop}をつける
    // user1/p@ss,user2/p@ss,admin/p@ss

    UserDetails user1 = User.withUsername("user1")
        .password("{bcrypt}$2y$10$ngxCDmuVK1TaGchiYQfJ1OAKkd64IH6skGsNw1sLabrTICOHPxC0e").roles("USER").build();
    UserDetails user2 = User.withUsername("user2")
        .password("{bcrypt}$2y$10$ngxCDmuVK1TaGchiYQfJ1OAKkd64IH6skGsNw1sLabrTICOHPxC0e").roles("USER").build();
    UserDetails admin = User.withUsername("admin")
        .password("{bcrypt}$2y$10$ngxCDmuVK1TaGchiYQfJ1OAKkd64IH6skGsNw1sLabrTICOHPxC0e").roles("ADMIN").build();
    // $ sshrun htpasswd -nbBC 10 customer1 p@ss
    UserDetails customer1 = User.withUsername("kouhei")
        .password("{bcrypt}$2y$05$OTHMZFLIBTVr0WNY3JTVsOPK3v3xwRBg0WP05oXMz84VwumewrBNO")
        .roles("CUSTOMER")
        .build();
    // $ sshrun htpasswd -nbBC 10 customer2 p@ss
    UserDetails customer2 = User.withUsername("akira")
        .password("{bcrypt}$2y$05$pZ/89n/pp0Jn35AdZF5gUuUZ4yObum376qvaRtn8WKYfXyOdODlF6")
        .roles("CUSTOMER")
        .build();
    // $ sshrun htpasswd -nbBC 10 seller p@ss
    UserDetails seller = User.withUsername("yuki")
        .password("{bcrypt}$2y$05$/52dtupZBqGVB7vEAxVvqeVV.AEEThBpl.WWtHXMliuiS5pfpmOF2")
        .roles("SELLER")
        .build();

    // 生成したユーザをImMemoryUserDetailsManagerに渡す（いくつでも良い）
    return new InMemoryUserDetailsManager(user1, user2, admin, customer1, customer2, seller);
  }

}
