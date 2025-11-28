# Sample nginx configuration with magic routing

As `nginx` is what I use and know, the following snippet of configuration can be used as a starting point for your own but it is not complete. Note that `location /rotproxy` is structured to support magic routing.

```
location /protected {
    error_page 401 403 404 500 502 503 504 = @fallback;

    auth_request /auth;
    
    proxy_pass http://localhost:8080/protected;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host $host;
    proxy_buffering off;
    proxy_ssl_verify off;
    proxy_intercept_errors on;
}

location /rotproxy {
    error_page 401 403 404 500 502 503 504 = @fallback;
    
    proxy_pass http://localhost:8000/rotproxy;
    proxy_intercept_errors on;
}

location = /auth {
    internal;
    deny all;
    allow 127.0.0.1;
    error_page 401 404 = @fallback;
    proxy_pass http://localhost:8000/rotproxy/auth;
}
```

With rotproxy configured like this:
```
ip = "127.0.0.1"
port = 8000
db_path = "/etc/rotproxy/users.json"
html_path = "/etc/rotproxy/index.html"
webroot_route = "rotproxy"
login_route = ""
auth_endpoint = "auth"
login_endpoint = "login"
login_redirect = "https://mydomain.com"
logout_endpoint = "logout"
logout_redirect = "https://mydomain.com"
trusted_proxies = ["127.0.0.1"]
magic_str = "mymagic"
magic_bytes = 32
magic_str_duration = "1h"
magic_str_char_range = "0:32"
rate_limit_max_user_attempts = 3
rate_limit_user_window = 1800
rate_limit_max_ip_attempts = 4
rate_limit_ip_window = 1800
rate_limit_bg_prune_job = 120
content_policy = "default-src 'self'; style-src 'self'; form-action 'self'; script-src 'self' 'sha256-xKOX32ceTgoNvySGOBePspULR2AmjzrMejHixwmcSgo='"
cookie_key = "some_key"
cookie_name = "rotproxy_session"
cookie_path = "/"
cookie_domain = "mydomain.com"
cookie_secure = true
session_ttl = 3600
session_abs_ttl = 28800
hash_mem_cost = 64
hash_time_cost = 3
hash_parallel_cost = 4
```

With this configuration `nginx` will check against `rotproxy` before it allows access to `/protected`. Note that it is not setup to redirect directly to the `rotproxy` login portal. Since magic routing is enabled in `rotproxy` (`magic_str` is `mymagic`), the expectation is that users know of this hidden protection and navigate to the login portal on their own. Once a user has logged in, access of `/protected` will be allowed. For more information on magic routing see [config documentation](config.md).


# Sample nginx configuration without magic routing, with login portal redirect

If you prefer to disable magic routing and present a normal login page instead, use the following snippet:

```
location /protected {
    auth_request /auth;
    error_page 401 =403 /rotproxy/;
        
    proxy_pass http://localhost:8080/protected;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host $host;
    proxy_buffering off;
    proxy_ssl_verify off;
    proxy_intercept_errors on;
}

location /rotproxy {
    error_page 401 403 404 500 502 503 504 = @fallback;
    
    proxy_pass http://localhost:8000/rotproxy;
    proxy_intercept_errors on;
}

location = /auth {
    internal;
    deny all;
    allow 127.0.0.1;
    error_page 401 404 = @fallback;
    proxy_pass http://localhost:8000/rotproxy/auth;
}
```

With rotproxy configured as:
```
ip = "127.0.0.1"
port = 8000
db_path = "/etc/rotproxy/users.json"
html_path = "/etc/rotproxy/index.html"
webroot_route = "rotproxy"
login_route = ""
auth_endpoint = "auth"
login_endpoint = "login"
login_redirect = "https://mydomain.com"
logout_endpoint = "logout"
logout_redirect = "https://mydomain.com"
trusted_proxies = ["127.0.0.1"]
magic_str = ""
magic_bytes = 32
magic_str_duration = "1h"
magic_str_char_range = "0:32"
rate_limit_max_user_attempts = 3
rate_limit_user_window = 1800
rate_limit_max_ip_attempts = 4
rate_limit_ip_window = 1800
rate_limit_bg_prune_job = 120
content_policy = "default-src 'self'; style-src 'self'; form-action 'self'; script-src 'self' 'sha256-xKOX32ceTgoNvySGOBePspULR2AmjzrMejHixwmcSgo='"
cookie_key = "some_key"
cookie_name = "rotproxy_session"
cookie_path = "/"
cookie_domain = "mydomain.com"
cookie_secure = true
session_ttl = 3600
session_abs_ttl = 28800
hash_mem_cost = 64
hash_time_cost = 3
hash_parallel_cost = 4
```