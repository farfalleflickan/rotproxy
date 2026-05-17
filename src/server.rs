use super::{config, config::{TotpConf}, crypt, crypt::{rand_str}, user, utils::{SmartQueue, append_slash, prepend_slash, trim_slashes, trim_slash_end, constant_time_eq_str, sanitize_string, truncate_string, unix_timestamp, fatal_error}, handle_unwrap};

use actix_web::{cookie::{Key, SameSite}, http::header, middleware::{Logger, NormalizePath}, rt, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_session::{storage::CookieSessionStore, SessionMiddleware, config::SessionLifecycle};
use std::{env, io::Write, net::IpAddr, time::{Duration, Instant}, collections::HashMap};
use log::{debug, error, info, trace, warn};
use zeroize::Zeroizing;
use serde::Deserialize;
use dashmap::DashMap;
use url::Url;

struct RateLimiter {
    clients: DashMap<String, SmartQueue<Instant>>,
    ip_max_requests: usize,
    user_max_requests: usize,
    ip_window: Duration,
    user_window: Duration,
}

impl RateLimiter {
    fn record_failure(&self, key: &str, window: Duration, max: usize) -> usize {
        let now = Instant::now();
        let mut queue = self.clients.entry(key.to_string()).or_insert_with(|| SmartQueue::new(max));

        trace!("record_failure pre prune {} {}", key, queue.len());
        queue.prune(|&ts| now.duration_since(ts) > window);
        trace!("record_failure post prune {} {}", key, queue.len());
        queue.insert(now);
        trace!("record_failure post insrt {} {}", key, queue.len());
        queue.len()
    }

    fn clear_prefix(&self, prefix: &str) {
        self.clients.retain(|k, _| !k.starts_with(prefix))
    }

    pub fn record_ip_failure(&self, ip: &str) -> usize {
        let key = format!("ip:{}", ip);
        self.record_failure(&key, self.ip_window, self.ip_max_requests)
    }

    pub fn record_user_failure(&self, user: &str, ip: &str) -> usize {
        let key = format!("user:{}:{}", user, ip);
        self.record_failure(&key, self.user_window, self.user_max_requests)
    }

    fn get_failures(&self, key: &str) -> usize {
        if let Some(mut queue) = self.clients.get_mut(key) {
            let now = Instant::now();
            let window = if key.starts_with("ip:") {
                self.ip_window
            } else {
                self.user_window
            };
            trace!("get_failures pre prune {} {}", key, queue.len());
            queue.prune(|&ts| now.duration_since(ts) > window);
            trace!("get_failures post prune {} {}", key, queue.len());
            if queue.is_empty() {
                drop(queue);
                self.clients.remove(key);
                return 0;
            }
            queue.len()
        } else {
            0
        }
    }

    pub fn get_ip_failures(&self, ip: &str) -> usize {
        let key = format!("ip:{}", ip);
        self.get_failures(&key)
    }

    pub fn get_user_failures(&self, user: &str, ip: &str) -> usize {
        let key = format!("user:{}:{}", user, ip);
        self.get_failures(&key)
    }

    pub fn clear_user(&self, user: &str, ip: &str) {
        self.clients.remove(&format!("user:{}:{}", user, ip));
    }
    
    #[allow(dead_code)]
    pub fn clear_ip(&self, ip: &str) {
        let prefix = format!("ip:{}", ip);
        self.clear_prefix(&prefix);
    }
}

#[derive(Deserialize)]
struct LoginForm {
    user: String,
    password: String,
    totp: String,
    csrf_token: String
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf_token: String
}

struct DummyCrypto {
    password: String,
    totp: String
}

struct HtmlIndexContent(pub String);
struct HtmlLogoutContent(pub String);
struct CssContent(pub String);
struct CssRoute(pub String);

fn check_relative_redirect(redirect: &str) -> bool {
    if redirect.is_empty() || redirect.len() > 2048 || !redirect.starts_with('/') || redirect.starts_with("//") {
        return false;
    }
        
    let baseurl = match Url::parse("https://localhost") {
        Ok(u) => u,
        Err(_) => return false,
    };
    
    let parsed = match baseurl.join(redirect) {
        Ok(u) => u,
        Err(_) => return false,
    };
    
    if parsed.scheme() != "https" || parsed.host_str() != Some("localhost") {
        return false;
    }
    
    let path = parsed.path();
    
    if path.contains('\\') || path.contains("/../") || path.ends_with("/..") {
        return false;
    }
    
    true
}

fn check_allowed_domain(redirect: &str, allowed_domains: &[String], allow_http: bool) -> bool {
    let parsed_url = match Url::parse(redirect) {
        Ok(url) => url,
        Err(_) => return false,
    };
    
    if parsed_url.scheme() != "https" && !(allow_http && parsed_url.scheme() == "http") {
        return false;
    }

    if parsed_url.port().is_some() {
        return false;
    }
    
    let host = match parsed_url.host_str() {
        Some(h) => h,
        None => return false,
    };
    
    for domain in allowed_domains {
        if host.eq_ignore_ascii_case(domain) {
            return true;
        }
    }
    
    false
}

pub fn check_redirect(redirect: &str, allowed_domains: &[String], allow_http: bool) -> bool {
    
    if redirect.starts_with('/') {
       return check_relative_redirect(redirect) 
    }

    if !allowed_domains.is_empty() {
        return check_allowed_domain(redirect, allowed_domains, allow_http);
    }

    false
}

fn is_session_expired(session: &actix_session::Session, tag: &str, ttl: i64) -> bool {
    if let Some(time) = session.get::<i64>(tag).unwrap_or(None) {
        unix_timestamp() - time > ttl
    } else {
        true
    }
}

fn is_totp_used(conf: &TotpConf, key: &str, data: &DashMap<String, Instant>) -> bool {
    use dashmap::mapref::entry::Entry;
    let now = Instant::now();
    match data.entry(key.to_string()) {
        Entry::Vacant(e) => { e.insert(now); false }
        Entry::Occupied(e) => {
            let time = conf.step * (2 * conf.skew as u64 + 1);
            if (now - *e.get()) > Duration::from_secs(time) {
                *e.into_ref() = now;
                return false;
            }

            true
        }
    }
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _    => out.push(c),
        }
    }
    out
}

async fn index_css(css: web::Data<CssContent>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(css.get_ref().0.clone())
}

async fn login_page(req: HttpRequest, magic_path: Option<web::Path<String>>, html: web::Data<HtmlIndexContent>, css_path: web::Data<CssRoute>, session: actix_session::Session, conf: web::Data<config::Config>) -> impl Responder {
    let magic = magic_path.unwrap_or(web::Path::from("".to_string()));

    if !conf.magic_str.is_empty() && !constant_time_eq_str(magic.as_str(), &crypt::magic_hash(&conf.magic_str, conf.magic_bytes, conf.magic_duration, conf.magic_range.clone())) {
        return HttpResponse::NotFound().body("");
    }
    
    let web_path;
    if req.uri().path().contains("index.html") {
        web_path = req.uri().path().replace("index.html", "");
    } else {
        web_path = req.uri().path().to_string();
    }
    let login_endpoint;

    if !conf.login_route.is_empty() {
        login_endpoint = web_path.replacen(&conf.login_route, "", 1) + &trim_slashes(&conf.login_endpoint);
    } else {
        login_endpoint = append_slash(&web_path) + &trim_slashes(&conf.login_endpoint);
    }
    
    match web::Query::<HashMap<String, String>>::from_query(req.query_string()) {
        Ok(query) => {
            if let Some(redirect_value) = query.get("redirect") {
                if check_redirect(redirect_value, &conf.redirect_domains, conf.allow_http_redirect) {
                    let _ = session.insert("login_redirect", redirect_value);
                    debug!("Parsed login_redirect from login page query: {}", sanitize_string(redirect_value));
                } else {
                    warn!("Ignored unsafe redirect: {}", sanitize_string(redirect_value));
                }
            }
        }
        Err(e) => {
            debug!("Failed to parse login page query: {}", e);
        }
    }

    let csrf_token: String = match session.get::<String>("csrf_token").unwrap_or(None) {
        Some(token) => token,
        None => {
            let token = crypt::rand_str(64);
            let _ = session.insert("csrf_token", &token);
            token
        }
    };

    let html_with_csrf = html.get_ref().0.replace("{CSRF_TOKEN_TEMPLATE}", &csrf_token).replace("{INDEX_CSS_WEBPATH}", css_path.get_ref().0.as_str()).replace("{LOGIN_ENDPOINT}", &html_escape(&login_endpoint)).replace("{ERROR_HTML}", "");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .insert_header(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
        .body(html_with_csrf)
}

async fn logout_page(req: HttpRequest, magic_path: Option<web::Path<String>>, html: web::Data<HtmlLogoutContent>, css_route: web::Data<CssRoute>, session: actix_session::Session, conf: web::Data<config::Config>) -> impl Responder {
    let magic = magic_path.unwrap_or(web::Path::from("".to_string()));

    if !conf.magic_str.is_empty() && !constant_time_eq_str(magic.as_str(), &crypt::magic_hash(&conf.magic_str, conf.magic_bytes, conf.magic_duration, conf.magic_range.clone())) {
        return HttpResponse::NotFound().body("");
    }
    
    let expired_session = conf.session_abs_ttl > 0 && is_session_expired(&session, "start", conf.session_abs_ttl);

    if expired_session {
        session.purge();

        match web::Query::<HashMap<String, String>>::from_query(req.query_string()) {
            Ok(query) => {
                if let Some(redirect_value) = query.get("redirect") {
                    if check_redirect(redirect_value, &conf.redirect_domains, conf.allow_http_redirect) {
                        return HttpResponse::SeeOther().insert_header((header::LOCATION, redirect_value.clone())).finish();
                    }
                }
            }
            Err(_) => {}
        }

        if conf.logout_redirect.is_empty() {
            return HttpResponse::Ok().body("Logged out");
        }

        return HttpResponse::SeeOther().insert_header((header::LOCATION, conf.logout_redirect.clone())).finish()
    }

    let web_path = req.uri().path().to_string();
    let css_path = css_route.get_ref().0.as_str();
    
    match web::Query::<HashMap<String, String>>::from_query(req.query_string()) {
        Ok(query) => {
            if let Some(redirect_value) = query.get("redirect") {
                if check_redirect(redirect_value, &conf.redirect_domains, conf.allow_http_redirect) {
                    let _ = session.insert("logout_redirect", redirect_value);
                    debug!("Parsed logout_redirect from logout page query: {}", sanitize_string(redirect_value));
                } else {
                    warn!("Ignored unsafe redirect: {}", sanitize_string(redirect_value));
                }
            }
        }
        Err(e) => {
            debug!("Failed to parse logout page query: {}", e);
        }
    }

    let csrf_token: String = match session.get::<String>("csrf_token").unwrap_or(None) {
        Some(token) => token,
        None => {
            let token = crypt::rand_str(64);
            let _ = session.insert("csrf_token", &token);
            token
        }
    };

    let html_with_csrf = html.get_ref().0.replace("{CSRF_TOKEN_TEMPLATE}", &csrf_token).replace("{INDEX_CSS_WEBPATH}", css_path).replace("{LOGOUT_ENDPOINT}", &html_escape(&web_path)).replace("{ERROR_HTML}", "");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .insert_header(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
        .body(html_with_csrf)
}

fn get_client_ip(conf: &config::Config, req: &HttpRequest) -> Option<IpAddr> {
    let peer_ip = req.peer_addr().map(|sock| sock.ip())?;

    if conf.trusted_proxies.contains(&peer_ip) {
        if let Some(xff) = req.headers().get(header::X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
            for ip in xff.split(',').map(str::trim).filter_map(|s| s.parse::<IpAddr>().ok()).rev() {
                if !conf.trusted_proxies.contains(&ip) {
                    return Some(ip);
                }
            }
        }

        if let Some(fwd) = req.headers().get(header::FORWARDED).and_then(|v| v.to_str().ok()) {
            for entry in fwd.split(',').rev() {
                for param in entry.trim().split(';') {
                    if let Some(val) = param.trim().to_lowercase().strip_prefix("for=") {
                        // strip optional quotes
                        let raw = val.trim_matches('"');
                        let ip_str = if raw.starts_with('[') {
                            //ipv6: addr between [ ], ignore port
                            raw.trim_start_matches('[').split(']').next().unwrap_or("")
                        } else {
                            // ipv4, drop port
                            raw.split(':').next().unwrap_or(raw)
                        };

                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            if !conf.trusted_proxies.contains(&ip) {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    if conf.trusted_proxies.is_empty() {
        return Some(peer_ip);
    }

    None
}

async fn login(req: HttpRequest, magic_path: Option<web::Path<String>>, data: web::Data<DashMap<String, user::User>>, totp_data: web::Data<DashMap<String, Instant>>, form: web::Form<LoginForm>, session: actix_session::Session, rate_limiter: web::Data<RateLimiter>, conf: web::Data<config::Config>, html: web::Data<HtmlIndexContent>, css_path: web::Data<CssRoute>, dummy_crypto: web::Data<DummyCrypto>) -> impl Responder {
    let magic = magic_path.unwrap_or(web::Path::from("".to_string()));

    if !conf.magic_str.is_empty() && !constant_time_eq_str(magic.as_str(), &crypt::magic_hash(&conf.magic_str, conf.magic_bytes, conf.magic_duration, conf.magic_range.clone())) {
        return HttpResponse::NotFound().body("");
    }
    
    let web_path = req.uri().path();
    
    let session_token: String = session.get("csrf_token").ok().flatten().unwrap_or_default();
    session.remove("csrf_token");

    let csrf_token = crypt::rand_str(64);

    let html_with_csrf = html.get_ref().0.replace("{CSRF_TOKEN_TEMPLATE}", &csrf_token).replace("{INDEX_CSS_WEBPATH}", css_path.get_ref().0.as_str()).replace("{LOGIN_ENDPOINT}", &html_escape(&web_path));
    let invalid_html = html_with_csrf.replace("{ERROR_HTML}", "<div class=\"error\">Invalid credentials</div>");
    
    let login_failed = HttpResponse::Unauthorized()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .insert_header(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
        .body(invalid_html);

    let session_success = if session_token.is_empty() || form.csrf_token.is_empty() {
            false
        } else { 
            constant_time_eq_str(&session_token, &form.csrf_token)
        };
    let _ = session.insert("csrf_token", &csrf_token);

    if let Some(ip_addr) = get_client_ip(&conf, &req) {
        let ip = ip_addr.to_string();
        let req_user_agent = req.headers().get(header::USER_AGENT).and_then(|s| s.to_str().ok()).unwrap_or("");
        let req_referer = req.headers().get(header::REFERER).and_then(|s| s.to_str().ok()).unwrap_or("");
        let username = Zeroizing::new(form.user.to_string());
        let password = Zeroizing::new(truncate_string(&form.password, conf.max_password_length).to_string());
        let totp     = Zeroizing::new(form.totp.trim().to_string());

        let mut user_fails = 0;
        let mut ip_fails = rate_limiter.get_ip_failures(&ip);

        if ip_fails >= rate_limiter.ip_max_requests {
            let millis = crypt::rand_between(1000, 2500);
            rt::time::sleep(Duration::from_millis(millis)).await;
            debug!("Authentication limited \"{}\" (ip: {}/{}) - \"{}\" \"{}\" \"{}\"", 
                sanitize_string(username.as_str()), 
                ip_fails, rate_limiter.ip_max_requests,ip, 
                sanitize_string(req_user_agent), sanitize_string(req_referer)
            );
            return login_failed
        }

        if session_success {
            user_fails = if conf.rate_limit_user_globally {
                    rate_limiter.get_user_failures(&username, "")
                } else {
                    rate_limiter.get_user_failures(&username, &ip)
                };
            if user_fails >= rate_limiter.user_max_requests {
                rate_limiter.record_ip_failure(&ip);
                let millis = crypt::rand_between(1000, 2500);
                rt::time::sleep(Duration::from_millis(millis)).await;
                debug!("Authentication limited \"{}\" (user: {}/{} ip: {}/{}) - \"{}\" \"{}\" \"{}\"", 
                    sanitize_string(username.as_str()), 
                    user_fails, rate_limiter.user_max_requests, 
                    ip_fails, rate_limiter.ip_max_requests,ip, 
                    sanitize_string(req_user_agent), sanitize_string(req_referer)
                );
                return login_failed
            }

            if user::validate_username(&username) {
                if let Some(user) = data.get(username.as_str()) {
                    let stored_pw   = Zeroizing::new(user.password.clone());
                    let stored_totp = Zeroizing::new(user.totp.clone());
                    drop(user);

                    let conf_copy = conf.clone();
                    let username_copy = username.clone();
                    let is_valid: bool = web::block(move || { 
                        let pwd_ok = crypt::verify_password(&conf_copy, &stored_pw, &password);
                        let pwd_salt = crypt::get_hash_salt(&stored_pw).unwrap_or_default();
                        let dec_totp = match crypt::kdf_decrypt(&conf_copy, &stored_totp, &password, &pwd_salt) {
                            Ok(val) => val,
                            Err(e) => {
                                warn!("Failed kdf_decrypt for user {}: {:?}", sanitize_string(username_copy.as_str()), e);
                                Zeroizing::new(String::default())
                            }
                        };

                        let totp_ok = crypt::check_totp(&conf_copy.totp_conf, &dec_totp, &totp);
                        let totp_used = pwd_ok && totp_ok && is_totp_used(&conf_copy.totp_conf, &format!("{}:{}", username_copy.as_str(), &totp.as_str()), &totp_data);
                        return pwd_ok && totp_ok && !totp_used;
                    }).await.unwrap_or(false);

                    if is_valid {
                        if conf.rate_limit_user_globally {
                            rate_limiter.clear_user(&username, "");
                        } else {
                            rate_limiter.clear_user(&username, &ip);
                        }
                        session.renew();
                        if session.insert("user", username.as_str()).is_ok() {
                            info!("Authenticated \"{}\" - \"{}\" \"{}\" \"{}\"", sanitize_string(username.as_str()), ip, sanitize_string(req_user_agent), sanitize_string(req_referer));
                            session.insert("start", unix_timestamp()).ok();
                            session.insert("activity", unix_timestamp()).ok();

                            if let Ok(Some(redirect)) = session.get::<String>("login_redirect") {
                                if !redirect.is_empty() {
                                    if check_redirect(&redirect, &conf.redirect_domains, conf.allow_http_redirect) {
                                        let _ = session.remove("login_redirect");
                                        return HttpResponse::SeeOther().insert_header((header::LOCATION, redirect)).finish();
                                    } else {
                                        warn!("Ignored unsafe stored redirect for user {}: {}", sanitize_string(username.as_str()), sanitize_string(&redirect));
                                    }
                                }
                            }
                            
                            if conf.login_redirect.is_empty() {
                                return HttpResponse::Ok().body("Authenticated");
                            }

                            return HttpResponse::SeeOther().insert_header((header::LOCATION, conf.login_redirect.clone())).finish();
                        }
                    } else {
                        user_fails = if conf.rate_limit_user_globally { 
                                rate_limiter.record_user_failure(&username, "")
                            } else {
                                rate_limiter.record_user_failure(&username, &ip)
                            };
                    }
                } else {
                    let conf_copy = conf.clone();
                    web::block(move || {
                        crypt::verify_password(&conf_copy, &dummy_crypto.password, &password);
                        let dummy_salt = crypt::get_hash_salt(&dummy_crypto.password).unwrap_or_default();
                        let dec_totp = crypt::kdf_decrypt(&conf_copy, &dummy_crypto.totp, &password, &dummy_salt).unwrap_or_default();
                        crypt::check_totp(&conf_copy.totp_conf, &dec_totp,&totp);
                    }).await.ok();
                    user_fails = if conf.rate_limit_user_globally { 
                        rate_limiter.record_user_failure(&username, "")
                    } else {
                        rate_limiter.record_user_failure(&username, &ip)
                    };
                }
            } else {
                let conf_copy = conf.clone();
                web::block(move || {
                    crypt::verify_password(&conf_copy, &dummy_crypto.password, &password);
                    let dummy_salt = crypt::get_hash_salt(&dummy_crypto.password).unwrap_or_default();
                    let dec_totp = crypt::kdf_decrypt(&conf_copy, &dummy_crypto.totp, &password, &dummy_salt).unwrap_or_default();
                    crypt::check_totp(&conf_copy.totp_conf, &dec_totp,&totp);
                }).await.ok();
                user_fails = if conf.rate_limit_user_globally { 
                        rate_limiter.record_user_failure(&username, "")
                    } else {
                        rate_limiter.record_user_failure(&username, &ip)
                    };
            }
        } else {
            ip_fails = rate_limiter.record_ip_failure(&ip);
            warn!("Invalid session \"{}\" (ip ban: {}/{}) - \"{}\" \"{}\" \"{}\"", 
                sanitize_string(&form.csrf_token), 
                ip_fails, rate_limiter.ip_max_requests, 
                ip, sanitize_string(req_user_agent), sanitize_string(req_referer)
            );

            let delay = std::cmp::min(std::cmp::max(user_fails, ip_fails) as u64, 5) as u64;
            let millis = crypt::rand_between(260, 990);
            rt::time::sleep(Duration::from_secs(std::cmp::max(1, delay)) + Duration::from_millis(millis)).await;
            return login_failed;
        }

        ip_fails = rate_limiter.record_ip_failure(&ip);

        warn!("Authentication failed \"{}\" (user: {}/{} ip: {}/{}) - \"{}\" \"{}\" \"{}\"", 
            sanitize_string(username.as_str()),
            user_fails, rate_limiter.user_max_requests, 
            ip_fails, rate_limiter.ip_max_requests,ip, 
            sanitize_string(req_user_agent), sanitize_string(req_referer)
        );

        let delay = std::cmp::min(std::cmp::max(user_fails, ip_fails) as u64, 5) as u64;
        let millis = crypt::rand_between(10, 500);
        rt::time::sleep(Duration::from_secs(std::cmp::max(1, delay)) + Duration::from_millis(millis)).await;

        if ip_fails >= rate_limiter.ip_max_requests {
            return login_failed
        }
        if user_fails >= rate_limiter.user_max_requests {
            return login_failed
        }
    } else {
        error!("Failed parsing ip in req: {:#?}", req);
    }
    login_failed
}

async fn auth(session: actix_session::Session, conf: web::Data<config::Config>) -> impl Responder {
    if conf.session_abs_ttl > 0 && is_session_expired(&session, "start", conf.session_abs_ttl) {
        session.purge();
    } else if let Some(_user) = session.get::<String>("user").unwrap_or(None) {
        if !is_session_expired(&session, "activity", conf.session_ttl) {
            session.insert("activity", unix_timestamp()).ok();
            return HttpResponse::Ok()
                .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
                .insert_header(("X-Frame-Options", "DENY"))
                .insert_header(("X-Content-Type-Options", "nosniff"))
                .insert_header(("Referrer-Policy", "no-referrer"))
                .insert_header(("Cache-Control", "no-store"))
                .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
                .insert_header(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
                .finish();
        }
    }

    session.purge();
    HttpResponse::Unauthorized()
        .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .insert_header(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
        .finish()
}

async fn logout(req: HttpRequest, magic_path: Option<web::Path<String>>, form: web::Form<LogoutForm>, session: actix_session::Session, conf: web::Data<config::Config>, html: web::Data<HtmlLogoutContent>, css_path: web::Data<CssRoute>) -> impl Responder {
    let magic = magic_path.unwrap_or(web::Path::from("".to_string()));

    if !conf.magic_str.is_empty() && !constant_time_eq_str(magic.as_str(), &crypt::magic_hash(&conf.magic_str, conf.magic_bytes, conf.magic_duration, conf.magic_range.clone())) {
        return HttpResponse::NotFound().body("");
    }

    let expired_session = conf.session_abs_ttl > 0 && is_session_expired(&session, "start", conf.session_abs_ttl);

    if expired_session {
        let redirect: String = session.get("logout_redirect").ok().flatten().unwrap_or_default();
        session.purge();

        if !redirect.is_empty() {
            if check_redirect(&redirect, &conf.redirect_domains, conf.allow_http_redirect) {
                return HttpResponse::SeeOther().insert_header((header::LOCATION, redirect.clone())).finish();
            }
        }

        if conf.logout_redirect.is_empty() {
            return HttpResponse::Ok().body("Logged out");
        }

        return HttpResponse::SeeOther().insert_header((header::LOCATION, conf.logout_redirect.clone())).finish()
    }

    let web_path = req.uri().path().to_string();
    let session_token: String = session.get("csrf_token").ok().flatten().unwrap_or_default();
    let session_success = if session_token.is_empty() || form.csrf_token.is_empty() {
            false
        } else { 
            constant_time_eq_str(&session_token, &form.csrf_token)
        };

    let csrf_token = crypt::rand_str(64);

    let html_with_csrf = html.get_ref().0.replace("{CSRF_TOKEN_TEMPLATE}", &csrf_token).replace("{INDEX_CSS_WEBPATH}", css_path.get_ref().0.as_str()).replace("{LOGOUT_ENDPOINT}", &html_escape(&web_path));
    let invalid_html = html_with_csrf.replace("{ERROR_HTML}", "<div class=\"error\">Failed!</div>");

    let logout_failed = HttpResponse::Unauthorized()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .insert_header(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
        .body(invalid_html);

    let username: String = session.get("user").ok().flatten().unwrap_or_default();
    let redirect: String = session.get("logout_redirect").ok().flatten().unwrap_or_default();

    if !session_success || username.is_empty() {
        let _ = session.insert("csrf_token", &csrf_token);
        return logout_failed;
    }
    
    if let Some(ip_addr) = get_client_ip(&conf, &req) {
        let ip = ip_addr.to_string();
        let req_user_agent = req.headers().get(header::USER_AGENT).and_then(|s| s.to_str().ok()).unwrap_or("");
        let req_referer = req.headers().get(header::REFERER).and_then(|s| s.to_str().ok()).unwrap_or("");

        info!("Logging out \"{}\" - \"{}\" \"{}\" \"{}\"", sanitize_string(username.as_str()), ip, sanitize_string(req_user_agent), sanitize_string(req_referer));
    } else {
        error!("Failed parsing ip in req: {:#?}", req);
        info!("Logging out \"{}\"", sanitize_string(username.as_str()));
    }

    session.purge();

    if !redirect.is_empty() {
        if check_redirect(&redirect, &conf.redirect_domains, conf.allow_http_redirect) {
            return HttpResponse::SeeOther().insert_header((header::LOCATION, redirect)).finish();
        } else {
            warn!("Ignored unsafe stored logout redirect for user {}: {}", sanitize_string(username.as_str()), sanitize_string(&redirect));
        }
    }

    if conf.logout_redirect.is_empty() {
        return HttpResponse::Ok().body("Logged out");
    }

    return HttpResponse::SeeOther().insert_header((header::LOCATION, conf.logout_redirect.clone())).finish()
}

#[actix_web::main]
pub async fn start_server(conf: config::Config) {
    let interface = conf.ip.as_str();
    let port = conf.port;

    let webroot = prepend_slash(&trim_slashes(&conf.webroot_route));
    let webroot_subpath = append_slash(&webroot);
    
    let magic_path;
    if !conf.magic_str.is_empty() {
        magic_path = append_slash("{magicToken}");
    } else {
        magic_path = "".to_string();
    }

    let login_subpath = format!("{}{}{}", webroot_subpath, magic_path, trim_slashes(&conf.login_route));
    let index_html_path = format!("{}index.html", append_slash(&login_subpath));
    let index_css_path  = format!("{}index.css", append_slash(&login_subpath));
    let auth_ep         = format!("{}{}", webroot_subpath, trim_slashes(&conf.auth_endpoint));
    let login_ep        = format!("{}{}{}", webroot_subpath, magic_path, trim_slashes(&conf.login_endpoint));
    let logout_ep       = format!("{}{}{}", webroot_subpath, magic_path, trim_slashes(&conf.logout_endpoint));

    let rate_limiter = web::Data::new(RateLimiter {
        clients: DashMap::new(),
        user_window: Duration::from_secs(conf.rate_limit_user_window),
        user_max_requests: conf.rate_limit_max_user_attempts,
        ip_window: Duration::from_secs(conf.rate_limit_ip_window),
        ip_max_requests: conf.rate_limit_max_ip_attempts
    });

    let conf_data = web::Data::new(conf.clone());

    let users_map = handle_unwrap!(user::read_user_db(&conf.db_path));
    let users_map_empty = users_map.is_empty();
    let users_dashmap: DashMap<String, user::User> = users_map.into_iter().collect();
    let map_data = web::Data::new(users_dashmap);
    let totp_dashmap: DashMap<String, Instant> = DashMap::default();
    let totp_data = web::Data::new(totp_dashmap);

    let index_html_file = handle_unwrap!(std::fs::read_to_string(conf.html_path.join("index.html")));
    let index_html_data = web::Data::new(HtmlIndexContent(index_html_file));
    let logout_html_file = handle_unwrap!(std::fs::read_to_string(conf.html_path.join("logout.html")));
    let logout_html_data = web::Data::new(HtmlLogoutContent(logout_html_file));
    let css_file = handle_unwrap!(std::fs::read_to_string(conf.html_path.join("index.css")));
    let css_data = web::Data::new(CssContent(css_file));
    let css_route = web::Data::new(CssRoute(index_css_path.clone()));

    let secret_key = Key::from(conf.cookie_key.as_bytes());
    let session_ttl = conf.session_ttl;

    let mut logger = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

    if env::var("RUST_LOG").is_err() { //NO RUST_LOG
        logger
            .filter_module("actix_server", log::LevelFilter::Off)
            .filter_module("actix_web", log::LevelFilter::Off)
            .filter_module("actix_web::middleware::logger", log::LevelFilter::Info);
    }

    logger.format(|buf, record| {
        let style = buf.default_level_style(record.level());

        writeln!(
            buf,
            "[{} {style}{}{style:#} rotproxy] {}",
            buf.timestamp(),
            record.level(),
            record.args()
        )}
    ).init();

    //precompute dummy crypto
    let dummy_crypto: DummyCrypto;
    {
        let pwd  = rand_str(32);
        let hash = handle_unwrap!(crypt::hash_password(&conf, &pwd));
        let salt = crypt::get_hash_salt(&hash);
        
        if salt.is_err() {
            fatal_error(&format!("Failed getting dummy salt while parsing dummy hash: {}", hash), salt.as_ref().err());
        }

        let salt = salt.unwrap();
        let secret = crypt::new_secret();
        let totp = crypt::kdf_encrypt(&conf, &secret, &pwd, &salt);

        if totp.is_err() {
            fatal_error(&format!("Error while kdf encrypting dummy TOTP: {}", secret), totp.as_ref().err());
        }

        let totp = totp.unwrap();

        dummy_crypto = DummyCrypto {
            password: hash,
            totp,
        };
    }

    let dummy_crypto_data = web::Data::new(dummy_crypto);

    info!("Starting rotproxy on {}:{}{}", interface, port, webroot);

    if users_map_empty {
        warn!("Starting server with empty user database!");
    }

    let totp_data_copy = totp_data.clone();
    let totp_time = conf.totp_conf.step * (2 * conf.totp_conf.skew as u64 + 1);

    rt::spawn(async move {
        let mut ticker = rt::time::interval(Duration::from_secs(totp_time/2));
        loop {
            ticker.tick().await;

            totp_data_copy.retain(|_, time| { time.elapsed() < Duration::from_secs(totp_time) });
        }
    });

    if conf.rate_limit_bg_prune_job >= 20 {
        let rl = rate_limiter.clone();
        rt::spawn(async move {
            let mut ticker = rt::time::interval(Duration::from_secs(conf.rate_limit_bg_prune_job));
            loop {
                ticker.tick().await;

                let now = Instant::now();
                rl.clients.retain(|key, queue| {
                    let window = if key.starts_with("ip:") {
                        rl.ip_window
                    } else {
                        rl.user_window
                    };
                
                    trace!("rate_limit_bg_prune_job pre prune {} {}", key, queue.len());
                    queue.prune(|&ts| now.duration_since(ts) > window);
                    trace!("rate_limit_bg_prune_job post prune {} {}", key, queue.len());
                    !queue.is_empty()
                });
            }
        });
    } else if conf.rate_limit_bg_prune_job > 0 {
        warn!("Rate limiting background job timer set to {} which is too low, should be >= 20s or 0 for off", conf.rate_limit_bg_prune_job);
    }

    HttpServer::new(move || {
        let session_conf = if session_ttl > 0 {
            SessionLifecycle::PersistentSession(actix_session::config::PersistentSession::default().session_ttl(actix_web::cookie::time::Duration::seconds(session_ttl)))
        } else {
            SessionLifecycle::BrowserSession(actix_session::config::BrowserSession::default())
        };

        App::new()
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(conf.cookie_secure)
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Strict)
                    .cookie_name(conf.cookie_name.clone())
                    .cookie_path(conf.cookie_path.clone())
                    .cookie_domain(if conf.cookie_domain.is_empty() { None } else { Some(conf.cookie_domain.clone()) })
                    .session_lifecycle(session_conf)
                    .build(),
            )
            .wrap(NormalizePath::trim())
            .app_data(map_data.clone())
            .app_data(totp_data.clone())
            .app_data(rate_limiter.clone())
            .app_data(index_html_data.clone())
            .app_data(logout_html_data.clone())
            .app_data(css_route.clone())
            .app_data(css_data.clone())
            .app_data(conf_data.clone())
            .app_data(dummy_crypto_data.clone())
            .app_data(web::FormConfig::default().limit(1024))
            .route(&auth_ep, web::get().to(auth)) //HAS to be here before wildcards in case magic_str is set...
            .route(&trim_slash_end(&login_subpath), web::get().to(login_page))
            .route(&index_html_path, web::get().to(login_page))
            .route(&index_css_path, web::get().to(index_css))
            .route(&logout_ep, web::get().to(logout_page))
            .route(&logout_ep, web::post().to(logout))
            .route(&login_ep, web::post().to(login))
    })
    .bind((interface, port))
    .unwrap_or_else(|err| {
        error!("Failed to bind server to {}:{} - {}", interface, port, err);
        std::process::exit(1);
    })
    .run()
    .await
    .unwrap_or_else(|err| {
        error!("Server failed to run: {}", err);
        std::process::exit(1);
    });

    info!("\nExiting rotproxy");
}
