use super::{config, crypt, user, utils, utils::SmartQueue, utils::{append_slash, prepend_slash, trim_slashes, trim_slash_end, constant_time_eq_str}, handle_unwrap};

use actix_web::{cookie::{Key, SameSite}, http::header, middleware::{Logger, NormalizePath}, rt, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_session::{storage::CookieSessionStore, SessionMiddleware, config::SessionLifecycle};
use std::{env, io::Write, net::IpAddr, time::{Duration, Instant}, collections::HashMap};
use log::{debug, error, info, trace, warn};
use zeroize::Zeroizing;
use serde::Deserialize;
use dashmap::DashMap;

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

    pub fn clear_user(&self, user: &str) {
        let prefix = format!("user:{}:", user);
        self.clear_prefix(&prefix);
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

struct HtmlContent(pub String);
struct CssContent(pub String);

fn is_session_expired(session: &actix_session::Session, ttl: i64) -> bool {
    if let Some(start) = session.get::<i64>("start").unwrap_or(None) {
        utils::unix_timestamp() - start > ttl
    } else {
        true
    }
}

async fn index_css(css: web::Data<CssContent>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(css.get_ref().0.clone())
}

async fn login_page(req: HttpRequest, magic_path: Option<web::Path<String>>, html: web::Data<HtmlContent>, session: actix_session::Session, conf: web::Data<config::Config>) -> impl Responder {
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
    let css_path = format!("{}index.css", &append_slash(&web_path));
    let login_endpoint;

    if !conf.login_route.is_empty() {
        login_endpoint = web_path.replace(&conf.login_route, "") + &trim_slashes(&conf.login_endpoint);
    } else {
        login_endpoint = append_slash(&web_path) + &trim_slashes(&conf.login_endpoint);
    }
    
    match web::Query::<HashMap<String, String>>::from_query(req.query_string()) {
        Ok(query) => {
            if let Some(redirect_value) = query.get("redirect") {
                let _ = session.insert("login_redirect", redirect_value);
                debug!("Parsed login_redirect from login page query: {}", redirect_value);
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

    let html_with_csrf = html.get_ref().0.replace("{CSRF_TOKEN_TEMPLATE}", &csrf_token).replace("{INDEX_CSS_WEBPATH}", &css_path).replace("{LOGIN_ENDPOINT}", &login_endpoint);

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Content-Security-Policy", conf.content_policy.as_str()))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(html_with_csrf)
}

fn get_client_ip(conf: &config::Config, req: &HttpRequest) -> Option<IpAddr> {
    let peer_ip = req.peer_addr().map(|sock| sock.ip())?;

    if conf.trusted_proxies.contains(&peer_ip) {
        if let Some(xff) = req.headers().get(header::X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
            if let Some(client_ip) = xff.split(',').map(str::trim).filter_map(|s| s.parse::<IpAddr>().ok()).find(|ip| !conf.trusted_proxies.contains(ip)) {
                return Some(client_ip);
            }
        }

        if let Some(fwd) = req.headers().get(header::FORWARDED).and_then(|v| v.to_str().ok()) {
            for entry in fwd.split(',') {
                for param in entry.trim().split(';') {
                    if let Some(val) = param.trim().strip_prefix("for=") {
                        // strip optional quotes
                        let ip_str = val.trim_matches('"');
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

    Some(peer_ip)
}

async fn login(req: HttpRequest, magic_path: Option<web::Path<String>>, data: web::Data<DashMap<String, user::User>>, form: web::Form<LoginForm>, session: actix_session::Session, rate_limiter: web::Data<RateLimiter>, conf: web::Data<config::Config>, html: web::Data<HtmlContent>) -> impl Responder {
    let magic = magic_path.unwrap_or(web::Path::from("".to_string()));

    if !conf.magic_str.is_empty() && !constant_time_eq_str(magic.as_str(), &crypt::magic_hash(&conf.magic_str, conf.magic_bytes, conf.magic_duration, conf.magic_range.clone())) {
        return HttpResponse::NotFound().body("");
    }
    
    let web_path = req.uri().path();
    let css_path = format!("{}/index.css", web_path.replace(&conf.login_endpoint, "") + &trim_slashes(&conf.login_route));
    
    let session_token: Option<String> = session.get("csrf_token").unwrap_or(None);
    session.remove("csrf_token");

    let csrf_token = crypt::rand_str(64);

    let html_with_csrf = html.get_ref().0.replace("{CSRF_TOKEN_TEMPLATE}", &csrf_token).replace("{INDEX_CSS_WEBPATH}", &css_path).replace("{LOGIN_ENDPOINT}", &web_path);
    let invalid_html = html_with_csrf.replace("<button type=\"submit\" id=\"loginButton\">Log in</button>", "<div class=\"error\">Invalid credentials</div>\n\t\t<button type=\"submit\" id=\"loginButton\">Log in</button>");
    let rate_html = html_with_csrf.replace("<button type=\"submit\" id=\"loginButton\">Log in</button>", "<div class=\"error\">Too many attempts, try again later</div>\n\t\t<button type=\"submit\" id=\"loginButton\">Log in</button>");
    let login_failed = HttpResponse::Ok().content_type("text/html; charset=utf-8").body(invalid_html);
    let login_limited = HttpResponse::Ok().content_type("text/html; charset=utf-8").body(rate_html);

    let session_success = session_token.as_deref() == Some(&form.csrf_token);
    let _ = session.insert("csrf_token", &csrf_token);

    if let Some(ip_addr) = get_client_ip(&conf, &req) {
        let ip = ip_addr.to_string();
        let req_user_agent = req.headers().get(header::USER_AGENT).and_then(|s| s.to_str().ok()).unwrap_or("");
        let req_referer = req.headers().get(header::REFERER).and_then(|s| s.to_str().ok()).unwrap_or("");
        let username = Zeroizing::new(form.user.trim().to_string());
        let password = Zeroizing::new(form.password.trim().to_string());
        let totp     = Zeroizing::new(form.totp.trim().to_string());

        let mut user_fails = 0;
        let mut ip_fails = rate_limiter.get_ip_failures(&ip);

        if ip_fails >= rate_limiter.ip_max_requests {
            let millis = crypt::rand_between(1000, 2500);
            rt::time::sleep(Duration::from_millis(millis)).await;
            debug!("Authentication limited \"{}\" (ip: {}/{}) - \"{}\" \"{}\" \"{}\"", 
                username.as_str(), 
                ip_fails, rate_limiter.ip_max_requests,ip, 
                req_user_agent, req_referer
            );
            return login_limited
        }

        if session_success {
            if user::validate_username(&username) {
                user_fails = rate_limiter.get_user_failures(&username, &ip);
                if user_fails >= rate_limiter.user_max_requests {
                    let millis = crypt::rand_between(1000, 2500);
                    rt::time::sleep(Duration::from_millis(millis)).await;
                    debug!("Authentication limited \"{}\" (user: {}/{} ip: {}/{}) - \"{}\" \"{}\" \"{}\"", 
                        username.as_str(), 
                        user_fails, rate_limiter.user_max_requests, 
                        ip_fails, rate_limiter.ip_max_requests,ip, 
                        req_user_agent, req_referer
                    );
                    return login_limited
                }

                if let Some(user) = data.get(username.as_str()) {
                    let conf_copy = conf.clone();
                    let user_pw_copy = Zeroizing::new(user.password.clone());
                    let input_pw_copy = Zeroizing::new(password.clone());
                    let is_valid: bool = web::block(move || crypt::verify_password(&conf_copy, &user_pw_copy, &input_pw_copy)).await.unwrap_or(false);

                    if is_valid {
                        if let Ok(pwd_salt) = crypt::get_hash_salt(&user.password) {
                            let conf_copy = conf.clone();
                            let totp_copy = Zeroizing::new(user.totp.clone());
                            let user_pw_copy = Zeroizing::new(password.clone());

                            let decrypt_res = web::block(move || crypt::kdf_decrypt(&conf_copy, &totp_copy, &user_pw_copy, &pwd_salt).map_err(|e| e.to_string())).await;
                            match decrypt_res {
                                Ok(Ok(dec_totp)) => {
                                    let totp_secret  = dec_totp.clone();
                                    let totp_copy = totp.clone();
                                    let totp_valid: bool = web::block(move || { crypt::check_totp(&totp_secret,&totp_copy)}).await.unwrap_or(false);

                                    if totp_valid {
                                        rate_limiter.clear_user(&username);
                                        if session.insert("user", username.as_str()).is_ok() {
                                            info!("Authenticated \"{}\" - \"{}\" \"{}\" \"{}\"", username.as_str(), ip, req_user_agent, req_referer);
                                            session.insert("start", utils::unix_timestamp()).ok();
                                            session.renew();

                                            if let Ok(Some(redirect)) = session.get::<String>("login_redirect") {
                                                if !redirect.is_empty() {
                                                    let _ = session.remove("login_redirect");
                                                    return HttpResponse::SeeOther().insert_header((header::LOCATION, redirect)).finish();
                                                }
                                            }
                                            
                                            if conf.login_redirect.is_empty() {
                                                return HttpResponse::Ok().body("Authenticated");
                                            }

                                            return HttpResponse::SeeOther().insert_header((header::LOCATION, conf.login_redirect.clone())).finish();
                                        }
                                    } else {
                                        user_fails = rate_limiter.record_user_failure(&username, &ip);
                                    }
                                }
                                _ => {
                                    user_fails = rate_limiter.record_user_failure(&username, &ip);
                                }
                            }
                        } else {
                            user_fails = rate_limiter.record_user_failure(&username, &ip);
                        }
                    } else {
                        user_fails = rate_limiter.record_user_failure(&username, &ip);
                    }
                }
            }
        } else {
            ip_fails = rate_limiter.record_ip_failure(&ip);
            warn!("Invalid session \"{}\" (ip ban: {}/{}) - \"{}\" \"{}\" \"{}\"", 
                form.csrf_token, 
                ip_fails, rate_limiter.ip_max_requests, 
                ip, req_user_agent, req_referer
            );

            let delay = std::cmp::min(std::cmp::max(user_fails, ip_fails) as u64, 5) as u64;
            if delay > 0 {
                let millis = crypt::rand_between(10, 500);
                rt::time::sleep(Duration::from_secs(delay) + Duration::from_millis(millis)).await;
            }
            return login_failed;
        }

        ip_fails = rate_limiter.record_ip_failure(&ip);

        warn!("Authentication failed \"{}\" (user: {}/{} ip: {}/{}) - \"{}\" \"{}\" \"{}\"", 
            username.as_str(), 
            user_fails, rate_limiter.user_max_requests, 
            ip_fails, rate_limiter.ip_max_requests,ip, 
            req_user_agent, req_referer
        );

        let delay = std::cmp::min(std::cmp::max(user_fails, ip_fails) as u64, 5) as u64;
        if delay > 0 {
            let millis = crypt::rand_between(10, 500);
            rt::time::sleep(Duration::from_secs(delay) + Duration::from_millis(millis)).await;
        }

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
    let abs_session_ttl = conf.session_abs_ttl as i64;

    if abs_session_ttl > 0 && is_session_expired(&session, abs_session_ttl) {
        session.purge();
    } else if let Some(_user) = session.get::<String>("user").unwrap_or(None) {
        return HttpResponse::Ok().finish();
    }

    let millis = crypt::rand_between(100, 1500);
    rt::time::sleep(Duration::from_millis(millis)).await;

    HttpResponse::Unauthorized().finish()
}

async fn logout(req: HttpRequest, magic_path: Option<web::Path<String>>, session: actix_session::Session, conf: web::Data<config::Config>) -> impl Responder {
    let magic = magic_path.unwrap_or(web::Path::from("".to_string()));

    if !conf.magic_str.is_empty() && !constant_time_eq_str(magic.as_str(), &crypt::magic_hash(&conf.magic_str, conf.magic_bytes, conf.magic_duration, conf.magic_range.clone())) {
        return HttpResponse::NotFound().body("");
    }

    let redirect_value = web::Query::<HashMap<String, String>>::from_query(req.query_string()).ok().and_then(|query| query.get("redirect").cloned());

    session.purge();

    if let Some(redirect) = redirect_value {
        debug!("Parsed redirect from logout page query: {}", redirect);
        return HttpResponse::SeeOther().insert_header((header::LOCATION, redirect)).finish();
    }

    if conf.logout_redirect.is_empty() {
        return HttpResponse::Ok().body("Logged out");
    }

    HttpResponse::SeeOther().insert_header((header::LOCATION, conf.logout_redirect.clone())).finish()
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
    let users_dashmap: DashMap<String, user::User> = users_map.into_iter().collect();
    let map_data = web::Data::new(users_dashmap);

    let mut css_path = conf.html_path.clone();
    let html_file = handle_unwrap!(std::fs::read_to_string(conf.html_path));
    let html_data = web::Data::new(HtmlContent(html_file));
    css_path.set_extension("css");
    let css_file = handle_unwrap!(std::fs::read_to_string(css_path));
    let css_data = web::Data::new(CssContent(css_file));

    let secret_key = Key::from(conf.cookie_key.as_bytes());
    let session_ttl: i64 = conf.session_ttl.into();

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

    info!("Starting rotproxy on {}:{}{}", interface, port, webroot);

    let user_map = handle_unwrap!(user::read_user_db(&conf.db_path));
    if user_map.is_empty() {
        warn!("Starting server with empty user database!");
    }

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
            .app_data(rate_limiter.clone())
            .app_data(html_data.clone())
            .app_data(css_data.clone())
            .app_data(conf_data.clone())
            .route(&auth_ep, web::get().to(auth)) //HAS to be here before wildcards in case magic_str is set...
            .route(&trim_slash_end(&login_subpath), web::get().to(login_page))
            .route(&index_html_path, web::get().to(login_page))
            .route(&index_css_path, web::get().to(index_css))
            .route(&logout_ep, web::get().to(logout))
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
