use crate::{handle_unwrap, utils::{is_valid_ip, is_valid_file_path}, crypt::{generate_cookie_key}};

use std::{net::{IpAddr, Ipv4Addr}, path::{Path, PathBuf}, time::Duration, ops::Range};
use serde::{Deserialize, Serialize};
use humantime::parse_duration;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum Operation {
    UserAdd,
    UserDel,
    UserEdit,
    UserList,
    #[default]
    SrvServe
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub ip: String,
    pub port: u16,
    pub db_path: PathBuf,
    pub html_path: PathBuf,
    pub webroot_route: String,
    pub login_route: String,
    pub auth_endpoint: String,
    pub login_endpoint: String,
    pub login_redirect: String,
    pub logout_endpoint: String,
    pub logout_redirect: String,
    pub trusted_proxies: Vec<std::net::IpAddr>,
    pub magic_str: String,
    pub magic_bytes: usize,
    pub magic_str_duration: String,
    pub magic_str_char_range: String,
    pub rate_limit_max_user_attempts: usize,
    pub rate_limit_user_window: u64,
    pub rate_limit_max_ip_attempts: usize,
    pub rate_limit_ip_window: u64,
    pub rate_limit_bg_prune_job: u64,
    pub content_policy: String,
    pub cookie_key: String,
    pub cookie_name: String,
    pub cookie_path: String,
    pub cookie_domain: String,
    pub cookie_secure: bool,
    pub session_ttl: u32,
    pub session_abs_ttl: u32,
    pub hash_mem_cost: u32,
    pub hash_time_cost: u32,
    pub hash_parallel_cost: u32,

    #[serde(skip_serializing, skip_deserializing, default)]
    pub op: Operation,
    #[serde(skip_serializing, skip_deserializing)]
    pub magic_duration: Duration,
    #[serde(skip_serializing, skip_deserializing)]
    pub magic_range: Range<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ip: "127.0.0.1".to_string(),
            port: 8000,
            db_path: PathBuf::from("/etc/rotproxy/users.json"),
            html_path: PathBuf::from("/etc/rotproxy/index.html"),
            webroot_route: "rotproxy".to_string(),
            login_route: "".to_string(),
            auth_endpoint: "auth".to_string(),
            login_endpoint: "login".to_string(),
            login_redirect: "".to_string(),
            logout_endpoint: "logout".to_string(),
            logout_redirect: "".to_string(),
            magic_str: "".to_string(),
            magic_bytes: 32,
            magic_str_duration: "1h".to_string(),
            magic_str_char_range: "0:10".to_string(),
            trusted_proxies: vec![ IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) ],
            rate_limit_max_user_attempts: 3,
            rate_limit_user_window: 1800,
            rate_limit_max_ip_attempts: 4,
            rate_limit_ip_window: 1800,
            rate_limit_bg_prune_job: 120,
            content_policy: String::from("default-src 'self'; style-src 'self'; form-action 'self'; script-src 'self' 'sha256-xKOX32ceTgoNvySGOBePspULR2AmjzrMejHixwmcSgo='"),
            cookie_key: generate_cookie_key(),
            cookie_name: String::from("rotproxy_session"),
            cookie_path: String::from("/"),
            cookie_domain: String::from(""),
            cookie_secure: true,
            session_ttl: 3600,
            session_abs_ttl: 28800,
            hash_mem_cost: 64,
            hash_time_cost: 3,
            hash_parallel_cost: 4,
            op: Operation::SrvServe,
            magic_duration: Duration::new(0, 0), 
            magic_range: 0..16,
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("\t-c | --config /path/to/config.toml\tSpecify path to config file");
    println!("\t-h | --help\t\t\t\tPrints this help");
    println!("\t-i | --interface ip\t\t\tip to bind to");
    println!("\t-p | --port port\t\t\tport to bind to");
    println!("\t-u | --users /path/to/db.json\t\tusers database");
    println!("\t-w | --webpage /path/to/index.html\thtml login page to serve");
    println!("\tadd-user\t\t\t\tCreate a new user");
    println!("\tdelete-user\t\t\t\tDelete a user");
    println!("\tedit-user\t\t\t\tEdit a user");
    println!("\tlist-users\t\t\t\tList all users");
    println!("\tinit-conf\t\t\t\tPrints default toml config");
    println!("\tgen-cookie\t\t\t\tProvides a new cookie key");
}

fn print_default_conf() {
    println!("{}", handle_unwrap!(toml::to_string_pretty(&Config::default())));
}

fn load_config_from_file<P: AsRef<Path>>(file_path: P, conf: &mut Config) -> Result<(), String> {
    let file_contents = std::fs::read_to_string(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let parsed_config: Config = toml::from_str(&file_contents).map_err(|e| format!("Failed to parse config TOML: {}", e))?;

    *conf = parsed_config;

    Ok(())
}

pub fn parse_args(conf: &mut Config) {
    let mut args: Vec<String> = std::env::args().collect();
    let mut override_cfg = false;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-c" || args[i] == "--config" {
            if i + 1 < args.len() {
                let config_file_path: &String = &args[i + 1];

                match load_config_from_file(config_file_path, conf) {
                    Ok(_) => {
                        override_cfg = true;
                        args.drain(i..i+2);
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error loading config file \"{}\": {}", config_file_path, e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Missing config file path after -c or --config");
                std::process::exit(1);
            }
        } else {
            i += 1;
        }
    }

    if !override_cfg {
        let mut config_paths: Vec<PathBuf> = vec![PathBuf::from("config.toml")];
        
        if let Some(mut user_local_conf_path) = dirs::config_dir() {
            user_local_conf_path.push("rotproxy/config.toml");
            config_paths.push(user_local_conf_path);
        }
        config_paths.push(PathBuf::from("/etc/rotproxy/config.toml"));

        for default_config_path in config_paths {
            match is_valid_file_path(&default_config_path, true, false) {
                Ok(()) => match load_config_from_file(&default_config_path, conf) { //basically only here to handle "init-conf > config.toml"
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Error loading config file \"{}\": {}", default_config_path.display(), e);
                        std::process::exit(1);
                    }
                },
                Err(_e) => {}
            }
        }
    }

    i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" | "help" => {
                print_usage();
                std::process::exit(0);
            }
            "-i" | "--interface" => {
                if i + 1 < args.len() {
                    let ip = args[i + 1].clone();
                    i += 1;
                    if !is_valid_ip(&ip) {
                        eprintln!("Invalid ip: {}", ip);
                        std::process::exit(1);
                    } else {
                        conf.ip = ip;
                    }
                } else {
                    eprintln!("Missing value for -i");
                    std::process::exit(1);
                }
            }
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse::<u16>() {
                        conf.port = p;
                    } else {
                        eprintln!("Invalid port: {}", args[i + 1]);
                        std::process::exit(1);
                    }
                    i += 1;
                } else {
                    eprintln!("Missing value for -p");
                    std::process::exit(1);
                }
            }
            "-u" | "--users" => {
                if i + 1 < args.len() {
                    let file = args[i + 1].clone();
                    i += 1;

                    match is_valid_file_path(&file, false, true) {
                        Ok(()) => {
                            conf.db_path = PathBuf::from(file);
                        }
                        Err(e) => {
                            eprintln!("Path to users database \"{}\" is invalid: {}", file, e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Missing value for -u");
                    std::process::exit(1);
                }
            }
            "-w" | "--webpage" => {
                if i + 1 < args.len() {
                    let file = args[i + 1].clone();
                    i += 1;

                    match is_valid_file_path(&file, true, false) {
                        Ok(()) => {
                            conf.html_path = PathBuf::from(file);
                        }
                        Err(e) => {
                            eprintln!("Path to html file \"{}\" is invalid: {}", file, e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Missing value for -t");
                    std::process::exit(1);
                }
            }
            "add-user" => {
                conf.op = Operation::UserAdd;
            }
            "delete-user" => {
                conf.op = Operation::UserDel;
            }
            "edit-user" => {
                conf.op = Operation::UserEdit;
            }
            "list-user" | "list-users" => {
                conf.op = Operation::UserList;
            }
            "init-conf" => {
                print_default_conf();
                std::process::exit(0);
            }
            "gen-cookie" => {
                println!("Generated cookie key: {}", generate_cookie_key());
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown command: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    match is_valid_file_path(&conf.db_path, false, conf.op != Operation::SrvServe && conf.op != Operation::UserList) {
        Ok(()) => {}
        Err(err) => {
            if err.contains("Path does not exist") {
                match std::fs::File::create(&conf.db_path) {
                    Ok(_file) => {},
                    Err(_e) => {
                        eprintln!( "Could not open user database \"{}\": {}", conf.db_path.display(), err);
                    } 
                }
            } else {
                eprintln!( "Could not open user database \"{}\": {}", conf.db_path.display(), err);
            }
            std::process::exit(1);
        }
    }
    
    match is_valid_file_path(&conf.html_path, true, false) {
        Ok(()) => {}
        Err(e) => {
            eprintln!( "Path to html file \"{}\" is invalid: {}", conf.html_path.display(), e);
            std::process::exit(1);
        }
    }

    let a_day = Duration::from_secs(24 * 60 * 60);

    conf.magic_duration = a_day;
    conf.magic_range = 0..16;

    if conf.op == Operation::SrvServe && !conf.magic_str.is_empty() {
        conf.magic_duration = parse_duration(&conf.magic_str_duration).unwrap_or(Duration::new(0, 0));
        if conf.magic_duration.is_zero() {
            eprintln!( "Invalid magic_str_duration \"{}\"", conf.magic_str_duration);
            std::process::exit(1);
        } else if conf.magic_duration > a_day {
            eprintln!( "Invalid magic_str_duration \"{}\", it cannot be longer than a day", conf.magic_str_duration);
            std::process::exit(1);
        }

        let char_range: Vec<&str> = conf.magic_str_char_range.split(':').collect();        
        if char_range.len() != 2 {
            conf.magic_range = 0..usize::MAX;
            return;
        }

        let start = if char_range[0].trim().is_empty() {
            0
        } else {
            match char_range[0].trim().parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!( "Invalid magic_str_char_range \"{}\", start value is invalid", conf.magic_str_char_range);
                    std::process::exit(1);
                }
            }
        };

        let end = if char_range[1].trim().is_empty() {
            usize::MAX
        } else {
            match char_range[1].trim().parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!( "Invalid magic_str_char_range \"{}\", end value is invalid", conf.magic_str_char_range);
                    std::process::exit(1);
                }
            }
        };

        if start == end {
            eprintln!( "Invalid magic_str_char_range \"{}\", start value can not be equal to the end value", conf.magic_str_char_range);
            std::process::exit(1);
        }

        if start > end {
            eprintln!( "Invalid magic_str_char_range \"{}\", start value can not be larger than the end value", conf.magic_str_char_range);
            std::process::exit(1);
        }

        conf.magic_range = start..end;
    }
}
