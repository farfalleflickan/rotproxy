use super::{crypt, utils, handle_unwrap, config::Config};

use std::{collections::HashMap, io::{self, Write}, path::PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub user: String,
    pub password: String,
    pub totp: String,
}

pub fn read_user_db(file: &PathBuf) -> Result<HashMap<String, User>, std::io::Error> {
    let data = std::fs::read_to_string(file)?;

    if data.trim().is_empty() {
        return Ok(HashMap::new());
    }

    let users: Result<Vec<User>, serde_json::Error> = serde_json::from_str(&data);

    match users {
        Ok(users) => {
            let users_map: HashMap<String, User> = users
                .into_iter()
                .map(|user| (user.user.clone(), user))
                .collect();
            Ok(users_map)
        }
        Err(err) => {
            eprintln!("Failed while parsing the user DB: {}", err);
            Ok(HashMap::new())
        },
    }
}

pub fn write_user_db(file: &PathBuf, user_map: HashMap<String, User>) -> Result<(), std::io::Error> {
    let users: Vec<User> = user_map
        .iter()
        .map(|(username, info)| User {
            user: username.clone(),
            password: info.password.clone(),
            totp: info.totp.clone(),
        })
        .collect();

    let tmp_path = file.with_extension("tmp");
    let data = serde_json::to_string_pretty(&users)?;

    std::fs::write(&tmp_path, data)?;
    std::fs::rename(&tmp_path, file)?;

    Ok(())
}

pub fn add_user(conf: Config) {
    let db_path = &conf.db_path;
    let mut user_map = handle_unwrap!(read_user_db(db_path));
    let mut username: String;
    let mut pwd: String;

    loop {
        username = utils::prompt_line("Enter username: ");

        if !username.is_empty() {
            if validate_username(&username) {
                if user_map.contains_key(&username) {
                    println!("User {} already exists!", username);
                } else {
                    break;
                }
            } else {
               println!("Username contains unallowed characters!"); 
            }
        } else {
            println!("Username cannot be empty!");
        }
    }

    loop {
        print!("Enter password: ");
        handle_unwrap!(std::io::stdout().flush());
        pwd = utils::read_password();

        if !pwd.is_empty() {
            let password_match: bool;
            println!();
            loop {
                print!("Repeat password: ");
                handle_unwrap!(std::io::stdout().flush());
                let repeat_pwd = utils::read_password();
        
                if !repeat_pwd.is_empty() {
                    password_match = pwd == repeat_pwd;
                    break;
                } else {
                    println!("\nPassword cannot be empty!");
                }
            }
            
            if password_match {
                println!();
                break
            } else {
                println!("\nPasswords do not match!");
                pwd.clear();
            }
        } else {
            println!("\nPassword cannot be empty!");
            pwd.clear();
        }
    }

    let hash = handle_unwrap!(crypt::hash_password(&conf, &pwd));
    let salt = crypt::get_hash_salt(&hash);
    
    if salt.is_err() {
        utils::fatal_error(&format!("Failed getting salt while parsing hash: {}", hash), salt.as_ref().err());
    }

    let salt = salt.unwrap();
    let secret = crypt::new_secret();
    let totp = crypt::kdf_encrypt(&conf, &secret, &pwd, &salt);

    if totp.is_err() {
        utils::fatal_error(&format!("Error while kdf encrypting TOTP: {}", secret), totp.as_ref().err());
    }

    let totp = totp.unwrap();

    let user = User {
        user: username.clone(),
        password: hash,
        totp
    };

    user_map.insert(username.clone(), user);
    let _ = write_user_db(db_path, user_map);

    crypt::print_totp_qr_cli(&username, &secret);
    println!("\nUser {} created!", username);
}

pub fn del_user(db_path: PathBuf) {
    let mut user_map = handle_unwrap!(read_user_db(&db_path));
    let mut input: String;

    let username = loop {
        input = utils::prompt_line("Enter username: ");

        if input.is_empty() {
            println!("Username cannot be empty!");
            continue;
        }
        if validate_username(&input) {
            if !user_map.contains_key(&input) {
                println!("User {} not found!", input);
                continue;
            } else {
                break input.clone();
            }
        } else {
           println!("Username contains unallowed characters!"); 
        }
    };

    let del_user = utils::prompt_yes_no(&format!(
        "User {} will be deleted! Are you sure? (y/n) ",
        username
    ));

    if del_user {
        let _ = user_map.remove(&username);
        let _ = write_user_db(&db_path, user_map);
        println!("User \"{}\" deleted.", username)
    } else {
        println!("Operation cancelled.");
    }
}

pub fn edit_user(conf: Config) {
    let db_path = &conf.db_path;
    let mut user_map = handle_unwrap!(read_user_db(db_path));
    let mut input: String;
    let og_user: String;

    let username = loop {
        input = utils::prompt_line("Enter username: ");

        if input.is_empty() {
            println!("Username cannot be empty!");
            continue;
        }
        if validate_username(&input) {
            if !user_map.contains_key(&input) {
                println!("User {} not found!", input);
            } else {
                og_user = input.clone();
                break input.clone();
            }
        } else {
            println!("Username contains unallowed characters!");
        }
    };

    if let Some(mut user) = user_map.remove(&username) { 
        let change_username = utils::prompt_yes_no("Change username? (y/n) ");

        if change_username {
            loop {
                input = utils::prompt_line("Enter new username: ");

                if !input.is_empty() {
                    user.user = input.clone();
                    break;
                } else {
                    println!("Username cannot be empty!");
                }
            }
        }

        let change_pwd = utils::prompt_yes_no("Change password? (y/n) ");
        let mut user_pwd: Option<String> = None;

        if change_pwd {
            let totp_secret;
            loop {
                print!("Enter old password: ");
                handle_unwrap!(io::stdout().flush());
                let old_pwd = utils::read_password();

                if crypt::verify_password(&conf, &user.password, &old_pwd) {
                    let salt = crypt::get_hash_salt(&user.password);
                    if salt.is_err() {
                        utils::fatal_error(&format!("Failed getting salt while parsing hash: {}", user.password), salt.as_ref().err());
                    }
                    let salt = salt.unwrap();
                    let totp = crypt::kdf_decrypt(&conf, &user.totp, &old_pwd, &salt);
                    
                    if totp.is_err() {
                        utils::fatal_error(&format!("Error while kdf decrypting TOTP: {}", &user.totp), totp.as_ref().err());
                    }
                
                    totp_secret = totp.unwrap();
                    break;
                } else {
                    println!("\nWrong password!");
                }
            }
            println!();
            loop {
                print!("Enter new password: ");
                handle_unwrap!(io::stdout().flush());
                let new_pwd = utils::read_password();

                if !new_pwd.is_empty() {
                    let password_match: bool;
                    println!();
                    loop {
                        print!("Repeat new password: ");
                        handle_unwrap!(std::io::stdout().flush());
                        let repeat_pwd = utils::read_password();
                
                        if !repeat_pwd.is_empty() {
                            password_match = new_pwd == repeat_pwd;
                            break;
                        } else {
                            println!("\nPassword cannot be empty!");
                        }
                    }
        
                    if password_match {
                        user.password = handle_unwrap!(crypt::hash_password(&conf, &new_pwd));

                        let salt = crypt::get_hash_salt(&user.password);
                        if salt.is_err() {
                            utils::fatal_error(&format!("Failed getting salt while parsing hash: {}", user.password), salt.as_ref().err());
                        }
                        let salt = salt.unwrap();
                        let totp = crypt::kdf_encrypt(&conf, &totp_secret, &new_pwd, &salt);

                        if totp.is_err() {
                            utils::fatal_error(&format!("Error while kdf encrypting TOTP: {}", *totp_secret), totp.as_ref().err());
                        }
                    
                        let totp = totp.unwrap();
                        user.totp = totp;

                        user_pwd = Some(new_pwd);
                        break
                    } else {
                        println!("\nPasswords do not match!");
                    }
                } else {
                    println!("\nPassword cannot be empty!");
                }
            }
            println!();
        }

        let change_totp = utils::prompt_yes_no("Change TOTP? (y/n) ");

        let mut secret: Option<String> = None;
        if change_totp {
            let temp_secret = crypt::new_secret();

            if let Some(pwd) = user_pwd {
                let salt = crypt::get_hash_salt(&user.password);
                if salt.is_err() {
                    utils::fatal_error(&format!("Failed getting salt while parsing hash: {}", user.password), salt.as_ref().err());
                }
                let salt = salt.unwrap();
                let totp = crypt::kdf_encrypt(&conf, &temp_secret, &pwd, &salt);

                if totp.is_err() {
                    utils::fatal_error(&format!("Error while kdf encrypting TOTP: {}", temp_secret), totp.as_ref().err());
                }
            
                let totp = totp.unwrap();
                user.totp = totp;

            } else {
                loop {
                    print!("Enter user password: ");
                    handle_unwrap!(io::stdout().flush());
                    let pwd = utils::read_password();
    
                    if crypt::verify_password(&conf, &user.password, &pwd) {
                        let salt = crypt::get_hash_salt(&user.password);
                        if salt.is_err() {
                            utils::fatal_error(&format!("Failed getting salt while parsing hash: {}", user.password), salt.as_ref().err());
                        }
                        let salt = salt.unwrap();
                        let totp = crypt::kdf_encrypt(&conf, &temp_secret, &pwd, &salt);

                        if totp.is_err() {
                            utils::fatal_error(&format!("Error while kdf encrypting TOTP: {}", temp_secret), totp.as_ref().err());
                        }
                    
                        let totp = totp.unwrap();
                        user.totp = totp;
                        break;
                    } else {
                        println!("\nWrong password!");
                    }
                }
                println!();
            }
            secret = Some(temp_secret);
        }

        let new_username = user.user.clone();
        user_map.insert(new_username.clone(), user);

        let _ = write_user_db(db_path, user_map);

        if change_username || change_pwd || change_totp {
            if change_username {
                println!("Changed user \"{}\" (was: \"{}\").", new_username, og_user);
            } else {
                println!("Changed user \"{}\".", og_user);
            }

            if change_pwd {
                println!("Password has been updated.");
            }

            if change_totp {
                if let Some(s) = &secret {
                    println!("TOTP has been updated.");
                    crypt::print_totp_qr_cli(&new_username, s);
                    println!();
                }
            }
        }
    } else {
        utils::fatal_error::<String>("Exptected user could not be changed.", None);
    }
}

pub fn list_users(db_path: PathBuf) {
    let user_map = handle_unwrap!(read_user_db(&db_path));
    let mut keys: Vec<&String> = user_map.keys().collect();
    keys.sort_by_key(|k| k.to_lowercase());

    if !keys.is_empty() {
        println!("Existing users:");
        for key in keys {
            println!("\t{}", key);
        }
    } else {
        println!("No users.");
    } 
}

pub fn validate_username(name: &str) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false
    }

    // Pre-made validation table, only allows:
    // ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-
    const TABLE: [bool; 256] = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, false, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, true, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
    !name.as_bytes().iter().any(|&c| !TABLE[c as usize])
}