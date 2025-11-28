mod config;
mod crypt;
mod server;
mod user;
mod utils;

use config::parse_args;

fn run(conf: config::Config) {
    if conf.op == config::Operation::UserAdd {
        user::add_user(conf);
    } else if conf.op == config::Operation::UserDel {
        user::del_user(conf.db_path);
    } else if conf.op == config::Operation::UserEdit {
        user::edit_user(conf);
    } else if conf.op == config::Operation::UserList {
        user::list_users(conf.db_path);
    } else {
        server::start_server(conf);
    }
}

fn main() {
    let mut conf = config::Config::default();

    parse_args(&mut conf);
    run(conf);
}
