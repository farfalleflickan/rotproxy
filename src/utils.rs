use std::{collections::VecDeque, fs::{OpenOptions}, io::{self, BufReader, Read, Write}, path::Path, str::FromStr, time::{SystemTime, UNIX_EPOCH}};
use termion::raw::IntoRawMode;

#[macro_export]
macro_rules! handle_unwrap {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(err) => {
                eprintln!("Error: {}", err);
                let bt = std::backtrace::Backtrace::capture();
                eprintln!("Backtrace:\n{:#?}", bt);
                std::process::exit(1);
            }
        }
    };
}

pub fn fatal_error<T: std::fmt::Debug>(msg: &str, err: Option<T>) {
    eprintln!("{}", msg);
    if let Some(error) = err {
        eprintln!("Error: {:?}", error)
    }
    let bt = std::backtrace::Backtrace::capture();
    eprintln!("Backtrace:\n{:#?}", bt);
    std::process::exit(1);
}

#[derive(Debug, Clone, Default)]
pub struct SmartQueue<T> {
    buf: VecDeque<T>,
    cap: usize,
}

impl<T> SmartQueue<T> {
    pub fn new(cap: usize) -> Self {
        SmartQueue {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn insert(&mut self, item: T) {
        self.buf.push_front(item);
        if self.buf.len() > self.cap {
            self.buf.pop_back();
        }
    }

    pub fn prune<P>(&mut self, mut predicate: P) where P: FnMut(&T) -> bool {
        while let Some(last) = self.buf.back() {
            if predicate(last) {
                self.buf.pop_back();
            } else {
                break; //Vector is ordered latest to oldest so first object that isn't too old means the rest of the vector up to top isn't either 
            }
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

pub fn read_password() -> String {
    let mut stdout = handle_unwrap!(io::stdout().lock().into_raw_mode());

    let mut password = String::new();
    let mut printed_chars = 0;

    let reader = BufReader::new(io::stdin().lock());
    for byte in reader.bytes() {
        let byte = handle_unwrap!(byte);

        if byte == 0x03 {
            drop(stdout);
            println!();
            std::process::exit(1);
        }

        if byte == b'\n' || byte == b'\r' {
            break;
        }

        //backspace/delete
        if byte == b'\x08' || byte == b'\x7f' {
            if printed_chars > 0 {
                print!("\x08 \x08");
                handle_unwrap!(stdout.flush());
                password.pop();
                printed_chars -= 1;
            }
        } else {
            print!("•");
            handle_unwrap!(stdout.flush());
            password.push(byte as char);
            printed_chars += 1;
        }
    }

    password
}

fn is_valid_ipv4(ip: &str) -> bool {
    std::net::Ipv4Addr::from_str(ip).is_ok()
}

fn is_valid_ipv6(ip: &str) -> bool {
    std::net::Ipv6Addr::from_str(ip).is_ok()
}

pub fn is_valid_ip(ip: &str) -> bool {
    is_valid_ipv4(ip) || is_valid_ipv6(ip)
}

pub fn is_valid_file_path<P: AsRef<Path>>(path: P, check_not_empty: bool, check_writable: bool) -> Result<(), String> {
    let path_ref = path.as_ref();
    
    if !path_ref.exists() {
        return Err(format!("Path does not exist: {}", path_ref.display()));
    }

    let metadata = std::fs::metadata(path_ref)
        .map_err(|e| format!("Failed to stat file '{}': {}", path_ref.display(), e))?;

    if !metadata.is_file() {
        return Err(format!("Path is not a file: {}", path_ref.display()));
    }

    if check_not_empty && metadata.len() == 0 {
        return Err(format!("File is empty: {}", path_ref.display()));
    }

    if check_writable {
        OpenOptions::new().write(true).open(path_ref).map_err(|e| format!("File is not writable '{}': {}", path_ref.display(), e))?;
    }

    Ok(())
}

pub fn prompt_line(text: &str) -> String {
    let mut input = String::new();
    print!("{}", text);
    handle_unwrap!(io::stdout().flush());
    handle_unwrap!(io::stdin().read_line(&mut input));
    input = input.trim().to_string();
    input
}

pub fn prompt_yes_no(text: &str) -> bool {
    loop {
        let mut input = String::new();
        print!("{}", text);

        handle_unwrap!(io::stdout().flush());
        handle_unwrap!(io::stdin().read_line(&mut input));
        match input.trim() {
            "y" | "Y" => return true,
            "n" | "N" => return false,
            _ => println!("Invalid input!"),
        }
    }
}

pub fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

pub fn prepend_slash(str: &str) -> String {
    let mut result = str.to_string();

    if !result.starts_with('/') {
        result.insert(0, '/');
    }

    result
}

pub fn append_slash(str: &str) -> String {
    let mut result = str.to_string();

    if !result.ends_with('/') {
        result.push('/');
    }

    result
}

pub fn trim_slashes(str: &str) -> String {
    str.trim_start_matches('/').trim_end_matches('/').to_string()
}

pub fn trim_slash_end(str: &str) -> String {
    if str != "/" {
        return str.trim_end_matches('/').to_string();
    }

    str.to_string()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut ret = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut ret, "{:02x}", b).unwrap();
    }
    ret
}