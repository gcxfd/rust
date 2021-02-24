use super::root;
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

pub mod str {
  pub const host: &str = "host";
  pub const port: &str = "port";
  pub const seed: &str = "seed";
}

#[macro_export]
macro_rules! config_set {
  ($key:tt, $val:expr) => {{
    use $crate::var::config;
    let mut c = config::config.write().unwrap();
    c.insert(String::from(config::str::$key), $val);
    let mut r: Vec<String> = vec![];
    for (key, val) in c.clone() {
      r.push(format!("{}:{}", key, val));
    }
    std::fs::write(config::yml.as_str(), r.join("\n").as_bytes()).unwrap();
  }};
}

#[macro_export]
macro_rules! config_get_or_default {
  ($key:tt, $val: tt) => {{
    use $crate::var::{args, config};
    match args::args.value_of(config::str::$key) {
      None => {
        let c = config::config.read().unwrap();
        match c.get(config::str::$key) {
          None => $val.to_owned(),
          Some(i) => i.to_owned(),
        }
      }
      Some(i) => i.to_owned(),
    }
  }};
}

#[macro_export]
macro_rules! config_get {
  ($key:tt) => {
    $crate::config_get_or_default!($key, "")
  };
}

lazy_static! {
  pub static ref yml: String = root::join("config.yml");
  pub static ref config: RwLock<HashMap<String, String>> = {
    let mut map = HashMap::new();
    let txt = {
      if Path::new(&yml.as_str()).is_file() {
        std::fs::read_to_string(&*yml).unwrap()
      } else {
        String::from("")
      }
    };
    for line in txt.split("\n") {
      let line = line.trim();
      if line.starts_with("#") {
        continue;
      }
      match line.find(":") {
        Some(i) => {
          let (key, val) = line.split_at(i);
          let (_, val) = val.split_at(1);
          if key.len() > 0 {
            map.insert(String::from(key.trim_end()), String::from(val.trim_start()));
          }
        }
        _ => {}
      }
    }

    RwLock::new(map)
  };
}
