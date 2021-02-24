use super::args::args;
use std::env;
use std::fs;
use std::path::PathBuf;

lazy_static! {
  pub static ref root: PathBuf = {
    let dir = match args.value_of("dir") {
      Some(i) => i,
      None => "",
    };
    let r = if dir.len() > 0 {
      PathBuf::from(dir)
    } else {
      if cfg!(windows) {
        let mut h = env::current_exe().unwrap();
        h.pop();
        h.push("rmw");
        h
      } else {
        let mut h = dirs::home_dir().unwrap();
        h.push(".rmw");
        h
      }
    };
    fs::create_dir_all(r.as_path().display().to_string()).unwrap();
    r
  };
}

pub fn join(dir: &str) -> String {
  let mut r = root.clone();
  r.push(dir);
  r.as_path().display().to_string()
}
