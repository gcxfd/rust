use crate::lib::now::sec;
use indexmap::IndexMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::RwLock;

pub fn bisect<F: Fn(usize) -> bool>(hi: usize, cmp: F) -> usize {
  let mut hi = hi;
  let mut lo: usize = 0;
  while lo < hi {
    let mid = (lo + hi) / 2;
    if cmp(mid) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  lo
}

pub struct Connecting<Key> {
  ip_time: RwLock<IndexMap<Key, u64>>,
  timeout_sec: u64,
}

impl<Key: Eq + Hash + Debug> Connecting<Key> {
  pub fn add(&self, ip: Key) {
    self.ip_time.write().unwrap().insert(ip, sec());
  }
  pub fn has(&self, ip: &Key) -> bool {
    self.ip_time.read().unwrap().get(ip) != None
  }
  pub fn pop(&self, ip: &Key) -> bool {
    self.ip_time.write().unwrap().shift_remove(ip) != None
  }
  pub fn clean(&self) {
    let lo = {
      let c = self.ip_time.read().unwrap();
      let len = c.len();
      if len == 0 {
        return;
      }
      let now = sec();
      bisect(len, |mid| {
        c.get_index(mid).unwrap().1 + self.timeout_sec < now
      })
    };
    /*
    {
      let c = self.ip_time.read().unwrap();
      println!("connecting {}", c.len());
      for i in c.iter() {
        println!("> {:?} lo {}", i, lo)
      }
    };
    */
    if lo != 0 {
      let mut c = self.ip_time.write().unwrap();
      c.drain(..lo);
    };
  }
  pub fn new(timeout_sec: u64) -> Self {
    Self {
      ip_time: RwLock::new(IndexMap::<Key, u64>::new()),
      timeout_sec: timeout_sec,
    }
  }
}
