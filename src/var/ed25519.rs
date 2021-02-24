use ed25519_dalek_blake2b::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;

fn _seed() -> [u8; 32] {
  let mut rng = OsRng {};
  let keypair: Keypair = Keypair::generate(&mut rng);
  keypair.secret.to_bytes()
}
lazy_static! {
  pub static ref SEED: [u8; 32] = {
    let seed = crate::config_get!(seed);

    if seed.len() > 0 {
      let i = base64::decode_config(&seed, base64::URL_SAFE_NO_PAD).unwrap_or_else(|_| vec![]);
      if i.len() == 32 {
        let mut r = [0u8; 32];
        r.clone_from_slice(&i[..32]);
        r
      } else {
        *blake3::hash(seed.as_bytes()).as_bytes()
      }
    } else {
      let s = _seed();
      crate::config_set!(seed, base64::encode_config(s, base64::URL_SAFE_NO_PAD));
      s
    }
  };
  pub static ref ED25519: Keypair = {
    let sk = SecretKey::from_bytes(&SEED.to_owned()).unwrap();
    let mut skv = sk.as_bytes().to_vec();
    skv.extend_from_slice(PublicKey::from(&sk).as_bytes());
    Keypair::from_bytes(&skv as &[u8]).unwrap()
  };
}
