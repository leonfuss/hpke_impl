use hpke;
use hpke::aead::AeadTag;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::Deserializable;
use hpke::OpModeR;
use rand::SeedableRng;

pub type SimpleHpke = Hpke<X25519HkdfSha256, ChaCha20Poly1305, HkdfSha256>;

pub struct Hpke<Kem, Aead, Kdf>
where
    Kem: hpke::Kem,
    Aead: hpke::aead::Aead,
    Kdf: hpke::kdf::Kdf,
{
    _kem: std::marker::PhantomData<Kem>,
    _aead: std::marker::PhantomData<Aead>,
    _kdf: std::marker::PhantomData<Kdf>,
}

pub type SimplePublicKey = Key<<X25519HkdfSha256 as hpke::Kem>::PublicKey>;
pub type SimplePrivateKey = Key<<X25519HkdfSha256 as hpke::Kem>::PrivateKey>;

pub struct Key<K>
where
    K: hpke::Serializable,
{
    key: K,
}

impl<K> Key<K>
where
    K: hpke::Serializable + Deserializable,
{
    fn new(key: K) -> Key<K> {
        Key { key }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        K::to_bytes(&self.key).to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Key<K>, String> {
        K::from_bytes(bytes)
            .map(|it| Key::new(it))
            .map_err(|e| e.to_string())
    }
}

impl<Kem, Aead, Kdf> Hpke<Kem, Aead, Kdf>
where
    Kem: hpke::Kem,
    Aead: hpke::aead::Aead,
    Kdf: hpke::kdf::Kdf,
{
    pub fn generate_key_pair() -> (
        Key<<Kem as hpke::Kem>::PrivateKey>,
        Key<<Kem as hpke::Kem>::PublicKey>,
    ) {
        let mut csprng = rand::rngs::StdRng::from_entropy();
        let (privat, public) = Kem::gen_keypair(&mut csprng);
        (Key::new(privat), Key::new(public))
    }
    // Given a message and associated data, returns an encapsulated key, ciphertext, and tag. The
    // ciphertext is encrypted with the shared AEAD context
    pub fn encrypt(
        msg: &[u8],
        associated_data: &[u8],
        server_public_key: &[u8],
        information_str: &[u8],
    ) -> (<Kem as hpke::Kem>::EncappedKey, Vec<u8>, AeadTag<Aead>) {
        let mut csprng = rand::rngs::StdRng::from_entropy();

        let server_public_key = <Kem as hpke::Kem>::PublicKey::from_bytes(server_public_key)
            .expect("could not deserialize server privkey!");

        // Encapsulate a key and use the resulting shared secret to encrypt a message. The AEAD context
        // is what you use to encrypt.
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &hpke::OpModeS::Base,
            &server_public_key,
            information_str,
            &mut csprng,
        )
        .expect("invalid server pubkey!");

        // On success, seal_in_place_detached() will encrypt the plaintext in place
        let mut msg_copy = msg.to_vec();
        let tag = sender_ctx
            .seal_in_place_detached(&mut msg_copy, associated_data)
            .expect("encryption failed!");

        let ciphertext = msg_copy;

        (encapped_key, ciphertext, tag)
    }

    // Returns the decrypted client message
    pub fn decrypt(
        server_secret_key: &[u8],
        encapped_key_bytes: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
        tag_bytes: &[u8],
        information_str: &[u8],
    ) -> Vec<u8> {
        // We have to derialize the secret key, AEAD tag, and encapsulated pubkey. These fail if the
        // bytestrings are the wrong length.
        let server_secret_key = <Kem as hpke::Kem>::PrivateKey::from_bytes(server_secret_key)
            .expect("could not deserialize server privkey!");
        let tag = AeadTag::<Aead>::from_bytes(tag_bytes).expect("could not deserialize AEAD tag!");
        let encapped_key = <Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key_bytes)
            .expect("could not deserialize the encapsulated pubkey!");

        // Decapsulate and derive the shared secret. This creates a shared AEAD context.
        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &server_secret_key,
            &encapped_key,
            information_str,
        )
        .expect("failed to set up receiver!");

        // On success, open_in_place_detached() will decrypt the ciphertext in place
        let mut ciphertext_copy = ciphertext.to_vec();
        receiver_ctx
            .open_in_place_detached(&mut ciphertext_copy, associated_data, &tag)
            .expect("invalid ciphertext!");

        // Rename for clarity.
        #[allow(clippy::let_and_return)]
        let plaintext = ciphertext_copy;

        plaintext
    }
}
