use hpke::Serializable;

use crate::simple_hpke::SimpleHpke;

#[test]
fn simple_verification() {
    let (private, public) = SimpleHpke::generate_key_pair();

    let message = "Hello world!";
    let information = "Session 01";
    let associated = "I am attached to you.";

    let (encaped, cypher, tag) = SimpleHpke::encrypt(
        message.as_bytes(),
        associated.as_bytes(),
        &public.as_bytes(),
        information.as_bytes(),
    );

    let decrypted = SimpleHpke::decrypt(
        &private.as_bytes(),
        &encaped.to_bytes(),
        &cypher,
        associated.as_bytes(),
        &tag.to_bytes(),
        information.as_bytes(),
    );

    let decrypted = String::from_utf8(decrypted).unwrap();

    assert_eq!(decrypted, message)
}
