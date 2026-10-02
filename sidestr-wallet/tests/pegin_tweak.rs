//! The peg-in tweak form as a wallet builds it (`build_pegin_tweak`): one
//! output to the address `sidestr_core::pegtweak::peg_output` derives from
//! the same reveal, no marker; the marker form (`build_pegin`) is unchanged
//! beside it.

use bitcoin::secp256k1::XOnlyPublicKey;
use sidestr_core::document::ChainDocument;
use sidestr_core::marker::op_return_data;
use sidestr_core::pegtweak::{peg_matches, peg_output, PegError, PegReveal};
use sidestr_wallet::pegin::{build_pegin, build_pegin_tweak};
use sidestr_wallet::Error;

fn doc(parent: &str) -> ChainDocument {
    ChainDocument::from_json(&format!(
        r#"{{"id":"sidestr:trial","name":"trial","parent":"{parent}",
  "challenge":"512098b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b","powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "addressPrefix":"trl","genesisTime":1790000000,"refundBlocks":10000,"pegs":[]}}"#
    ))
    .unwrap()
}

fn holders() -> XOnlyPublicKey {
    "98b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b"
        .parse()
        .unwrap()
}

fn refund() -> XOnlyPublicKey {
    "c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88"
        .parse()
        .unwrap()
}

fn side() -> String {
    format!("5120{}", "ab".repeat(32))
}

#[test]
fn tweak_plan_pays_the_address_the_reveal_rebuilds() {
    for (parent, hrp) in [
        ("tbtc4", "tb"),
        ("txbt4", "tb"),
        ("btc", "bc"),
        ("xbt", "bc"),
    ] {
        let chain = doc(parent);
        let p = build_pegin_tweak(
            &chain,
            &"cd".repeat(32),
            &holders(),
            &refund(),
            250_000,
            &side(),
        )
        .unwrap();
        let reveal = PegReveal {
            internal: holders().to_string(),
            refund_key: refund().to_string(),
            refund_blocks: 10_000,
            chain_hash: "cd".repeat(32),
            script: side(),
            extra_leaves: vec![],
        };
        let o = peg_output(&reveal, hrp).unwrap();
        assert_eq!(p.peg_address.to_string(), o.address, "{parent}");
        assert_eq!(p.peg.script_pubkey, o.script());
        assert_eq!(p.reveal(), &o.reveal);
        assert_eq!(p.descriptor(), o.descriptor);
        assert!(peg_matches(p.reveal(), &p.peg.script_pubkey.to_hex_string()).unwrap());
        // one output and no OP_RETURN
        let tx = p.transaction(vec![], None);
        assert_eq!(tx.output.len(), 1);
        assert!(tx
            .output
            .iter()
            .all(|o| op_return_data(&o.script_pubkey).is_none()));
        let send = p.core_send_outputs();
        assert_eq!(send.as_array().unwrap().len(), 1);
        assert_eq!(send[0][p.peg_address.to_string()], "0.00250000");
    }
}

#[test]
fn the_side_script_may_be_an_address_and_the_chain_hash_is_checked() {
    let chain = doc("tbtc4");
    let a = build_pegin_tweak(
        &chain,
        &"cd".repeat(32),
        &holders(),
        &refund(),
        250_000,
        "trl1p4w4tgrem0ultguq3x5zrxe8h7xqdj3wzla0dwskl4sgtkd6pxecqwfk6xg",
    );
    // a bad checksum is a bad destination, as everywhere
    assert!(matches!(a, Err(Error::BadDestination(_))));
    // a good address under the chain's prefix commits to its script, as the hex does
    let script = bitcoin::ScriptBuf::from_hex(&side()).unwrap();
    let address = sidestr_core::address::script_to_address(&script, "trl").unwrap();
    let by_address = build_pegin_tweak(
        &chain,
        &"cd".repeat(32),
        &holders(),
        &refund(),
        250_000,
        &address,
    )
    .unwrap();
    let by_hex = build_pegin_tweak(
        &chain,
        &"cd".repeat(32),
        &holders(),
        &refund(),
        250_000,
        &side(),
    )
    .unwrap();
    assert_eq!(by_address, by_hex);
    let e = build_pegin_tweak(
        &chain,
        "sidestr:trial",
        &holders(),
        &refund(),
        250_000,
        &side(),
    )
    .unwrap_err();
    assert!(matches!(e, Error::PegTweak(PegError::ChainHash)));
    assert!(e.to_string().contains("chain event"));
    assert!(matches!(
        build_pegin_tweak(&chain, &"cd".repeat(32), &holders(), &refund(), 0, &side()),
        Err(Error::BadAmount)
    ));
    assert!(matches!(
        build_pegin_tweak(
            &chain,
            &"cd".repeat(32),
            &holders(),
            &refund(),
            100,
            &side()
        ),
        Err(Error::Dust { .. })
    ));
}

#[test]
fn the_marker_form_is_unchanged_beside_it() {
    let chain = doc("tbtc4");
    let t = build_pegin_tweak(
        &chain,
        &"cd".repeat(32),
        &holders(),
        &refund(),
        250_000,
        &side(),
    )
    .unwrap();
    // the marker form still pays the address it is given and writes its marker
    let m = build_pegin(&chain, &t.peg_address.to_string(), 250_000, &side()).unwrap();
    assert_eq!(m.outputs().len(), 2);
    assert_eq!(m.peg, t.peg);
    assert_eq!(
        hex::encode(op_return_data(&m.marker.script_pubkey).unwrap()),
        hex::encode(
            [
                b"pegin:sidestr:trial:".as_slice(),
                &hex::decode(side()).unwrap()
            ]
            .concat()
        )
    );
}
