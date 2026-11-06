use super::*;

fn again(text: &str) -> Result<String, Error> {
    again_within(text, u64::MAX)
}

fn again_within(text: &str, limit: u64) -> Result<String, Error> {
    let mut out = Vec::new();
    let mut work = Work::new(limit);
    write(parse(text.as_bytes())?, &mut out, &mut work)?;
    assert_eq!(work.held(), 0, "{text}");
    Ok(String::from_utf8(out).unwrap())
}

#[test]
fn numbers_are_written_as_javascript_writes_them() {
    for (n, js) in [
        (1.5, "1.5"),
        (-0.0, "0"),
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1.5e300, "1.5e+300"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1.2e-7, "1.2e-7"),
        (-2.5e-8, "-2.5e-8"),
        (5e-324, "5e-324"),
        (0.1 + 0.2, "0.30000000000000004"),
        (18446744073709551615.0, "18446744073709552000"),
        (123456789012345678901.0, "123456789012345680000"),
        (f64::INFINITY, "null"),
        (f64::NAN, "null"),
        // Halfway between two decimals of the fewest digits: the even one,
        // where Rust's shortest form takes the one above.
        (1658206780088562.25, "1658206780088562.2"),
        (-1658206780088562.25, "-1658206780088562.2"),
        (1658206780088562.75, "1658206780088562.8"),
        (140737488355328.125, "140737488355328.12"),
        (1.00000762939453125, "1.0000076293945312"),
        // At a power of two the closest of those digits reads as the
        // double below: the next one up.
        (2f64.powi(-24), "5.960464477539063e-8"),
        (1e23, "1e+23"),
        (9007199254740993.0, "9007199254740992"),
    ] {
        assert_eq!(js_number(n).as_deref(), Some(js), "{n}");
    }
    assert_eq!(
        again("[1e400,-0,9007199254740993,123]").unwrap(),
        "[null,0,9007199254740992,123]"
    );
}

/// Every number of the vectors' number cases, as main wrote it: the
/// halfway cases, the powers of two, the range's ends and thresholds, doubles
/// drawn from every magnitude, 2^53 and its neighbours, `-0`, and the
/// floats and integers. Each through [`js_number`] and through the text's
/// own path ([`write_number`], whose integers of up to 15 digits skip it).
#[test]
fn numbers_are_mains_in_the_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../vectors/radicle-reads.json")).unwrap();
    // The elements of a flat array's text; an object's members split too,
    // the same in both texts, and are skipped.
    let elements = |text: &str| -> Vec<String> {
        let inner = text.strip_prefix('[').unwrap().strip_suffix(']').unwrap();
        inner.split(',').map(str::to_string).collect()
    };
    let (mut checked, mut example) = (0, false);
    for case in vectors["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if !(id.starts_with("remotes-numbers-")
            || id == "remotes-floats"
            || id == "remotes-integers")
        {
            continue;
        }
        let texts = elements(case["addon"][0]["text"].as_str().unwrap());
        let written = elements(case["main"]["body"].as_str().unwrap());
        assert_eq!(texts.len(), written.len(), "{id}");
        for (text, js) in texts.iter().zip(&written) {
            if !text.starts_with(|c: char| c == '-' || c.is_ascii_digit()) {
                continue;
            }
            let n: f64 = text.parse().unwrap();
            assert_eq!(js_number(n).as_deref(), Some(js.as_str()), "{id}: {text}");
            let mut out = Vec::new();
            write_number(text.as_bytes(), &mut out).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), *js, "{id}: {text}");
            example |= text == "1658206780088562.25" && js == "1658206780088562.2";
            checked += 1;
        }
    }
    assert!(example);
    assert_eq!(checked, 512);
}

#[test]
fn strings_are_written_as_javascript_writes_them() {
    // Built here, so no escape in this source is read as its character.
    let bs = '\\';
    let text = format!(
        r#"["{bs}u00e9{bs}/{bs}u0001{bs}u001F{bs}u0008{bs}u007f","{bs}ud83d{bs}ude00","{bs}udc00{bs}ud800x"]"#
    );
    assert_eq!(
        again(&text).unwrap(),
        format!("[\"\u{e9}/{bs}u0001{bs}u001f{bs}b\u{7f}\",\"\u{1f600}\",\"{bs}udc00{bs}ud800x\"]")
    );
    // What serde_json writes, JavaScript writes again as it is.
    let raw = serde_json::to_string(&"\"\\\n\t\u{0}\u{1f}\u{7f}\u{2028}é😀").unwrap();
    assert_eq!(again(&raw).unwrap(), raw);
}

#[test]
fn an_objects_index_keys_come_first_and_a_repeated_key_keeps_its_place() {
    assert_eq!(
        again(r#"{"b":1,"10":2,"a":3,"2":4,"01":5,"4294967295":6,"4294967294":7,"-1":8}"#).unwrap(),
        r#"{"2":4,"10":2,"4294967294":7,"b":1,"a":3,"01":5,"4294967295":6,"-1":8}"#
    );
    assert_eq!(
        again(r#"{"a":1,"b":2,"a":3,"1":4,"1":5}"#).unwrap(),
        r#"{"1":5,"a":3,"b":2}"#
    );
    assert_eq!(again(" { } ").unwrap(), "{}");
}

#[test]
fn a_member_is_read_as_javascript_reads_it() {
    let bs = '\\';
    let text = format!(r#"{{"state":{{"status":"x"}},"n":0,"{bs}u0073tate":{{"status":"open"}}}}"#);
    let value = parse(text.as_bytes()).unwrap();
    let state = value.get("state").unwrap().unwrap();
    assert!(state.get("status").unwrap().unwrap().is_str("open"));
    assert!(!value.get("n").unwrap().unwrap().truthy());
    assert_eq!(value.get("none").unwrap(), None);
    assert_eq!(parse(b"[1]").unwrap().get("0").unwrap(), None);
    for (text, truthy) in [
        ("null", false),
        ("false", false),
        ("0", false),
        ("-0.0", false),
        ("\"\"", false),
        ("true", true),
        ("0.5", true),
        ("\"0\"", true),
        ("[]", true),
        ("{}", true),
    ] {
        assert_eq!(parse(text.as_bytes()).unwrap().truthy(), truthy, "{text}");
    }
}

#[test]
fn parse_int_is_javascripts() {
    for (s, n) in [
        ("42", 42.0),
        ("  \t\u{a0}\u{feff}\u{2028}7x", 7.0),
        ("+3", 3.0),
        ("-5", -5.0),
        ("2.9", 2.0),
        ("1e3", 1.0),
        ("0x10", 0.0),
    ] {
        assert_eq!(parse_int(s), n, "{s:?}");
    }
    assert!(parse_int("-0").is_sign_negative());
    for s in [
        "",
        "abc",
        "\u{85}1",
        "\u{180e}1",
        "\u{200b}1",
        "--1",
        "+-1",
        "Infinity",
    ] {
        assert!(parse_int(s).is_nan(), "{s:?}");
    }
    assert_eq!(parse_int(&"9".repeat(400)), f64::INFINITY);
}

#[test]
fn the_window_is_paginates() {
    assert_eq!(window(None, None), (0.0, 30.0));
    assert_eq!(window(Some(""), Some("")), (0.0, 30.0));
    assert_eq!(window(Some("2"), Some("10")), (20.0, 30.0));
    assert_eq!(window(Some("-3"), Some("0")), (0.0, 30.0));
    assert_eq!(window(Some("1"), Some("-5")), (1.0, 2.0));
    assert_eq!(window(Some("1"), Some("500")), (100.0, 200.0));
    assert_eq!(window(Some("Infinity"), Some("abc")), (0.0, 30.0));
    let (start, _) = window(Some(&"9".repeat(400)), Some("1"));
    assert_eq!(start, f64::INFINITY);
}

#[test]
fn a_page_filters_then_windows() {
    let items = r#"[{"state":{"status":"open"},"n":1},{"state":{"status":"closed"},"n":2},{"state":{"status":"open"},"n":3},null,{"state":{"status":"open"},"n":4}]"#;
    let page_of = |status: Option<&str>, at: &str, per: &str| {
        let mut out = Vec::new();
        page(
            parse(items.as_bytes()).unwrap(),
            status,
            window(Some(at), Some(per)),
            &mut out,
            &mut Work::new(u64::MAX),
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    };
    assert_eq!(
        page_of(Some("open"), "1", "1"),
        r#"[{"state":{"status":"open"},"n":3}]"#
    );
    assert_eq!(
        page_of(Some(""), "1", "2"),
        r#"[{"state":{"status":"open"},"n":3},null]"#
    );
    assert_eq!(page_of(Some("open"), "3", "1"), "[]");
    assert_eq!(page_of(None, "0", "100").matches("\"n\"").count(), 4);
}

#[test]
fn the_working_set_holds_the_members_being_written() {
    // One object of three members, inside one of one.
    let text = r#"{"a":{"x":1,"y":2,"z":3}}"#;
    let cost = 4 * MEMBER;
    assert_eq!(again_within(text, cost).unwrap(), text);
    match again_within(text, cost - 1) {
        Err(Error::TooLarge { size, limit }) => {
            assert_eq!((size, limit), (cost, cost - 1));
        }
        other => panic!("{other:?}"),
    }
    // Siblings are written one after the other: no more than one is held.
    let text = r#"[{"x":1,"y":2},{"x":1,"y":2}]"#;
    assert_eq!(again_within(text, 2 * MEMBER).unwrap(), text);
    assert!(matches!(
        again_within(text, 2 * MEMBER - 1),
        Err(Error::TooLarge { .. })
    ));
    // Nothing for arrays, strings, numbers.
    assert_eq!(again_within("[[1,\"a\"],[]]", 0).unwrap(), "[[1,\"a\"],[]]");
}

#[test]
fn a_text_too_deep_or_not_json_is_refused() {
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert_eq!(again(&deep(DEPTH)).unwrap(), deep(DEPTH));
    assert!(matches!(again(&deep(DEPTH + 1)), Err(Error::Malformed(_))));
    for text in ["", "[1,]", "{\"a\"}", "[1] 2", "\"\u{1}\"", "nul"] {
        assert!(matches!(again(text), Err(Error::Malformed(_))), "{text:?}");
    }
    assert!(matches!(parse(b"\"\xff\""), Err(Error::Malformed(_))));
}

#[test]
fn readme_takes_the_first_candidate() {
    let names = ["readme.md", "README", "README.txt"];
    assert_eq!(readme(names.iter().copied()), Some("README.txt"));
    assert_eq!(readme(["README.MD", "Readme"].iter().copied()), None);
    assert_eq!(readme(std::iter::empty()), None);
}

#[test]
fn splicing_puts_the_path_before_the_brace() {
    let splice = |chunks: &[&[u8]]| {
        let mut out = Vec::new();
        let mut spliced = Spliced::new(&mut out, "README.md");
        for chunk in chunks {
            spliced.write_all(chunk).unwrap();
        }
        spliced.finish().map(|()| String::from_utf8(out).unwrap())
    };
    assert_eq!(
        splice(&[b"{", b"\"binary\":true,\"name\":\"README.md\"", b"}"]).unwrap(),
        r#"{"binary":true,"name":"README.md","path":"README.md"}"#
    );
    assert_eq!(
        splice(&[b"{\"a\":1}"]).unwrap(),
        r#"{"a":1,"path":"README.md"}"#
    );
    for chunks in [
        &[b"[1]".as_slice()][..],
        &[b" {\"a\":1}"],
        &[b"{\"a\":1} "],
        &[],
    ] {
        assert!(matches!(splice(chunks), Err(Error::Malformed(_))));
    }
}
