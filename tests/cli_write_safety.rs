use maige::{crypto, Store};
use std::collections::BTreeMap;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const PASS: &str = "write-safety-test-passphrase";
const OPERATIONS: &[&[&str]] = &[
    &["var", "set", "NEW", "new-value", "--realm", "dev"],
    &[
        "import",
        "source.env",
        "--realm",
        "dev",
        "--convert",
        "--delete",
    ],
    &[
        "import",
        "source.env",
        "--realm",
        "dev",
        "--convert",
        "--delete",
        "--require-existing",
    ],
];

fn setup() -> (TempDir, Store) {
    let dir = TempDir::new().unwrap();
    let store = Store::new(dir.path().join("store"));
    store.initialize(PASS).unwrap();
    std::fs::write(dir.path().join("source.env"), "NEW=new-value\n").unwrap();
    std::fs::write(dir.path().join("source.env.maige"), "existing conversion\n").unwrap();
    (dir, store)
}

fn run(dir: &TempDir, store: &Store, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maige"))
        .current_dir(dir.path())
        .env("MAIGE_HOME", store.root())
        .env_remove("MAIGE_PASSPHRASE")
        .args(["--passphrase", PASS])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn assert_inputs_preserved(dir: &TempDir) {
    assert_eq!(
        std::fs::read_to_string(dir.path().join("source.env")).unwrap(),
        "NEW=new-value\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("source.env.maige")).unwrap(),
        "existing conversion\n"
    );
}

fn assert_rejected_realm_is_preserved(bytes: &[u8], error: &str) {
    for args in OPERATIONS {
        let (dir, store) = setup();
        std::fs::write(store.realm_path("dev"), bytes).unwrap();
        let output = run(&dir, &store, args);
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert_eq!(std::fs::read(store.realm_path("dev")).unwrap(), bytes);
        assert_inputs_preserved(&dir);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(error), "{args:?}: {stderr}");
        assert!(!stderr.contains("does not exist"), "{stderr}");
    }
}

#[test]
fn failed_writes_preserve_corrupted_realm() {
    assert_rejected_realm_is_preserved(b"corrupted ciphertext", "Failed to decrypt realm");
}

#[test]
fn failed_writes_preserve_realm_encrypted_with_another_key() {
    let encrypted = crypto::encrypt(br#"{"EXISTING":"keep-me"}"#, "different-key").unwrap();
    assert_rejected_realm_is_preserved(encrypted.as_bytes(), "Failed to decrypt realm");
}

#[test]
fn failed_writes_preserve_invalid_realm_json() {
    let encrypted = crypto::encrypt(b"not valid JSON", PASS).unwrap();
    assert_rejected_realm_is_preserved(encrypted.as_bytes(), "Failed to parse realm");
}

#[test]
fn failed_writes_preserve_non_utf8_realm_file() {
    assert_rejected_realm_is_preserved(&[0xff, 0xfe], "Failed to read realm");
}

#[test]
fn failed_writes_report_io_errors_without_claiming_realm_is_missing() {
    for args in OPERATIONS {
        let (dir, store) = setup();
        std::fs::create_dir(store.realm_path("dev")).unwrap();
        let output = run(&dir, &store, args);
        assert!(!output.status.success());
        assert!(store.realm_path("dev").is_dir());
        assert_inputs_preserved(&dir);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Failed to read realm"), "{stderr}");
        assert!(!stderr.contains("does not exist"), "{stderr}");
    }
}

#[test]
fn writes_create_missing_realms_unless_existing_is_required() {
    for args in &OPERATIONS[..2] {
        let (dir, store) = setup();
        let output = run(&dir, &store, args);
        assert!(output.status.success(), "{:?}", output);
        let vars = store.load_realm("dev", PASS).unwrap();
        assert_eq!(vars.get("NEW").unwrap(), "new-value");
    }

    let (dir, store) = setup();
    let output = run(&dir, &store, OPERATIONS[2]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not exist"));
    assert!(!store.realm_path("dev").exists());
    assert_inputs_preserved(&dir);
}

#[test]
fn successful_writes_preserve_existing_variables() {
    for args in OPERATIONS {
        let (dir, store) = setup();
        let mut vars = BTreeMap::new();
        vars.insert("EXISTING".to_string(), "keep-me".to_string());
        vars.insert("NEW".to_string(), "old-value".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();
        let output = run(&dir, &store, args);
        assert!(output.status.success(), "{:?}", output);
        let updated = store.load_realm("dev", PASS).unwrap();
        assert_eq!(updated.len(), 2);
        assert_eq!(updated.get("EXISTING").unwrap(), "keep-me");
        assert_eq!(updated.get("NEW").unwrap(), "new-value");
        if args[0] == "import" {
            assert!(!dir.path().join("source.env").exists());
            assert_eq!(
                std::fs::read_to_string(dir.path().join("source.env.maige")).unwrap(),
                "NEW=maige(\"var:/dev/NEW\")\n"
            );
        }
    }
}
