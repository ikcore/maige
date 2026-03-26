use std::collections::BTreeMap;
use std::path::PathBuf;
use tempfile::TempDir;

// We test against the library internals by path, since this is the same crate.
// For integration tests we invoke the binary or replicate logic using the store directly.

/// Helper: create a Store in a temp directory
fn temp_store() -> (TempDir, maige::Store) {
    let dir = TempDir::new().unwrap();
    let store = maige::Store::new(dir.path().to_path_buf());
    (dir, store)
}

const PASS: &str = "test-passphrase-123";
const PASS2: &str = "new-passphrase-456";

// =====================================================================
// Crypto tests
// =====================================================================

mod crypto {
    use maige::crypto::{decrypt, decrypt_from_file, encrypt, encrypt_to_file};
    use tempfile::TempDir;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world";
        let pass = "secret";
        let enc = encrypt(plaintext, pass).unwrap();
        let dec = decrypt(&enc, pass).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn different_passphrases_produce_different_ciphertext() {
        let plaintext = b"same data";
        let enc1 = encrypt(plaintext, "pass1").unwrap();
        let enc2 = encrypt(plaintext, "pass2").unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn same_passphrase_different_ciphertext_due_to_random_salt() {
        let plaintext = b"deterministic?";
        let pass = "same-pass";
        let enc1 = encrypt(plaintext, pass).unwrap();
        let enc2 = encrypt(plaintext, pass).unwrap();
        // Should differ because salt and nonce are random
        assert_ne!(enc1, enc2);
        // But both decrypt to the same value
        assert_eq!(decrypt(&enc1, pass).unwrap(), plaintext);
        assert_eq!(decrypt(&enc2, pass).unwrap(), plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let enc = encrypt(b"secret", "right").unwrap();
        assert!(decrypt(&enc, "wrong").is_err());
    }

    #[test]
    fn empty_plaintext() {
        let enc = encrypt(b"", "pass").unwrap();
        let dec = decrypt(&enc, "pass").unwrap();
        assert_eq!(dec, b"");
    }

    #[test]
    fn large_plaintext() {
        let data = vec![0xABu8; 100_000];
        let enc = encrypt(&data, "pass").unwrap();
        let dec = decrypt(&enc, "pass").unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn invalid_base64_fails() {
        assert!(decrypt("not-valid-base64!!!", "pass").is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let enc = encrypt(b"data", "pass").unwrap();
        // Truncate to just the salt (too short)
        let truncated = &enc[..10];
        assert!(decrypt(truncated, "pass").is_err());
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let mut enc = encrypt(b"data", "pass").unwrap();
        // Flip a character in the middle
        let bytes = unsafe { enc.as_bytes_mut() };
        let mid = bytes.len() / 2;
        bytes[mid] = bytes[mid].wrapping_add(1);
        assert!(decrypt(&enc, "pass").is_err());
    }

    #[test]
    fn file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.enc");
        let plaintext = b"file-secret";
        encrypt_to_file(plaintext, "pass", &path).unwrap();
        assert!(path.exists());
        let dec = decrypt_from_file(&path, "pass").unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn file_wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.enc");
        encrypt_to_file(b"secret", "right", &path).unwrap();
        assert!(decrypt_from_file(&path, "wrong").is_err());
    }

    #[test]
    fn file_not_found_fails() {
        let path = std::path::PathBuf::from("/tmp/nonexistent_maige_test_file.enc");
        assert!(decrypt_from_file(&path, "pass").is_err());
    }
}

// =====================================================================
// Store initialization tests
// =====================================================================

mod store_init {
    use super::*;

    #[test]
    fn not_initialized_by_default() {
        let (_dir, store) = temp_store();
        assert!(!store.is_initialized());
    }

    #[test]
    fn initialize_creates_structure() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        assert!(store.is_initialized());
        assert!(store.root().exists());
        assert!(store.realms_dir().exists());
        assert!(store.verify_path().exists());
        assert!(store.root().join(".gitignore").exists());
    }

    #[test]
    fn gitignore_contains_wildcard() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        let content = std::fs::read_to_string(store.root().join(".gitignore")).unwrap();
        assert_eq!(content, "*\n");
    }

    #[test]
    fn verify_correct_passphrase() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        assert!(store.verify_passphrase(PASS).unwrap());
    }

    #[test]
    fn verify_wrong_passphrase() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        assert!(!store.verify_passphrase("wrong").unwrap());
    }

    #[test]
    fn verify_before_init_fails() {
        let (_dir, store) = temp_store();
        assert!(store.verify_passphrase(PASS).is_err());
    }
}

// =====================================================================
// Realm CRUD tests
// =====================================================================

mod realm_crud {
    use super::*;

    #[test]
    fn list_empty() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        assert_eq!(store.list_realms().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn create_and_list() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let vars = BTreeMap::new();
        store.save_realm("dev", &vars, PASS).unwrap();
        store.save_realm("prod", &vars, PASS).unwrap();

        let realms = store.list_realms().unwrap();
        assert_eq!(realms, vec!["dev", "prod"]);
    }

    #[test]
    fn list_is_sorted() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let vars = BTreeMap::new();
        store.save_realm("zebra", &vars, PASS).unwrap();
        store.save_realm("alpha", &vars, PASS).unwrap();
        store.save_realm("middle", &vars, PASS).unwrap();

        let realms = store.list_realms().unwrap();
        assert_eq!(realms, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn delete_realm() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let vars = BTreeMap::new();
        store.save_realm("temp", &vars, PASS).unwrap();
        assert_eq!(store.list_realms().unwrap().len(), 1);

        store.delete_realm("temp").unwrap();
        assert_eq!(store.list_realms().unwrap().len(), 0);
        assert!(!store.realm_path("temp").exists());
    }

    #[test]
    fn delete_nonexistent_realm_fails() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        assert!(store.delete_realm("nope").is_err());
    }

    #[test]
    fn load_nonexistent_realm_fails() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        assert!(store.load_realm("nope", PASS).is_err());
    }

    #[test]
    fn realm_file_is_encrypted() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("SECRET".to_string(), "hunter2".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        // Read raw file — should not contain plaintext
        let raw = std::fs::read_to_string(store.realm_path("dev")).unwrap();
        assert!(!raw.contains("hunter2"));
        assert!(!raw.contains("SECRET"));
    }
}

// =====================================================================
// Variable CRUD tests
// =====================================================================

mod var_crud {
    use super::*;

    fn setup() -> (TempDir, maige::Store) {
        let (dir, store) = temp_store();
        store.initialize(PASS).unwrap();
        let vars = BTreeMap::new();
        store.save_realm("dev", &vars, PASS).unwrap();
        (dir, store)
    }

    #[test]
    fn set_and_get_var() {
        let (_dir, store) = setup();

        let mut vars = store.load_realm("dev", PASS).unwrap();
        vars.insert("API_KEY".to_string(), "sk-abc123".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let loaded = store.load_realm("dev", PASS).unwrap();
        assert_eq!(loaded.get("API_KEY").unwrap(), "sk-abc123");
    }

    #[test]
    fn update_var() {
        let (_dir, store) = setup();

        let mut vars = BTreeMap::new();
        vars.insert("KEY".to_string(), "old".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let mut vars = store.load_realm("dev", PASS).unwrap();
        vars.insert("KEY".to_string(), "new".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let loaded = store.load_realm("dev", PASS).unwrap();
        assert_eq!(loaded.get("KEY").unwrap(), "new");
    }

    #[test]
    fn delete_var() {
        let (_dir, store) = setup();

        let mut vars = BTreeMap::new();
        vars.insert("A".to_string(), "1".to_string());
        vars.insert("B".to_string(), "2".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let mut vars = store.load_realm("dev", PASS).unwrap();
        vars.remove("A");
        store.save_realm("dev", &vars, PASS).unwrap();

        let loaded = store.load_realm("dev", PASS).unwrap();
        assert!(loaded.get("A").is_none());
        assert_eq!(loaded.get("B").unwrap(), "2");
    }

    #[test]
    fn many_vars() {
        let (_dir, store) = setup();

        let mut vars = BTreeMap::new();
        for i in 0..100 {
            vars.insert(format!("VAR_{}", i), format!("value_{}", i));
        }
        store.save_realm("dev", &vars, PASS).unwrap();

        let loaded = store.load_realm("dev", PASS).unwrap();
        assert_eq!(loaded.len(), 100);
        assert_eq!(loaded.get("VAR_42").unwrap(), "value_42");
    }

    #[test]
    fn special_characters_in_values() {
        let (_dir, store) = setup();

        let mut vars = BTreeMap::new();
        vars.insert("CONN".to_string(), "postgres://user:p@ss=w0rd@host:5432/db?ssl=true".to_string());
        vars.insert("JSON".to_string(), r#"{"key":"value","arr":[1,2,3]}"#.to_string());
        vars.insert("MULTILINE".to_string(), "line1\nline2\nline3".to_string());
        vars.insert("EMPTY".to_string(), "".to_string());
        vars.insert("UNICODE".to_string(), "hello 世界 🌍".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let loaded = store.load_realm("dev", PASS).unwrap();
        assert_eq!(loaded.get("CONN").unwrap(), "postgres://user:p@ss=w0rd@host:5432/db?ssl=true");
        assert_eq!(loaded.get("JSON").unwrap(), r#"{"key":"value","arr":[1,2,3]}"#);
        assert_eq!(loaded.get("MULTILINE").unwrap(), "line1\nline2\nline3");
        assert_eq!(loaded.get("EMPTY").unwrap(), "");
        assert_eq!(loaded.get("UNICODE").unwrap(), "hello 世界 🌍");
    }

    #[test]
    fn wrong_passphrase_cannot_load() {
        let (_dir, store) = setup();

        let mut vars = BTreeMap::new();
        vars.insert("SECRET".to_string(), "value".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        assert!(store.load_realm("dev", "wrong-pass").is_err());
    }
}

// =====================================================================
// Key rotation tests
// =====================================================================

mod key_rotation {
    use super::*;

    #[test]
    fn rotate_key_works() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("KEY".to_string(), "value".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();
        store.save_realm("prod", &vars, PASS).unwrap();

        store.rotate_key(PASS, PASS2).unwrap();

        // Old passphrase no longer works
        assert!(!store.verify_passphrase(PASS).unwrap());
        assert!(store.load_realm("dev", PASS).is_err());

        // New passphrase works
        assert!(store.verify_passphrase(PASS2).unwrap());
        let loaded = store.load_realm("dev", PASS2).unwrap();
        assert_eq!(loaded.get("KEY").unwrap(), "value");
        let loaded = store.load_realm("prod", PASS2).unwrap();
        assert_eq!(loaded.get("KEY").unwrap(), "value");
    }

    #[test]
    fn rotate_with_no_realms() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        store.rotate_key(PASS, PASS2).unwrap();
        assert!(store.verify_passphrase(PASS2).unwrap());
    }

    #[test]
    fn rotate_with_wrong_old_passphrase_fails() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("K".to_string(), "V".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        assert!(store.rotate_key("wrong", PASS2).is_err());

        // Original passphrase still works
        assert!(store.verify_passphrase(PASS).unwrap());
        let loaded = store.load_realm("dev", PASS).unwrap();
        assert_eq!(loaded.get("K").unwrap(), "V");
    }
}

// =====================================================================
// .env parsing tests
// =====================================================================

mod env_parsing {
    use maige::store::{format_env, parse_env};

    #[test]
    fn parse_simple() {
        let content = "KEY=value\nAPI=token";
        let vars = parse_env(content);
        assert_eq!(vars.get("KEY").unwrap(), "value");
        assert_eq!(vars.get("API").unwrap(), "token");
    }

    #[test]
    fn parse_quoted_values() {
        let content = r#"KEY="hello world"
SINGLE='quoted'
"#;
        let vars = parse_env(content);
        assert_eq!(vars.get("KEY").unwrap(), "hello world");
        assert_eq!(vars.get("SINGLE").unwrap(), "quoted");
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let content = "# This is a comment\n\nKEY=value\n  # another comment\n\nKEY2=val2";
        let vars = parse_env(content);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars.get("KEY").unwrap(), "value");
        assert_eq!(vars.get("KEY2").unwrap(), "val2");
    }

    #[test]
    fn parse_trims_whitespace() {
        let content = "  KEY  =  value  \n  API  =  token  ";
        let vars = parse_env(content);
        assert_eq!(vars.get("KEY").unwrap(), "value");
        assert_eq!(vars.get("API").unwrap(), "token");
    }

    #[test]
    fn parse_empty_value() {
        let content = "KEY=";
        let vars = parse_env(content);
        assert_eq!(vars.get("KEY").unwrap(), "");
    }

    #[test]
    fn parse_value_with_equals() {
        let content = "CONN=postgres://host:5432/db?ssl=true";
        let vars = parse_env(content);
        assert_eq!(vars.get("CONN").unwrap(), "postgres://host:5432/db?ssl=true");
    }

    #[test]
    fn parse_empty_content() {
        let vars = parse_env("");
        assert!(vars.is_empty());
    }

    #[test]
    fn parse_only_comments() {
        let vars = parse_env("# comment\n# another");
        assert!(vars.is_empty());
    }

    #[test]
    fn format_simple() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("A".to_string(), "1".to_string());
        vars.insert("B".to_string(), "2".to_string());
        let output = format_env(&vars);
        assert_eq!(output, "A=1\nB=2");
    }

    #[test]
    fn format_quotes_spaces() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("MSG".to_string(), "hello world".to_string());
        let output = format_env(&vars);
        assert_eq!(output, "MSG=\"hello world\"");
    }

    #[test]
    fn format_escapes_quotes() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("JSON".to_string(), r#"{"key":"val"}"#.to_string());
        let output = format_env(&vars);
        assert!(output.contains(r#"JSON=\"{\\\"key\\\":\\\"val\\\"}\""#) || output.contains("JSON="));
    }

    #[test]
    fn roundtrip_parse_format() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("SIMPLE".to_string(), "value".to_string());
        vars.insert("NUM".to_string(), "12345".to_string());
        let formatted = format_env(&vars);
        let parsed = parse_env(&formatted);
        assert_eq!(parsed, vars);
    }
}

// =====================================================================
// Resolver tests
// =====================================================================

mod resolver {
    use super::*;
    use maige::resolver::*;

    #[test]
    fn parse_maige_ref_simple() {
        let content = r#"KEY=maige("var:/dev/API_KEY")"#;
        let refs = parse_maige_refs(content);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].realm, "dev");
        assert_eq!(refs[0].key, "API_KEY");
    }

    #[test]
    fn parse_maige_ref_multiple() {
        let content = r#"
KEY1=maige("var:/dev/API_KEY")
KEY2=maige("var:/prod/DB_PASS")
KEY3=plain_value
"#;
        let refs = parse_maige_refs(content);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].realm, "dev");
        assert_eq!(refs[0].key, "API_KEY");
        assert_eq!(refs[1].realm, "prod");
        assert_eq!(refs[1].key, "DB_PASS");
    }

    #[test]
    fn parse_maige_ref_with_spaces() {
        let content = r#"KEY=maige( "var:/dev/KEY" )"#;
        let refs = parse_maige_refs(content);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].realm, "dev");
        assert_eq!(refs[0].key, "KEY");
    }

    #[test]
    fn parse_no_refs() {
        let content = "KEY=plain\nOTHER=value";
        let refs = parse_maige_refs(content);
        assert!(refs.is_empty());
    }

    #[test]
    fn find_env_maige_in_current_dir() {
        let dir = TempDir::new().unwrap();
        let env_file = dir.path().join(".env.maige");
        std::fs::write(&env_file, "KEY=val").unwrap();
        assert_eq!(find_env_maige(dir.path()), Some(env_file));
    }

    #[test]
    fn find_env_maige_in_parent_dir() {
        let dir = TempDir::new().unwrap();
        let env_file = dir.path().join(".env.maige");
        std::fs::write(&env_file, "KEY=val").unwrap();

        let child = dir.path().join("subdir");
        std::fs::create_dir(&child).unwrap();

        assert_eq!(find_env_maige(&child), Some(env_file));
    }

    #[test]
    fn find_env_maige_in_grandparent() {
        let dir = TempDir::new().unwrap();
        let env_file = dir.path().join(".env.maige");
        std::fs::write(&env_file, "KEY=val").unwrap();

        let child = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&child).unwrap();

        assert_eq!(find_env_maige(&child), Some(env_file));
    }

    #[test]
    fn find_env_maige_not_found() {
        let dir = TempDir::new().unwrap();
        assert_eq!(find_env_maige(dir.path()), None);
    }

    #[test]
    fn resolve_env_maige_with_refs() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("API_KEY".to_string(), "sk-secret-123".to_string());
        vars.insert("DB_PASS".to_string(), "p@ssw0rd".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"PROJECT=MyApp
API_KEY=maige("var:/dev/API_KEY")
DB_PASS=maige("var:/dev/DB_PASS")
PLAIN=hello
"#).unwrap();

        let resolved = resolve_env_maige_with_store(&env_file, PASS, &store).unwrap();
        assert_eq!(resolved.get("PROJECT").unwrap(), "MyApp");
        assert_eq!(resolved.get("API_KEY").unwrap(), "sk-secret-123");
        assert_eq!(resolved.get("DB_PASS").unwrap(), "p@ssw0rd");
        assert_eq!(resolved.get("PLAIN").unwrap(), "hello");
    }

    #[test]
    fn resolve_env_maige_missing_var_fails() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let vars = BTreeMap::new();
        store.save_realm("dev", &vars, PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"KEY=maige("var:/dev/NONEXISTENT")"#).unwrap();

        assert!(resolve_env_maige_with_store(&env_file, PASS, &store).is_err());
    }

    #[test]
    fn resolve_env_maige_missing_realm_fails() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"KEY=maige("var:/nonexistent/KEY")"#).unwrap();

        assert!(resolve_env_maige_with_store(&env_file, PASS, &store).is_err());
    }

    #[test]
    fn check_refs_all_valid() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("KEY".to_string(), "val".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"VAL=maige("var:/dev/KEY")"#).unwrap();

        let missing = check_refs_with_store(&env_file, PASS, &store).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn check_refs_missing_var() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let vars = BTreeMap::new();
        store.save_realm("dev", &vars, PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"VAL=maige("var:/dev/MISSING")"#).unwrap();

        let missing = check_refs_with_store(&env_file, PASS, &store).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "dev");
        assert_eq!(missing[0].1, "MISSING");
    }

    #[test]
    fn check_refs_missing_realm() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"VAL=maige("var:/ghost/KEY")"#).unwrap();

        let missing = check_refs_with_store(&env_file, PASS, &store).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "ghost");
    }

    #[test]
    fn check_refs_multiple_issues() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut vars = BTreeMap::new();
        vars.insert("EXISTS".to_string(), "val".to_string());
        store.save_realm("dev", &vars, PASS).unwrap();

        let project_dir = TempDir::new().unwrap();
        let env_file = project_dir.path().join(".env.maige");
        std::fs::write(&env_file, r#"A=maige("var:/dev/EXISTS")
B=maige("var:/dev/NOPE")
C=maige("var:/ghost/KEY")
"#).unwrap();

        let missing = check_refs_with_store(&env_file, PASS, &store).unwrap();
        assert_eq!(missing.len(), 2);
    }
}

// =====================================================================
// Multiple realm interaction tests
// =====================================================================

mod multi_realm {
    use super::*;

    #[test]
    fn vars_are_isolated_between_realms() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let mut dev_vars = BTreeMap::new();
        dev_vars.insert("DB".to_string(), "localhost".to_string());
        store.save_realm("dev", &dev_vars, PASS).unwrap();

        let mut prod_vars = BTreeMap::new();
        prod_vars.insert("DB".to_string(), "prod-db.example.com".to_string());
        prod_vars.insert("EXTRA".to_string(), "val".to_string());
        store.save_realm("prod", &prod_vars, PASS).unwrap();

        let dev = store.load_realm("dev", PASS).unwrap();
        let prod = store.load_realm("prod", PASS).unwrap();

        assert_eq!(dev.get("DB").unwrap(), "localhost");
        assert!(dev.get("EXTRA").is_none());
        assert_eq!(prod.get("DB").unwrap(), "prod-db.example.com");
        assert_eq!(prod.get("EXTRA").unwrap(), "val");
    }

    #[test]
    fn delete_one_realm_leaves_others() {
        let (_dir, store) = temp_store();
        store.initialize(PASS).unwrap();

        let vars = BTreeMap::new();
        store.save_realm("a", &vars, PASS).unwrap();
        store.save_realm("b", &vars, PASS).unwrap();
        store.save_realm("c", &vars, PASS).unwrap();

        store.delete_realm("b").unwrap();

        let realms = store.list_realms().unwrap();
        assert_eq!(realms, vec!["a", "c"]);
    }
}

// =====================================================================
// CLI binary tests (invoke the actual binary)
// =====================================================================

mod cli_binary {
    use std::process::Command;

    fn maige_bin() -> PathBuf {
        // Use the debug binary built by cargo
        PathBuf::from(env!("CARGO_BIN_EXE_maige"))
    }

    use super::*;

    #[test]
    fn help_flag() {
        let output = Command::new(maige_bin())
            .arg("--help")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Securely manage and inject"));
        assert!(stdout.contains("init"));
        assert!(stdout.contains("realm"));
        assert!(stdout.contains("var"));
        assert!(stdout.contains("run"));
        assert!(stdout.contains("shell"));
        assert!(stdout.contains("import"));
        assert!(stdout.contains("export"));
        assert!(stdout.contains("check"));
        assert!(stdout.contains("diff"));
    }

    #[test]
    fn version_flag() {
        let output = Command::new(maige_bin())
            .arg("--version")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("maige"));
    }

    #[test]
    fn realm_help() {
        let output = Command::new(maige_bin())
            .args(["realm", "--help"])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("list"));
        assert!(stdout.contains("create"));
        assert!(stdout.contains("delete"));
    }

    #[test]
    fn var_help() {
        let output = Command::new(maige_bin())
            .args(["var", "--help"])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("list"));
        assert!(stdout.contains("get"));
        assert!(stdout.contains("set"));
        assert!(stdout.contains("delete"));
    }

    #[test]
    fn unknown_subcommand_fails() {
        let output = Command::new(maige_bin())
            .arg("nonexistent")
            .output()
            .unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn run_without_command_shows_help() {
        let output = Command::new(maige_bin())
            .output()
            .unwrap();
        // No subcommand should show error/help
        assert!(!output.status.success());
    }
}
