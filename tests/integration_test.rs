use ethers::signers::{LocalWallet, Signer};
use std::fs;
use std::path::PathBuf;
use std::thread;
use tempfile::TempDir;

#[test]
fn test_end_to_end_prover_verifier_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let accounts_file = temp_dir.path().join("accounts.txt");
    let proof_file = temp_dir.path().join("proof.json");

    let wallet1 = LocalWallet::new(&mut rand::thread_rng());
    let wallet2 = LocalWallet::new(&mut rand::thread_rng());
    let wallet3 = LocalWallet::new(&mut rand::thread_rng());

    let addresses = [
        format!("{:x}", wallet1.address()),
        format!("{:x}", wallet2.address()),
        format!("{:x}", wallet3.address()),
    ];

    let accounts_content = addresses.join("\n");
    fs::write(&accounts_file, accounts_content).expect("Failed to write accounts file");

    let private_key_hex = format!("{:x}", wallet1.signer().to_bytes());

    let prover_path = PathBuf::from("./target/release/prover");
    let verifier_path = PathBuf::from("./target/release/verifier");

    if !prover_path.exists() || !verifier_path.exists() {
        eprintln!("Skipping integration test: release binaries not found");
        return;
    }

    let prover_output = std::process::Command::new(&prover_path)
        .arg("--accounts-file")
        .arg(&accounts_file)
        .arg("--output")
        .arg(&proof_file)
        .env("ZKP_PRIVATE_KEY", &private_key_hex)
        .output()
        .expect("Failed to execute prover");

    assert!(
        prover_output.status.success(),
        "Prover failed: {}",
        String::from_utf8_lossy(&prover_output.stderr)
    );

    assert!(proof_file.exists(), "Proof file was not created");

    let verifier_output = std::process::Command::new(&verifier_path)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("Failed to execute verifier");

    assert!(
        verifier_output.status.success(),
        "Verifier failed: {}",
        String::from_utf8_lossy(&verifier_output.stderr)
    );

    let verifier_stdout = String::from_utf8_lossy(&verifier_output.stdout);
    assert!(
        verifier_stdout.contains("Proof verification PASSED"),
        "Proof verification did not pass: {verifier_stdout}"
    );
}

#[test]
fn test_replay_attack_prevention() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let accounts_file = temp_dir.path().join("accounts.txt");
    let proof_file = temp_dir.path().join("proof.json");

    let wallet1 = LocalWallet::new(&mut rand::thread_rng());
    let wallet2 = LocalWallet::new(&mut rand::thread_rng());
    let wallet3 = LocalWallet::new(&mut rand::thread_rng());

    let addresses = [
        format!("{:x}", wallet1.address()),
        format!("{:x}", wallet2.address()),
        format!("{:x}", wallet3.address()),
    ];

    let accounts_content = addresses.join("\n");
    fs::write(&accounts_file, accounts_content).expect("Failed to write accounts file");

    let private_key_hex = format!("{:x}", wallet1.signer().to_bytes());

    let prover_path = PathBuf::from("./target/release/prover");
    let verifier_path = PathBuf::from("./target/release/verifier");

    if !prover_path.exists() || !verifier_path.exists() {
        eprintln!("Skipping integration test: release binaries not found");
        return;
    }

    let prover_output = std::process::Command::new(&prover_path)
        .arg("--accounts-file")
        .arg(&accounts_file)
        .arg("--output")
        .arg(&proof_file)
        .env("ZKP_PRIVATE_KEY", &private_key_hex)
        .output()
        .expect("Failed to execute prover");

    assert!(
        prover_output.status.success(),
        "Prover failed: {}",
        String::from_utf8_lossy(&prover_output.stderr)
    );

    let verifier_output = std::process::Command::new(&verifier_path)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("Failed to execute verifier");

    assert!(
        verifier_output.status.success(),
        "First verification should succeed: {}",
        String::from_utf8_lossy(&verifier_output.stderr)
    );

    let verifier_output2 = std::process::Command::new(&verifier_path)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("Failed to execute verifier second time");

    assert!(
        !verifier_output2.status.success(),
        "Second verification should fail due to replay attack: {}",
        String::from_utf8_lossy(&verifier_output2.stderr)
    );

    let verifier_stderr = String::from_utf8_lossy(&verifier_output2.stderr);
    assert!(
        verifier_stderr.contains("replay") || verifier_stderr.contains("nullifier"),
        "Error should mention replay or nullifier: {verifier_stderr}"
    );
}

#[test]
fn test_large_merkle_tree() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let accounts_file = temp_dir.path().join("large_accounts.txt");
    let proof_file = temp_dir.path().join("proof.json");

    let mut addresses = Vec::new();
    let prover_wallet = LocalWallet::new(&mut rand::thread_rng());
    addresses.push(format!("{:x}", prover_wallet.address()));

    for _ in 0..150 {
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        addresses.push(format!("{:x}", wallet.address()));
    }

    let accounts_content = addresses.join("\n");
    fs::write(&accounts_file, accounts_content).expect("Failed to write accounts file");

    let private_key_hex = format!("{:x}", prover_wallet.signer().to_bytes());

    let prover_path = PathBuf::from("./target/release/prover");
    let verifier_path = PathBuf::from("./target/release/verifier");

    if !prover_path.exists() || !verifier_path.exists() {
        eprintln!("Skipping integration test: release binaries not found");
        return;
    }

    let prover_output = std::process::Command::new(&prover_path)
        .arg("--accounts-file")
        .arg(&accounts_file)
        .arg("--output")
        .arg(&proof_file)
        .env("ZKP_PRIVATE_KEY", &private_key_hex)
        .output()
        .expect("Failed to execute prover");

    assert!(
        prover_output.status.success(),
        "Prover failed: {}",
        String::from_utf8_lossy(&prover_output.stderr)
    );

    let verifier_output = std::process::Command::new(&verifier_path)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("Failed to execute verifier");

    assert!(
        verifier_output.status.success(),
        "Verifier failed: {}",
        String::from_utf8_lossy(&verifier_output.stderr)
    );
}

#[test]
fn test_invalid_proof_structure() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let proof_file = temp_dir.path().join("invalid_proof.json");

    let invalid_json = r#"{
        "merkle_root": "invalid_hex",
        "nullifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "zkp_proof": [1, 2, 3],
        "verification_key": {
            "leaf": "0000000000000000000000000000000000000000000000000000000000000000",
            "root": "0000000000000000000000000000000000000000000000000000000000000000",
            "nullifier": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        "leaf_index": 0,
        "timestamp": 1234567890,
        "merkle_siblings": []
    }"#;

    fs::write(&proof_file, invalid_json).expect("Failed to write invalid proof file");

    let verifier_path = PathBuf::from("./target/release/verifier");

    if !verifier_path.exists() {
        eprintln!("Skipping integration test: release binaries not found");
        return;
    }

    let verifier_output = std::process::Command::new(&verifier_path)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("Failed to execute verifier");

    assert!(
        !verifier_output.status.success(),
        "Verifier should fail on invalid proof structure"
    );
}

#[test]
fn test_duplicate_addresses() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let accounts_file = temp_dir.path().join("duplicate_accounts.txt");
    let proof_file = temp_dir.path().join("proof.json");
    let wallet1 = LocalWallet::new(&mut rand::thread_rng());
    let wallet2 = LocalWallet::new(&mut rand::thread_rng());

    let addresses = [
        format!("{:x}", wallet1.address()),
        format!("{:x}", wallet2.address()),
        format!("{:x}", wallet1.address()),
    ];

    let accounts_content = addresses.join("\n");
    fs::write(&accounts_file, accounts_content).expect("Failed to write accounts file");

    let private_key_hex = format!("{:x}", wallet1.signer().to_bytes());

    let prover_path = PathBuf::from("./target/release/prover");

    if !prover_path.exists() {
        eprintln!("Skipping integration test: release binaries not found");
        return;
    }

    let prover_output = std::process::Command::new(&prover_path)
        .arg("--accounts-file")
        .arg(&accounts_file)
        .arg("--output")
        .arg(&proof_file)
        .env("ZKP_PRIVATE_KEY", &private_key_hex)
        .output()
        .expect("Failed to execute prover");

    assert!(
        !prover_output.status.success(),
        "Prover should fail with duplicate addresses"
    );

    let stderr = String::from_utf8_lossy(&prover_output.stderr);
    assert!(
        stderr.to_lowercase().contains("duplicate"),
        "Error should mention duplicate: {stderr}"
    );
}

#[test]
fn test_concurrent_prover_calls() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let accounts_file = temp_dir.path().join("accounts.txt");
    let proof_file1 = temp_dir.path().join("proof1.json");
    let proof_file2 = temp_dir.path().join("proof2.json");

    let wallet1 = LocalWallet::new(&mut rand::thread_rng());
    let wallet2 = LocalWallet::new(&mut rand::thread_rng());
    let wallet3 = LocalWallet::new(&mut rand::thread_rng());

    let addresses = [
        format!("{:x}", wallet1.address()),
        format!("{:x}", wallet2.address()),
        format!("{:x}", wallet3.address()),
    ];

    let accounts_content = addresses.join("\n");
    fs::write(&accounts_file, accounts_content).expect("Failed to write accounts file");

    let private_key1 = format!("{:x}", wallet1.signer().to_bytes());
    let private_key2 = format!("{:x}", wallet2.signer().to_bytes());

    let prover_path = PathBuf::from("./target/release/prover");

    if !prover_path.exists() {
        eprintln!("Skipping integration test: release binaries not found");
        return;
    }

    let prover_path_clone = prover_path.clone();
    let accounts_file_clone = accounts_file.clone();
    let proof_file1_clone = proof_file1.clone();

    let handle1 = thread::spawn(move || {
        std::process::Command::new(&prover_path)
            .arg("--accounts-file")
            .arg(&accounts_file)
            .arg("--output")
            .arg(&proof_file1_clone)
            .env("ZKP_PRIVATE_KEY", &private_key1)
            .output()
            .expect("Failed to execute prover")
    });

    let proof_file2_clone = proof_file2.clone();

    let handle2 = thread::spawn(move || {
        std::process::Command::new(&prover_path_clone)
            .arg("--accounts-file")
            .arg(&accounts_file_clone)
            .arg("--output")
            .arg(&proof_file2_clone)
            .env("ZKP_PRIVATE_KEY", &private_key2)
            .output()
            .expect("Failed to execute prover")
    });

    let output1 = handle1.join().expect("Thread 1 panicked");
    let output2 = handle2.join().expect("Thread 2 panicked");

    assert!(
        output1.status.success(),
        "Prover 1 failed: {}",
        String::from_utf8_lossy(&output1.stderr)
    );

    assert!(
        output2.status.success(),
        "Prover 2 failed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    assert!(proof_file1.exists());
    assert!(proof_file2.exists());
}
