use ethers::signers::{LocalWallet, Signer};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_end_to_end_prover_verifier_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let accounts_file = temp_dir.path().join("accounts.txt");
    let proof_file = temp_dir.path().join("proof.json");

    let wallet1 = LocalWallet::new(&mut rand::thread_rng());
    let wallet2 = LocalWallet::new(&mut rand::thread_rng());
    let wallet3 = LocalWallet::new(&mut rand::thread_rng());

    let addresses = vec![
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
        .arg("--private-key")
        .arg(&private_key_hex)
        .arg("--output")
        .arg(&proof_file)
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
        "Proof verification did not pass: {}",
        verifier_stdout
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

    let addresses = vec![
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
        .arg("--private-key")
        .arg(&private_key_hex)
        .arg("--output")
        .arg(&proof_file)
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
        String::from_utf8_lossy(&verifier_output2.stdout)
    );

    let verifier_stderr = String::from_utf8_lossy(&verifier_output2.stderr);
    assert!(
        verifier_stderr.contains("replay") || verifier_stderr.contains("nullifier"),
        "Error should mention replay or nullifier: {}",
        verifier_stderr
    );
}
