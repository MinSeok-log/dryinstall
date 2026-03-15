use napi_derive::napi;
use std::process::Command;

#[napi]
pub fn sandbox_run(
    command: String,
    args: Vec<String>,
    block_network: bool,
    block_files: bool,
    filter_env: bool,
) -> String {
    let mut result = format!(
        "[dryinstall-core] sandbox: -n={} -f={} -e={}\n",
        block_network, block_files, filter_env
    );

    // 절대 경로로 바이너리 지정
    let binary = "/home/vboxuser/dryinstall/dryinstall-core/target/release/dryinstall-core";

    let mut flags: Vec<&str> = vec![];
    if block_network { flags.push("-n"); }
    if block_files   { flags.push("-f"); }
    if filter_env    { flags.push("-e"); }

    let output = Command::new(binary)
        .args(&flags)
        .arg(&command)
        .args(&args)
        .output();

    match output {
        Ok(o) => {
            result.push_str(&String::from_utf8_lossy(&o.stdout));
            result.push_str(&String::from_utf8_lossy(&o.stderr));
        }
        Err(e) => {
            result.push_str(&format!("Error: {}", e));
        }
    }

    result
}
