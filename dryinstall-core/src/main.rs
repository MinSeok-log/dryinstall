extern crate seccomp;
extern crate libc;
use seccomp::*;
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let block_network = args.contains(&"-n".to_string());
    let block_files   = args.contains(&"-f".to_string());
    let filter_env    = args.contains(&"-e".to_string());

    let cmd_args: Vec<&String> = args.iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();

    if cmd_args.is_empty() {
        eprintln!("Usage: dryinstall-core [-n] [-f] [-e] <command> [args]");
        eprintln!("  -n  block network");
        eprintln!("  -f  block filesystem (/etc/passwd, /etc/shadow)");
        eprintln!("  -e  filter environment variables");
        std::process::exit(1);
    }

    println!("[dryinstall-core] Starting sandbox...");
    if block_network { println!("[dryinstall-core] -n network: BLOCKED"); }
    if block_files   { println!("[dryinstall-core] -f filesystem: BLOCKED"); }
    if filter_env    { println!("[dryinstall-core] -e env vars: FILTERED"); }
    println!("---");

    // -f 옵션이면 namespace로 파일 격리
    if block_files {
        let mut full_cmd = format!(
            "mount --bind /dev/null /etc/passwd && \
             mount --bind /dev/null /etc/shadow && \
             {} {}",
            cmd_args[0],
            cmd_args[1..].iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")
        );

        let mut cmd = Command::new("unshare");
        cmd.args(&["--mount", "--pid", "--fork", "bash", "-c", &full_cmd]);
        cmd.env("NODE_OPTIONS",
            "--require /home/vboxuser/dryinstall/dryinstall-core/block-child.js"
        );

        if filter_env {
            cmd.env_clear();
            cmd.env("PATH", env::var("PATH").unwrap_or_default());
            cmd.env("HOME", env::var("HOME").unwrap_or_default());
            cmd.env("NODE_OPTIONS",
                "--require /home/vboxuser/dryinstall/dryinstall-core/block-child.js"
            );
        }

        let block_net = block_network;
        unsafe {
            cmd.pre_exec(move || {
                if block_net {
                    let mut ctx = Context::default(Action::Allow).unwrap();
                    let rule = Rule::new(
                        42,
                        Compare::arg(0).with(0).using(Op::Ge).build().unwrap(),
                        Action::Errno(libc::EPERM),
                    );
                    ctx.add_rule(rule).unwrap();
                    ctx.load().unwrap();
                }
                Ok(())
            });
        }

        let output = cmd.output().unwrap();
        println!("{}", String::from_utf8_lossy(&output.stdout));
        println!("{}", String::from_utf8_lossy(&output.stderr));

    } else {
        // -f 없으면 일반 실행
        let mut cmd = Command::new(cmd_args[0]);
        for arg in &cmd_args[1..] { cmd.arg(arg); }

        cmd.env("NODE_OPTIONS",
            "--require /home/vboxuser/dryinstall/dryinstall-core/block-child.js"
        );

        if filter_env {
            cmd.env_clear();
            cmd.env("PATH", env::var("PATH").unwrap_or_default());
            cmd.env("NODE_OPTIONS",
                "--require /home/vboxuser/dryinstall/dryinstall-core/block-child.js"
            );
        }

        let block_net = block_network;
        unsafe {
            cmd.pre_exec(move || {
                if block_net {
                    let mut ctx = Context::default(Action::Allow).unwrap();
                    let rule = Rule::new(
                        42,
                        Compare::arg(0).with(0).using(Op::Ge).build().unwrap(),
                        Action::Errno(libc::EPERM),
                    );
                    ctx.add_rule(rule).unwrap();
                    ctx.load().unwrap();
                }
                Ok(())
            });
        }

        let output = cmd.output().unwrap();
        println!("{}", String::from_utf8_lossy(&output.stdout));
        println!("{}", String::from_utf8_lossy(&output.stderr));
    }

    println!("---");
    println!("[dryinstall-core] Done");
}
