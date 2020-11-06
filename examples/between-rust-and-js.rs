use encon::Password;
use std::process::Command;
use std::process::Stdio;

type Error = Box<dyn std::error::Error>;

fn basic_cli(command: &str, password: &str, arg: &str) -> Result<String, Error> {
    let mut cmd = Command::new("node");
    cmd.arg("encon-js/src/basic-cli.js");
    cmd.arg(command);
    cmd.arg(password);
    cmd.arg(arg);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    let desc = format!("node basic-cli.js {} {} {}", command, password, arg);
    eprintln!("Running '{}'", desc);
    let output = cmd.output()?;

    if !output.status.success() {
        Err(format!("Command '{}' failed.", desc))?;
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn main() -> Result<(), Error> {
    static PASS: &str = "strongpassword";
    static PLAIN: &str = "Hello, world!";
    let pass = Password::new(PASS);

    eprintln!("Running basic-cli.js encrypt");
    let output = basic_cli("encrypt", PASS, PLAIN)?;
    println!("Output: {}", &output);

    let bytes = hex::decode(output.trim())?;

    let decrypted = pass.decrypt(bytes)?;
    let decrypted = String::from_utf8_lossy(&decrypted);

    eprintln!("Rust decrypted to: {:?}", decrypted);
    assert_eq!(decrypted.as_ref(), PLAIN);

    eprintln!("Encrypting in Rust...");
    let bytes = pass.encrypt(PLAIN)?;
    let hex = hex::encode(&bytes);
    eprintln!("Running basic-cli.js decrypt");
    let output = basic_cli("decrypt", PASS, &hex)?;
    eprintln!("Output: {:?}", output);
    assert_eq!(output.trim(), PLAIN);

    Ok(())
}
