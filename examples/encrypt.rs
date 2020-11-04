use encon::Encryptable;
use encon::Password;
use serde_json::to_string_pretty;
use std::env;
use std::fmt::Write;

fn main() {
    let plain_text = match env::args().skip(1).next() {
        Some(arg) => arg,
        None => {
            eprintln!("Pass the string to encrypt as the first argument, e.g.");
            eprintln!("cargo run --example encrypt -- 'Hello, world!'");
            std::process::exit(1);
        }
    };
    let pass = Password::new("strongpassword");
    let encrypted = pass.encrypt(&plain_text).unwrap();

    println!("vec![");

    let mut s = String::new();

    for byte in encrypted {
        write!(&mut s, "0x{:02x?}, ", byte).unwrap();
        if s.len() >= 70 {
            println!("    {}", s);
            s = Default::default();
        }
    }

    if !s.is_empty() {
        println!("    {}", s);
    }

    println!("];\n");

    let encryptable = Encryptable::Plain(plain_text.into())
        .to_encrypted(&pass)
        .unwrap();
    let json = to_string_pretty(&encryptable).unwrap();
    println!("{}", json);
}
