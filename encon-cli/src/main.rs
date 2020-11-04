use encon::Encryptable;
use encon::Map;
use encon::Password;
use std::env;
use std::fs::File;

enum State {
    Normal,
    Password,
    File,
    Key,
    Value,
}

fn unexpected_arg(arg: &str) {
    usage(format!("Unexpected argument {:?}", arg))
}

fn usage(message: impl Into<String>) {
    let message = message.into();
    if !message.is_empty() {
        eprintln!("{}", message);
    }
    eprintln!(
        "{}",
        r#"encon-cli

Commands:
    seal --file cfg.json --password strongpassword key [value]
    unseal --file cfg.json --password strongpassword [key [value]]
"#
    );

    std::process::exit(1);
}

fn main() {
    let mut cmd = None;
    let mut password = None;
    let mut file_path = None;
    let mut key = None;
    let mut value = None;

    let mut state = State::Normal;
    for arg in env::args() {
        match state {
            State::Normal => match arg.as_str() {
                "-p" | "--password" => state = State::Password,
                "-f" | "--file" => state = State::File,
                "-k" | "--key" => state = State::Key,
                "-v" | "--value" => state = State::Value,
                x if x.starts_with('-') => unexpected_arg(x),
                x => {
                    if cmd.is_none() {
                        match x {
                            "seal" | "unseal" => cmd = Some(arg),
                            _ => unexpected_arg(x),
                        }
                    } else if key.is_none() {
                        key = Some(arg)
                    } else if value.is_none() {
                        value = Some(arg)
                    } else {
                        unexpected_arg(x)
                    }
                }
            },
            State::File => {
                file_path = Some(arg);
                state = State::Normal
            }
            State::Password => {
                password = Some(arg);
                state = State::Normal
            }
            State::Key => {
                key = Some(arg);
                state = State::Normal
            }
            State::Value => {
                value = Some(arg);
                state = State::Normal
            }
        }
    }

    let cmd = cmd.as_deref().unwrap_or_else(|| {
        usage("A command is required");
        unreachable!()
    });

    let password = password.unwrap_or_else(|| {
        env::var("ENCON_PASSWORD").unwrap_or_else(|_| {
            usage("A password must be provided with -p/--password or the ENCON_PASSWORD env var");
            unreachable!()
        })
    });
    let password = Password::new(password);

    let file_path = file_path.unwrap_or_else(|| {
        usage("A file path must be provided with -f/--file");
        unreachable!()
    });

    let file = File::open(&file_path).unwrap_or_else(|err| {
        eprintln!("Failed to open {} for reading.\n    {:?}", file_path, err);
        std::process::exit(1)
    });

    let mut map: Map = match serde_json::from_reader(file) {
        Ok(map) => map,
        Err(err) => {
            eprintln!("Failed to parse/deserialize the JSON file.\n    {:?}", err);
            std::process::exit(1)
        }
    };

    match cmd {
        "seal" => {
            let key = key.unwrap_or_else(|| {
                usage("A key is required for the 'seal' command");
                unreachable!()
            });

            if let Some(value) = value {
                let serde_value: serde_json::Value =
                    if value.starts_with('{') || value.starts_with('"') || value.starts_with('[') {
                        serde_json::from_str(&value).unwrap_or_else(|_| value.clone().into())
                    } else {
                        value.into()
                    };
                map.insert(
                    key.clone(),
                    Encryptable::Plain(serde_value).with_intent_encrypted(),
                );
            } else {
                match map.get_mut(&key.clone()) {
                    Some(item) => {
                        item.intend_encrypted();
                    }
                    None => {
                        eprintln!("The key {:?} doesn't appear in the file, and a value wasn't provided in this command.", key);
                        std::process::exit(1);
                    }
                }
            }

            let out_json = map.to_json_pretty().unwrap();
            match std::fs::write(&file_path, &out_json) {
                Ok(_) => {
                    eprintln!("Wrote updated JSON to {}", file_path);
                }
                Err(err) => {
                    eprintln!(
                        "Failed to write updated JSON to {:?}\n    {:?}",
                        file_path, err
                    );
                    std::process::exit(1);
                }
            }
        }
        "unseal" => {
            if let Some(key) = key {
                match map.get(&key) {
                    Some(enc) => {
                        let result = enc
                            .to_decrypted(&password)
                            .map(|plain| plain.as_plain().unwrap().clone());
                        match result {
                            Ok(plain) => {
                                let json = serde_json::to_string_pretty(&plain).unwrap();
                                println!("{}", json);
                            }
                            Err(encon::DecryptError::LikelyWrongPassword) => {
                                eprintln!("The provided password appears to be incorrect.");
                                std::process::exit(1);
                            }
                            Err(err) => {
                                eprintln!(
                                    "An unexpected error ocurred during decryption:\n    {:#?}",
                                    err
                                );
                            }
                        }
                    }
                    None => {
                        eprintln!("The provided key of {:?} does not exist", key);
                        std::process::exit(1);
                    }
                }
            } else {
                for (_, value) in &mut map {
                    value.intend_plain();
                }

                if let Err(err) = map.apply_all_intents(&password) {
                    eprintln!("Failed to decrypt all keys in the file with the provided password.\n    {:#?}", err);
                    std::process::exit(1);
                }

                match map.to_json_pretty() {
                    Ok(json) => {
                        println!("{}", json);
                    }
                    Err(err) => {
                        eprintln!("Failed to convert Map to JSON:\n    {:#?}", err);
                    }
                }
            }
        }
        other => unreachable!("Unexpected command {:?}", other),
    }
}
