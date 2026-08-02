use anyhow::{bail, Context, Result};
use clap::Args;
use meshlake_core::read_restricted_secret_file;
use std::{
    fmt,
    io::{self, BufRead},
    path::PathBuf,
};
use zeroize::Zeroizing;

pub(crate) enum SecretInput {
    DeprecatedArg(Zeroizing<String>),
    Stdin,
    File(PathBuf),
    HiddenPrompt,
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match self {
            Self::DeprecatedArg(_) => "deprecated argv",
            Self::Stdin => "standard input",
            Self::File(_) => "restricted file",
            Self::HiddenPrompt => "hidden terminal prompt",
        };
        formatter.debug_tuple("SecretInput").field(&source).finish()
    }
}

impl SecretInput {
    pub(crate) fn resolve(self, description: &'static str) -> Result<Zeroizing<String>> {
        let stdin = io::stdin();
        self.resolve_with(description, &mut stdin.lock(), |prompt| {
            rpassword::prompt_password(prompt)
        })
    }

    fn resolve_with<R, P>(
        self,
        description: &'static str,
        stdin: &mut R,
        prompt: P,
    ) -> Result<Zeroizing<String>>
    where
        R: BufRead,
        P: FnOnce(&str) -> io::Result<String>,
    {
        let mut value = match self {
            Self::DeprecatedArg(value) => {
                eprintln!(
                    "WARNING: passing {description} in argv is deprecated; use the corresponding --*-prompt, --*-stdin, or --*-file option"
                );
                value
            }
            Self::Stdin => {
                let mut line = String::new();
                stdin
                    .read_line(&mut line)
                    .with_context(|| format!("cannot read {description} from standard input"))?;
                Zeroizing::new(line)
            }
            Self::File(path) => {
                let bytes = read_restricted_secret_file(&path)
                    .with_context(|| format!("cannot read {description} from restricted file"))?;
                Zeroizing::new(
                    String::from_utf8(bytes.to_vec())
                        .with_context(|| format!("{description} file is not valid UTF-8"))?,
                )
            }
            Self::HiddenPrompt => Zeroizing::new(
                prompt(&format!("{description}: "))
                    .with_context(|| format!("cannot read {description} from terminal"))?,
            ),
        };
        trim_line_ending(&mut value);
        if value.is_empty() {
            bail!("{description} must not be empty");
        }
        Ok(value)
    }
}

fn trim_line_ending(value: &mut String) {
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
}

macro_rules! secret_args {
    (
        $name:ident,
        $group:literal,
        $legacy:ident, $legacy_long:literal,
        $stdin:ident, $stdin_long:literal,
        $file:ident, $file_long:literal,
        $prompt:ident, $prompt_long:literal
    ) => {
        #[derive(Args)]
        #[group(id = $group, required = true, multiple = false)]
        pub(crate) struct $name {
            /// Deprecated: pass the secret through argv.
            #[arg(long = $legacy_long, group = $group, value_name = "SECRET")]
            $legacy: Option<String>,
            /// Read one secret line from standard input.
            #[arg(long = $stdin_long, group = $group)]
            $stdin: bool,
            /// Read the secret from a restricted file.
            #[arg(long = $file_long, group = $group, value_name = "SECRET_FILE")]
            $file: Option<PathBuf>,
            /// Read the secret through a hidden terminal prompt.
            #[arg(long = $prompt_long, group = $group)]
            $prompt: bool,
        }

        impl From<$name> for SecretInput {
            fn from(args: $name) -> Self {
                if let Some(value) = args.$legacy {
                    Self::DeprecatedArg(Zeroizing::new(value))
                } else if args.$stdin {
                    Self::Stdin
                } else if let Some(path) = args.$file {
                    Self::File(path)
                } else if args.$prompt {
                    Self::HiddenPrompt
                } else {
                    unreachable!("clap requires exactly one secret source")
                }
            }
        }
    };
}

secret_args!(
    AdminTokenInputArgs,
    "admin_token_source",
    admin_token,
    "admin-token",
    admin_token_stdin,
    "admin-token-stdin",
    admin_token_file,
    "admin-token-file",
    admin_token_prompt,
    "admin-token-prompt"
);

secret_args!(
    EnrollmentTokenInputArgs,
    "enrollment_token_source",
    token,
    "token",
    token_stdin,
    "token-stdin",
    token_file,
    "token-file",
    token_prompt,
    "token-prompt"
);

secret_args!(
    JoinLinkInputArgs,
    "join_link_source",
    link,
    "link",
    link_stdin,
    "link-stdin",
    link_file,
    "link-file",
    link_prompt,
    "link-prompt"
);

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::create_restricted_secret_file;
    use std::io::Cursor;
    use uuid::Uuid;

    #[test]
    fn stdin_file_and_prompt_sources_resolve_without_debug_disclosure() {
        let secret = "meshlake://join?token=secret-value";
        let mut stdin = Cursor::new(format!("{secret}\n"));
        let value = SecretInput::Stdin
            .resolve_with("join link", &mut stdin, |_| unreachable!())
            .unwrap();
        assert_eq!(value.as_str(), secret);

        let path = std::env::temp_dir().join(format!("meshlake-cli-secret-{}", Uuid::new_v4()));
        create_restricted_secret_file(&path, format!("{secret}\n").as_bytes()).unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let value = SecretInput::File(path.clone())
            .resolve_with("join link", &mut empty, |_| unreachable!())
            .unwrap();
        assert_eq!(value.as_str(), secret);
        std::fs::remove_file(path).unwrap();

        let value = SecretInput::HiddenPrompt
            .resolve_with("join link", &mut empty, |_| Ok(secret.into()))
            .unwrap();
        assert_eq!(value.as_str(), secret);
        assert!(!format!(
            "{:?}",
            SecretInput::DeprecatedArg(Zeroizing::new(secret.into()))
        )
        .contains(secret));
    }
}
