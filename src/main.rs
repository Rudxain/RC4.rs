use std::{
	fs,
	io::{self, Read, Write},
	process::ExitCode,
};

mod util;
#[allow(clippy::wildcard_imports)]
use util::*;

fn print_help(o: &mut io::StdoutLock) -> Result<(), io::Error> {
	writeln!(
		o,
		"Usage: rc4 <password> <file>\n\
		This program will overwrite the file\n\
		with the RC4-{{en,de}}crypted version of itself.\n\
		If `file` is \"-\", `stdin` will be {{en,de}}crypted to `stdout`"
	)
}

fn main() -> ExitCode {
	let inp = io::stdin().lock();
	let mut out = io::stdout().lock();
	let mut err = io::stderr().lock();
	let mut a = std::env::args_os().skip(1);

	let mut k = RC4Key::new();

	let key = if let Some(k) = a.next() {
		// WARN: this is bad for interop
		k.into_encoded_bytes()
	} else {
		print_help(&mut out).unwrap();
		return ExitCode::FAILURE;
	};
	let Some(file) = a.next() else {
		writeln!(&mut err, "No file!").unwrap();
		print_help(&mut out).unwrap();
		return ExitCode::FAILURE;
	};
	if file == "-" {
		k.init(&key);
		for b in rc4_g(inp.bytes().map(|i| i.unwrap()), &mut k) {
			out.write_all(&[b]).unwrap();
		}
	} else {
		let mut buf = match fs::read(&file) {
			Ok(b) => b,
			Err(e) => {
				writeln!(&mut err, "Failed to read file: {e}").unwrap();
				return ExitCode::FAILURE;
			}
		};
		k.init(&key);
		rc4(&mut buf, &mut k);
		// should this add metadata?
		if let Err(e) = fs::write(file, buf) {
			writeln!(&mut err, "Failed to write file: {e}").unwrap();
			return ExitCode::FAILURE;
		}
	}
	ExitCode::SUCCESS
}
