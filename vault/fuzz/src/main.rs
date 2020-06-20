macro_rules! print_status {
    ($data:expr) => {{
        use std::io::{self, Write};
        let mut stdout = io::stdout();
        let _ = stdout.write($data);
        let _ = stdout.flush();
    }};
}

use vault::{DBView, Id, Key, ListResult, ReadResult};

fn main() {
    println!("Hello, world!");
}
