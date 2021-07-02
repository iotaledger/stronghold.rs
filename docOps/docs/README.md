# Documentation Area
Everything related to IOTA stronghold.

## Run locally
You can run a local server to run the documentation page.

### Dependencies

[mdBook]https://github.com/rust-lang/mdBook is a utility to create modern online books from Markdown files.

```bash
cargo install mdbook
```

### Run it

be sure, you're in the right directory.

```bash
cd docs
mdbook serve
```

Now you can visit `http://localhost:3000`.