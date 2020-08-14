#!/bin/bash

set -o nounset -o pipefail -o errexit

OUT=README.md

DEFAULT_SNAPSHOT_DIR='~/.engine'
EXECUTABLE=stronghold
PS='>'

cargo build
TARGET="target/debug/$EXECUTABLE"

TMP=$(mktemp -d)
trap 'rm -rf $TMP' EXIT

export STRONGHOLD=$TMP/engine
run_example() {
    cat <<EOF >> "$OUT"
\`\`\`shell
$PS $EXECUTABLE $@
EOF
    $TARGET "$@" 2>&1 | tee -a "$OUT"
    cat <<EOF >> "$OUT"
\`\`\`
EOF
}

cat <<EOF > "$OUT"
# A Stronghold commandline interface

To show off the features of this set of libraries, an MVP command line tool was
created. This CLI is bare bones and based heavily off of the vault fuzz client.
Its main purpose is to show off the libraries in a minimal yet meaningful
manner. The structure of this application follows a kind of server/client
pattern.  The state of the database is maintained in a hashmap wrapped in a
RwLock and an Arc which is globally available via a lazy static macro. On the
frontend, there is a client which contains the client ID and a Vault structure.
The Vault structure contains the client’s key and a data view so that it can
interact with the data. The key implements a provider which inherits from the
box provider trait and this is where the encryption algorithm is defined. The
client and the backend are connected through a simple connection structure with
some basic logic to access the state hashmap.

Unlike the original vault fuzz client, this application needs to upload and
offload its data to and from a snapshot. To achieve this, a snapshot structure
was made; it consists of the client’s id and key as well as the database’s
hashmap. Each time a user runs this CLI they must submit a password to unlock
the snapshot so that the state can be loaded into the application. The id and
key are used to create a new client and a garbage collection operation is
executed to recreate the data chain from the incoming data. This operation
creates a new Initial Transaction and it iterates through each of the
transactions to verify that they are owned by the owner.  Any foreign data is
discarded in this process.

## Installation
Build and install using [cargo](https://doc.rust-lang.org/cargo/):
\`\`\`shell
$PS cargo install --path .
\`\`\`
By default this will install the \`$EXECUTABLE\` executable under the user's cargo
directory: \`~/.cargo/bin/$EXECUTABLE\`, so make sure it's in your \`PATH\`:
\`\`\`shell
$PS export PATH=~/.cargo/bin:\$PATH
\`\`\`
and refer to your shell's manual to make the change permanent
([bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html#Bash-Startup-Files),
[zsh](http://zsh.sourceforge.net/Doc/Release/Files.html#Startup_002fShutdown-Files)).

If you only want to play around without installing anything you can run the
commmandline interface directly:
\`\`\`shell
$PS cargo run -- --help
\`\`\`
That is in the usage examples bellow replace \`$EXECUTABLE\` with \`cargo run --\`
(note however that by default the snapshots will still be saved under the
\`$DEFAULT_SNAPSHOT_DIR\` directory).

## Examples
By default, \`$EXECUTABLE\` will store its snapshots under the \`$DEFAULT_SNAPSHOT_DIR\`
directory. The location can be overridden by setting the \`STRONGHOLD\`
environment variable.

Create a new chain by encrypting some data and get back the unique identifier
of the newly created encrypted record containing our plain-text data:
EOF
ID=$(run_example encrypt --pass foo --plain "secret text")
cat <<EOF >> "$OUT"
(Note that if you haven't/don't want to install the executable you can still
run this as: \`cargo run -- encrypt --pass foo --plain "secret text"\`.)

To read and decrypt the record we use the \`read\` command:
EOF
run_example read --pass foo --id "$ID" > /dev/null

cat <<EOF >> "$OUT"
## Usage
\`\`\`
EOF

$TARGET --help >> "$OUT"

cat <<EOF >> "$OUT"
\`\`\`
EOF

for CMD in "encrypt" "read" "list" "revoke"; do
  echo >> "$OUT"
  echo "### $CMD" >> "$OUT"
  echo '```' >> "$OUT"
  $TARGET "$CMD" --help 2>&1 >> "$OUT"
  echo '```' >> "$OUT"
done
