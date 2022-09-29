// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

#[cfg(feature = "std")]
mod stronghold_test_std {

    use iota_stronghold::{procedures::WriteVault, Location, Stronghold};
    use std::error::Error;
    use stronghold_utils::random::{self, variable_bytestring};

    #[cfg(feature = "insecure")]
    use iota_stronghold::procedures::CompareSecret;

    /// Generates a random [`Location`].
    pub fn location() -> Location {
        Location::generic(variable_bytestring(4096), variable_bytestring(4096))
    }

    #[tokio::test]
    #[cfg(feature = "insecure")]
    async fn external_fn_test_access_secrets() -> Result<(), Box<dyn Error>> {
        let stronghold = Stronghold::default();
        let client = stronghold.create_client("client_path")?;

        let expected = random::variable_bytestring(4096);
        let location = location();

        let write_procedure = WriteVault {
            data: expected.clone(),
            location: location.clone(),
        };

        let checking_procedure = CompareSecret { location, expected };

        client.execute_procedure(write_procedure)?;

        // The current impl of `Procedure` only allows `Vec<u8>` as return types, hence the ugly conversion
        // This restriction shall be lifted in the future
        assert!(matches!(client.execute_procedure(checking_procedure)?, v if v[0] >= 1 ));

        Ok(())
    }
}
