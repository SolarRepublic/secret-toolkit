use std::u64;

use cosmwasm_std::{to_binary, Binary, CanonicalAddr, Deps, Env, StdError, StdResult, Uint64};
use ripemd::{Digest, Ripemd160};
use secret_toolkit_utils::iso8601_utc0_to_seconds;

use crate::{Permissions, Permit, RevokedPermits, RevokedPermitsStore, AminoSignedPermit, BLANKET_PERMIT_TOKEN, ED25519_PUBLIC_KEY_TYPE, EIP_712_PERMIT_PARAMS_TYPEHASH, MODE_ADR_036, MODE_AMINO, MODE_EIP_712, SECP256K1_PUBLIC_KEY_TYPE};
use bech32::{ToBase32, Variant};
use secret_toolkit_crypto::{keccak_256, secp256k1::{PublicKey, COMPRESSED_PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE}, sha_256, KECCAK256_HASH_SIZE};

pub fn validate<Permission: Permissions>(
    deps: Deps,
    env: &Env,
    permit: &Permit<Permission>,
    current_token_address: String,
    hrp: Option<&str>,
) -> StdResult<String> {
    let account_hrp = hrp.unwrap_or("secret");

    if permit.params.allowed_tokens.contains(&BLANKET_PERMIT_TOKEN.to_string()) {
        // using blanket permit
        
        // assert allowed_tokens list has an exact length of 1
        if permit.params.allowed_tokens.len() != 1 {
            return Err(StdError::generic_err("Blanket permits cannot contain other allowed tokens"));
        }

        // assert created field is specified
        if permit.params.created.is_none() {
            return Err(StdError::generic_err("Blanket permits must have a `created` time"));
        }
    } else if !permit.check_token(&current_token_address) {
        // check that current token address is in allowed tokens
        return Err(StdError::generic_err(format!(
            "Permit doesn't apply to token {:?}, allowed tokens: {:?}",
            current_token_address.as_str(),
            permit
                .params
                .allowed_tokens
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<&str>>()
        )));
    }

    // Convert the permit created field to a Timestamp
    let created_timestamp = permit.params.created.clone()
        .map(|created| 
            iso8601_utc0_to_seconds(&created)
        )
        .transpose()?;

    if let Some(created) = created_timestamp {
        // Verify that the permit was not created after the current block time
        if created > env.block.time.seconds() {
            return Err(StdError::generic_err("Permit `created` after current block time"));
        }
    }

    // Convert the permit expires field to a Timestamp
    let expires_timestamp = permit.params.expires.clone()
        .map(|created| 
            iso8601_utc0_to_seconds(&created)
        )
        .transpose()?;

    // Verify that the permit did not expire before the current block time
    if let Some(expires) = expires_timestamp {
        if expires <= env.block.time.seconds() {
            return Err(StdError::generic_err("Permit has expired"))
        }
    }

    // Get public key value
    let pubkey = &permit.signature.pub_key.value;

    // Derive account from public key based on the number of bytes
    let account = match pubkey.0.len() {
        // public key is 33 bytes
        COMPRESSED_PUBLIC_KEY_SIZE => {
            let base32_addr = pubkey_to_account(pubkey).0.as_slice().to_base32();
            bech32::encode(account_hrp, base32_addr, Variant::Bech32).unwrap()
        }

        // public key is 65 bytes
        PUBLIC_KEY_SIZE => {
            // convert uncompressed public key (65 bytes) to compressed (33 bytes)
            let compressed = PublicKey::parse(&pubkey.0)?.serialize_compressed();
            let base32_addr = pubkey_to_account(&Binary(compressed.into())).0.as_slice().to_base32();
            bech32::encode(account_hrp, base32_addr, Variant::Bech32).unwrap()
        }
        _ => {
            return Err(StdError::generic_err("Public key len is not 33 or 65 bytes"))
        }
    };

    // Get the list of all revocations for this address
    let revocations = RevokedPermits::list_revocations(deps.storage, &account)?;

    // Check if account has an all time permit revocation
    if RevokedPermits::is_all_time_revoked(deps.storage, account.as_str())? {
        return Err(StdError::generic_err(
            format!("Permits revoked by {:?}", account.as_str())
        ));
    }

    // Check if there are any revocation intervals blocking all permits
    //   TODO: An interval or segment tree might be preferable to make this more efficient for cases 
    //         when the number of revocations is allowed to grow to a large amount.
    for revocation in revocations {
        // If the permit has a `created` field
        if let Some(created) = created_timestamp {
            // Revocation created before field, default 0
            let created_before = revocation.interval.created_before.unwrap_or(Uint64::from(0u64));

            // Revocation created after field, default max u64
            let created_after = revocation.interval.created_after.unwrap_or(Uint64::from(u64::MAX));

            // If the permit's `created` field falls in between created after and created before, then reject it
            if created > created_after.u64() || created < created_before.u64() {
                return Err(StdError::generic_err(
                    format!("Permits created at {:?} revoked by account {:?}", created, account.as_str())
                ));                
            }         
        }
    }

    // Validate permit_name
    let permit_name = &permit.params.permit_name;
    let is_permit_revoked =
        RevokedPermits::is_permit_revoked(deps.storage, &account, permit_name);
    if is_permit_revoked {
        return Err(StdError::generic_err(format!(
            "Permit {:?} was revoked by account {:?}",
            permit_name,
            account.as_str()
        )));
    }

    // Signature mode
    let mode = permit.signature.mode.clone().unwrap_or(MODE_AMINO.to_string());

    // Derive the signed bytes hash based on the mode provided
    let signed_bytes_hash = match mode.as_str() {
        MODE_AMINO => {
            // Validate signature, reference: https://github.com/enigmampc/SecretNetwork/blob/f591ed0cb3af28608df3bf19d6cfb733cca48100/cosmwasm/packages/wasmi-runtime/src/crypto/secp256k1.rs#L49-L82
            let signed_bytes = to_binary(&AminoSignedPermit::from_params(&permit.params))?;
            sha_256(signed_bytes.as_slice())
        },
        MODE_EIP_712 => {
            // Create a buffer to store concatenated permission hashes
            let mut concatenated_permission_hashes: Vec<u8> = Vec::with_capacity(permit.params.permissions.len() * KECCAK256_HASH_SIZE);

            for permission in permit.params.permissions.clone() {
                // Serialize each permission to JSON
                let json = serde_json::to_string(&permission).unwrap();

                // Hash the serialized JSON
                let hash = keccak_256(json.as_bytes());

                // Append the hash to the buffer
                concatenated_permission_hashes.extend_from_slice(&hash);
            }

            // Construct permit params hash
            let permit_params_hash = [
                EIP_712_PERMIT_PARAMS_TYPEHASH,
                keccak_256(permit.params.permit_name.as_bytes()),
                keccak_256(&keccak_256(BLANKET_PERMIT_TOKEN.as_bytes())),
                keccak_256(&concatenated_permission_hashes),
                keccak_256(permit.params.created.clone().unwrap_or_default().as_bytes()),
                keccak_256(permit.params.expires.clone().unwrap_or_default().as_bytes()),
            ].concat();

            // Construct permit msg hash
            let permit_msg_hash = [
                keccak_256(permit.params.chain_id.as_bytes()).as_slice(),
                permit_params_hash.as_slice(),
            ].concat();

            sha_256(&permit_msg_hash)
        },
        MODE_ADR_036 => {
            return Err(StdError::generic_err("TODO: ADR-036 signing not implemented"));
        },
        _ => {
            return Err(StdError::generic_err("Invalid signing mode"));
        }
    };

    let verified = match permit.signature.pub_key.r#type.as_str() {
        SECP256K1_PUBLIC_KEY_TYPE => deps
            .api
            .secp256k1_verify(&signed_bytes_hash, &permit.signature.signature.0, &pubkey.0)
            .map_err(|err| StdError::generic_err(err.to_string()))?,
        ED25519_PUBLIC_KEY_TYPE => deps
            .api
            .ed25519_verify(&signed_bytes_hash, &permit.signature.signature.0, &pubkey.0)
            .map_err(|err| StdError::generic_err(err.to_string()))?,
        _ => {
            return Err(StdError::generic_err("Invalid signature public key type"));
        }
    };

    if !verified {
        return Err(StdError::generic_err(
            "Failed to verify signatures for the given permit",
        ));
    }

    Ok(account)
}

pub fn pubkey_to_account(pubkey: &Binary) -> CanonicalAddr {
    let mut hasher = Ripemd160::new();
    hasher.update(sha_256(&pubkey.0));
    CanonicalAddr(Binary(hasher.finalize().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PermitParams, PermitSignature, PubKey, TokenPermissions};
    use cosmwasm_std::{testing::{mock_dependencies, mock_env}, Timestamp};

    #[test]
    fn test_verify_permit() {
        let deps = mock_dependencies();

        //{"permit": {"params":{"chain_id":"pulsar-2","permit_name":"memo_secret1rf03820fp8gngzg2w02vd30ns78qkc8rg8dxaq","allowed_tokens":["secret1rf03820fp8gngzg2w02vd30ns78qkc8rg8dxaq"],"permissions":["history"]},"signature":{"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"A5M49l32ZrV+SDsPnoRv8fH7ivNC4gEX9prvd4RwvRaL"},"signature":"hw/Mo3ZZYu1pEiDdymElFkuCuJzg9soDHw+4DxK7cL9rafiyykh7VynS+guotRAKXhfYMwCiyWmiznc6R+UlsQ=="}}}

        let token = "secret1rf03820fp8gngzg2w02vd30ns78qkc8rg8dxaq".to_string();

        let permit: Permit = Permit{
            params: PermitParams {
                allowed_tokens: vec![token.clone()],
                permit_name: "memo_secret1rf03820fp8gngzg2w02vd30ns78qkc8rg8dxaq".to_string(),
                chain_id: "pulsar-2".to_string(),
                permissions: vec![TokenPermissions::History],
                created: None,
                expires: None,
            },
            signature: PermitSignature {
                pub_key: PubKey {
                    r#type: "tendermint/PubKeySecp256k1".to_string(),
                    value: Binary::from_base64("A5M49l32ZrV+SDsPnoRv8fH7ivNC4gEX9prvd4RwvRaL").unwrap(),

                },
                signature: Binary::from_base64("hw/Mo3ZZYu1pEiDdymElFkuCuJzg9soDHw+4DxK7cL9rafiyykh7VynS+guotRAKXhfYMwCiyWmiznc6R+UlsQ==").unwrap(),
                mode: None,            
            }
        };

        let env = mock_env();

        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        )
        .unwrap();

        assert_eq!(
            address,
            "secret1399pyvvk3hvwgxwt3udkslsc5jl3rqv4yshfrl".to_string()
        );

        let env = mock_env();

        let address = validate::<_>(
            deps.as_ref(), 
            &env, 
            &permit, 
            token, 
            Some("cosmos")
        ).unwrap();

        assert_eq!(
            address,
            "cosmos1399pyvvk3hvwgxwt3udkslsc5jl3rqv4x4rq7r".to_string()
        );
    }

    #[test]
    fn test_verify_permit_created_expires() {
        let deps = mock_dependencies();

        // test both created and expired set

        //{"permit": {"params":{"chain_id":"secret-4","permit_name":"test","allowed_tokens":["secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg"],"permissions":["balance"],"created":"2024-12-17T16:59:00.000Z","expires":"2024-12-20T06:59:30.333Z"},"signature":{"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr"},"signature":"mFDn5w59gaDTHZ5UzEA6l+sUOtlWDx/HcSi1NpZM13YuamMehIi3mseqXcQy4loE63N0hYhyXiVZdzrPM28A+g=="}}}

        let token = "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg".to_string();

        let permit: Permit = Permit{
            params: PermitParams {
                allowed_tokens: vec![token.clone()],
                permit_name: "test".to_string(),
                chain_id: "secret-4".to_string(),
                permissions: vec![TokenPermissions::Balance],
                created: Some("2024-12-17T16:59:00.000Z".to_string()),
                expires: Some("2024-12-20T06:59:30.333Z".to_string()),
            },
            // {"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr"},"signature":"mFDn5w59gaDTHZ5UzEA6l+sUOtlWDx/HcSi1NpZM13YuamMehIi3mseqXcQy4loE63N0hYhyXiVZdzrPM28A+g=="}
            signature: PermitSignature {
                pub_key: PubKey {
                    r#type: "tendermint/PubKeySecp256k1".to_string(),
                    value: Binary::from_base64("AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr").unwrap(),
                },
                signature: Binary::from_base64("mFDn5w59gaDTHZ5UzEA6l+sUOtlWDx/HcSi1NpZM13YuamMehIi3mseqXcQy4loE63N0hYhyXiVZdzrPM28A+g==").unwrap(),
                mode: None,
            }
        };

        let created_seconds: u64 = 1734454740;
        let expires_seconds: u64 = 1734677970;

        // validate after created, before expires

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(created_seconds + 100);

        // secret16v498l7d335wlzxpzg0mwkucrszdlza008dhc9
        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        ).unwrap();

        assert_eq!(
            address,
            "secret16v498l7d335wlzxpzg0mwkucrszdlza008dhc9".to_string()
        );

        // validate before created

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(created_seconds - 100);

        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        );

        assert!(address.is_err(), "validated before created");

        // validate after expires

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(expires_seconds + 100);

        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        );

        assert!(address.is_err(), "validated after expires");

    }

    #[test]
    fn test_verify_blanket_permit() {
        let deps = mock_dependencies();

        // blanket permit

        //{"permit": {"params":{"chain_id":"secret-4","permit_name":"test","allowed_tokens":["ANY_TOKEN"],"permissions":["balance"],"created":"2024-12-17T16:59:00.000Z","expires":"2024-12-20T06:59:30.333Z"},"signature":{"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr"},"signature":"Qte1iS54RsyRCN3rmOjA96yXQTn+eg4YaEUAU/Q5mLVGU9mOCEw6LMZjU2owLB4ogcziWrMkLOL3dtOrj3dL4Q=="}}}

        let token = BLANKET_PERMIT_TOKEN.to_string();

        let permit: Permit = Permit{
            params: PermitParams {
                allowed_tokens: vec![token.clone()],
                permit_name: "test".to_string(),
                chain_id: "secret-4".to_string(),
                permissions: vec![TokenPermissions::Balance],
                created: Some("2024-12-17T16:59:00.000Z".to_string()),
                expires: Some("2024-12-20T06:59:30.333Z".to_string()),
            },
            signature: PermitSignature {
                pub_key: PubKey {
                    r#type: "tendermint/PubKeySecp256k1".to_string(),
                    value: Binary::from_base64("AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr").unwrap(),
                },
                signature: Binary::from_base64("Qte1iS54RsyRCN3rmOjA96yXQTn+eg4YaEUAU/Q5mLVGU9mOCEw6LMZjU2owLB4ogcziWrMkLOL3dtOrj3dL4Q==").unwrap(),
                mode: None,
            }
        };

        let created_seconds: u64 = 1734454740;
        let expires_seconds: u64 = 1734677970;

        // validate after created, before expires

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(created_seconds + 100);

        // secret16v498l7d335wlzxpzg0mwkucrszdlza008dhc9
        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        ).unwrap();

        assert_eq!(
            address,
            "secret16v498l7d335wlzxpzg0mwkucrszdlza008dhc9".to_string()
        );

        // validate before created

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(created_seconds - 100);

        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        );

        assert!(address.is_err(), "validated before created");

        // validate after expires

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(expires_seconds + 100);

        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        );

        assert!(address.is_err(), "validated after expires");

        // blanket permit invalid with another token in addition to ANY_TOKEN

        //{"permit": {"params":{"chain_id":"secret-4","permit_name":"test","allowed_tokens":["secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg","ANY_TOKEN"],"permissions":["balance"],"created":"2024-12-17T16:59:00.000Z","expires":"2024-12-20T06:59:30.333Z"},"signature":{"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr"},"signature":"vc36PM85beBIOmimreAD428O3ldyyUqNHxmzUYlsHaJ+560Ce8G5ibJR7KCvHJitRuds/3TvGX4dPp6l6xfrUg=="}}}

        let token = BLANKET_PERMIT_TOKEN.to_string();

        let permit: Permit = Permit{
            params: PermitParams {
                allowed_tokens: vec!["secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg".to_string(), token.clone()],
                permit_name: "test".to_string(),
                chain_id: "secret-4".to_string(),
                permissions: vec![TokenPermissions::Balance],
                created: Some("2024-12-17T16:59:00.000Z".to_string()),
                expires: Some("2024-12-20T06:59:30.333Z".to_string()),
            },
            signature: PermitSignature {
                pub_key: PubKey {
                    r#type: "tendermint/PubKeySecp256k1".to_string(),
                    value: Binary::from_base64("AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr").unwrap(),
                },
                signature: Binary::from_base64("vc36PM85beBIOmimreAD428O3ldyyUqNHxmzUYlsHaJ+560Ce8G5ibJR7KCvHJitRuds/3TvGX4dPp6l6xfrUg==").unwrap(),
                mode: None,
            }
        };

        let created_seconds: u64 = 1734454740;

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(created_seconds + 100);

        // secret16v498l7d335wlzxpzg0mwkucrszdlza008dhc9
        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        );

        assert!(address.is_err(), "passed with second token in addition to ANY_TOKEN");

        // blanket permit invalid with no created

        //{"permit": {"params":{"chain_id":"secret-4","permit_name":"test","allowed_tokens":["ANY_TOKEN"],"permissions":["balance"],"expires":"2024-12-20T06:59:30.333Z"},"signature":{"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr"},"signature":"k2tdjChWUeIfs63qcHwzUdt1C92gQ5lwvEPS4fv7GpM2geaWGpUsy6Ne+m0pda0AJEpdbiZ38KjiKNlU3CmkOw=="}}}

        let token = BLANKET_PERMIT_TOKEN.to_string();

        let permit: Permit = Permit{
            params: PermitParams {
                allowed_tokens: vec![token.clone()],
                permit_name: "test".to_string(),
                chain_id: "secret-4".to_string(),
                permissions: vec![TokenPermissions::Balance],
                created: None,
                expires: Some("2024-12-20T06:59:30.333Z".to_string()),
            },
            signature: PermitSignature {
                pub_key: PubKey {
                    r#type: "tendermint/PubKeySecp256k1".to_string(),
                    value: Binary::from_base64("AwSFyMndr25JX03rGSlXQ5oSO6F+9GoqQILZu/DytRrr").unwrap(),
                },
                signature: Binary::from_base64("k2tdjChWUeIfs63qcHwzUdt1C92gQ5lwvEPS4fv7GpM2geaWGpUsy6Ne+m0pda0AJEpdbiZ38KjiKNlU3CmkOw==").unwrap(),
                mode: None,
            }
        };

        let created_seconds: u64 = 1734454740;

        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(created_seconds + 100);

        // secret16v498l7d335wlzxpzg0mwkucrszdlza008dhc9
        let address = validate::<_>(
            deps.as_ref(),
            &env,
            &permit,
            token.clone(),
            Some("secret"),
        );

        assert!(address.is_err(), "blanket permit passed with no created field");
    }
}
