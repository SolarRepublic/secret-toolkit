#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::pubkey_to_account;
use cosmwasm_std::{Binary, CanonicalAddr, Uint128};

pub const BLANKET_PERMIT_TOKEN: &str = "ANY_TOKEN";
pub const REVOKED_ALL: &str = "REVOKED_ALL";

pub const MODE_AMINO: &str = "amino";
pub const MODE_ADR_036: &str = "adr-036";
pub const MODE_EIP_712: &str = "eip-712";

/// EIP-712 permit params typehash
/// PERMIT_PARAMS_TYPEHASH := keccack256("Snip24PermitParams(string permit_name,string[] allowed_tokens,string[] permissions,string created,string expires)")
/// `# ==> 0x156a194f7ab977bb05ec4e69ebb93692100868a082ba66b17131cbab1745ffca`
pub const EIP_712_PERMIT_PARAMS_TYPEHASH: [u8; 32] = [
    0x15, 0x6a, 0x19, 0x4f, 0x7a, 0xb9, 0x77, 0xbb, 0x05, 0xec, 
    0x4e, 0x69, 0xeb, 0xb9, 0x36, 0x92, 0x10, 0x08, 0x68, 0xa0,
    0x82, 0xba, 0x66, 0xb1, 0x71, 0x31, 0xcb, 0xab, 0x17, 0x45,
    0xff, 0xca
];

/// EIP-712 permit msg typehash
/// PERMIT_MSG_TYPEHASH := keccack256("Snip24PermitMsg(string chain_id,Snip24PermitParams)")
/// `# ==> 0xa97869de207379729fdfc6f8d6822524cd2fd88db433fc310f787b0d710ae3c2``
pub const EIP_712_PERMIT_MSG_TYPEHASH: [u8; 32] = [
    0xa9, 0x78, 0x69, 0xde, 0x20, 0x73, 0x79, 0x72, 0x9f, 0xdf,
    0xc6, 0xf8, 0xd6, 0x82, 0x25, 0x24, 0xcd, 0x2f, 0xd8, 0x8d,
    0xb4, 0x33, 0xfc, 0x31, 0x0f, 0x78, 0x7b, 0x0d, 0x71, 0x0a,
    0xe3, 0xc2
];

/// Public key types
pub const SECP256K1_PUBLIC_KEY_TYPE: &str = "tendermint/PubKeySecp256k1";
pub const ED25519_PUBLIC_KEY_TYPE: &str = "tendermint/PubKeyEd25519";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Permit<Permission: Permissions = TokenPermissions> {
    #[serde(bound = "")]
    pub params: PermitParams<Permission>,
    pub signature: PermitSignature,
}

impl<Permission: Permissions> Permit<Permission> {
    pub fn check_token(&self, token: &str) -> bool {
        self.params.allowed_tokens.contains(&token.to_string()) 
    }

    pub fn check_permission(&self, permission: &Permission) -> bool {
        self.params.permissions.contains(permission)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PermitParams<Permission: Permissions = TokenPermissions> {
    pub allowed_tokens: Vec<String>,
    pub permit_name: String,
    pub chain_id: String,
    #[serde(bound = "")]
    pub permissions: Vec<Permission>,
    pub created: Option<String>,
    pub expires: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PermitSignature {
    pub pub_key: PubKey,
    /// either 64-byte or 65-byte (R, S, V) format
    pub signature: Binary,
    /// optional signing mode field:
    /// * `"amino"` the original SNIP-24 sign mode (same as omitting `mode`)
    /// * `"adr-036"` for ADR-036
    /// * `"eip-712"` for EIP-712
    pub mode: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PubKey {
    /// must be "tendermint/PubKeySecp256k1" or "tendermint/PubKeyEd25519" otherwise the verification will fail
    pub r#type: String,
    /// Secp256k1 PubKey or Ed25519 PubKey
    pub value: Binary,
}

impl PubKey {
    pub fn canonical_address(&self) -> CanonicalAddr {
        pubkey_to_account(&self.value)
    }
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct AminoSignedPermit<Permission: Permissions = TokenPermissions> {
    /// ignored
    pub account_number: Uint128,
    /// ignored, no Env in query
    pub chain_id: String,
    /// ignored
    pub fee: Fee,
    /// ignored
    pub memo: String,
    /// the signed message
    #[serde(bound = "")]
    pub msgs: Vec<PermitMsg<Permission>>,
    /// ignored
    pub sequence: Uint128,
}

impl<Permission: Permissions> AminoSignedPermit<Permission> {
    pub fn from_params(params: &PermitParams<Permission>) -> Self {
        Self {
            account_number: Uint128::zero(),
            chain_id: params.chain_id.clone(),
            fee: Fee::new(),
            memo: String::new(),
            msgs: vec![PermitMsg::from_content(PermitContent::from_params(params))],
            sequence: Uint128::zero(),
        }
    }
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas: Uint128,
}

impl Fee {
    pub fn new() -> Self {
        Self {
            amount: vec![Coin::new()],
            gas: Uint128::new(1),
        }
    }
}

impl Default for Fee {
    fn default() -> Self {
        Self::new()
    }
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Coin {
    pub amount: Uint128,
    pub denom: String,
}

impl Coin {
    pub fn new() -> Self {
        Self {
            amount: Uint128::zero(),
            denom: "uscrt".to_string(),
        }
    }
}

impl Default for Coin {
    fn default() -> Self {
        Self::new()
    }
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PermitMsg<Permission: Permissions = TokenPermissions> {
    pub r#type: String,
    #[serde(bound = "")]
    pub value: PermitContent<Permission>,
}

impl<Permission: Permissions> PermitMsg<Permission> {
    pub fn from_content(content: PermitContent<Permission>) -> Self {
        Self {
            r#type: "query_permit".to_string(),
            value: content,
        }
    }
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PermitContent<Permission: Permissions = TokenPermissions> {
    pub allowed_tokens: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(bound = "")]
    pub permissions: Vec<Permission>,
    pub permit_name: String,
}

impl<Permission: Permissions> PermitContent<Permission> {
    pub fn from_params(params: &PermitParams<Permission>) -> Self {
        Self {
            allowed_tokens: params.allowed_tokens.clone(),
            created: params.created.clone(),
            expires: params.expires.clone(),
            permit_name: params.permit_name.clone(),
            permissions: params.permissions.clone(),
        }
    }
}

/// This trait is an alias for all the other traits it inherits from.
/// It does this by providing a blanket implementation for all types that
/// implement the same set of traits
pub trait Permissions:
    Clone + PartialEq + Serialize + for<'d> Deserialize<'d> + JsonSchema
{
}

impl<T> Permissions for T where
    T: Clone + PartialEq + Serialize + for<'d> Deserialize<'d> + JsonSchema
{
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenPermissions {
    /// Allowance for SNIP-20 - Permission to query allowance of the owner & spender
    Allowance,
    /// Balance for SNIP-20 - Permission to query balance
    Balance,
    /// History for SNIP-20 - Permission to query transfer_history & transaction_hisotry
    History,
    /// Owner permission indicates that the bearer of this permit should be granted all
    /// the access of the creator/signer of the permit.  SNIP-721 uses this to grant
    /// viewing access to all data that the permit creator owns and is whitelisted for.
    /// For SNIP-721 use, a permit with Owner permission should NEVER be given to
    /// anyone else.  If someone wants to share private data, they should whitelist
    /// the address they want to share with via a SetWhitelistedApproval tx, and that
    /// address will view the data by creating their own permit with Owner permission
    Owner,
}

/* Example EIP-712 payload

{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "salt", "type": "bytes32" }
    ],
    "Snip24PermitParams": [
      { "name": "permit_name", "type": "string" },
      { "name": "allowed_tokens", "type": "string[]" },
      { "name": "permissions", "type": "string[]" },
      { "name": "created", "type": "string" },
      { "name": "expires", "type": "string" }
    ],
    "Snip24PermitMsg": [
      { "name": "chain_id", "type": "string" },
      { "name": "params", "Snip24PermitParams" }
    ]
  },
  "primaryType": "Snip24PermitMsg",
  "domain": {
    "name": "My App",
    "version": "1",
  },
  "message": {
    "chain_id": "secret-4",
    "params": {
      "permit_name": "my permit",
      "allowed_tokens": ["ANY_TOKEN"],
      "permissions": ["balance"],
      "created": "2025-01-01T00:04:20.691Z"
    }
  }
}

*/