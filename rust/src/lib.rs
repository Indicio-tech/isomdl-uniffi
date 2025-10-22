use uuid::Uuid;

uniffi::setup_scaffolding!();

pub mod mdl;

// Re-export the simplified API types
pub use mdl::issuer::{MdocIssuer, IssuerError};
pub use mdl::verifier::{MdocVerifier, VerifierError, VerificationResult};
pub use mdl::mdl_issuer::{SimpleMdl, MdlError};

uniffi::custom_type!(Uuid, String);

impl UniffiCustomTypeConverter for Uuid {
    type Builtin = String;
    fn into_custom(val:Self::Builtin) ->  uniffi::Result<Self>where Self: ::std::marker::Sized {
        Ok(val.parse()?)
    }
    fn from_custom(obj:Self) -> Self::Builtin {
        obj.to_string()
    }
}