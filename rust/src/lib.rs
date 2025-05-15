use uuid::Uuid;

uniffi::setup_scaffolding!();

pub mod mdl;

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