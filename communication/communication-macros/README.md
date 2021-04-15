# Macros for the stronghold communication library
This library includes a macro for deriving the `ToPermissionVariants<P: VariantPermission>` trait that is required for messages when using the communication actor:
```
pub trait ToPermissionVariants<P: VariantPermission> {
    fn to_permissioned(&self) -> P;
}

pub trait VariantPermission {
    fn permission(&self) -> PermissionValue;
}
```

## Enums
The concept of variant permissions mainly targets enums, in order to enable the restriction of certain enum variants, while allowing others.
The macro creates a `<EnumName>Permission` Version of the enum with each variant only being a Unit without any fields, for this enum then the `VariantPermission` is implemented.
The `PermissionValue` of an enum variant is related to its "position" within the enum.
For example
```
pub enum Request {
    VariantA { inner : u32 },
    VariantB(String),
    VariantC
}
```
will generate

```
impl ToPermissionVariants<RequestPermission> for Request {
    fn to_permission_variants(&self) -> RequestPermission {
        match self {
            Request::VariantA { .. } => RequestPermission::VariantA,
            Request::VariantB(_) => RequestPermission::VariantB,
            Request::VariantC => RequestPermission::VariantC,
        }
    }
}

#[derive(Clone, Debug)]
pub enum RequestPermission {
    VariantA,
    VariantB,
    VariantC
}

impl VariantPermission for RequestPermission {
    fn variant_permission_value(&self) -> PermissionValue {
        let n = match self {
            VariantA => 0,
            VariantB => 1,
            VariantC => 2
        };
        // Only panics for values > 31.
        PermissionValue::new(n).unwrap()
    }
}
```

## Structs and Union
For Structs and Unions, `VariantPermission` is directly implemented with `PermissionValue(1)`, which will automatically also implement `ToPermissionVariants` via blanked implementation.



