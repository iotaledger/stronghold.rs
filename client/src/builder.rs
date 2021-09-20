// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder Pattern  Macros
//! The main intention of the this builder macro is to provide
//! infrastructure code to provide recursive builder pattern,
//! that returns a specific builder for complex, non-primitive types.
//!
//! For any type annotated with the #[derive(RecursiveBuilder)] macro
//! code will be generated for the current type, inspecting all fields,
//! generating addidional builders, if complex types are present.

use std::path::PathBuf;

#[derive(Default)]
struct Config {
    path: PathConfig,
    id: usize,
}

#[derive(Default)]
struct PathConfig {
    name: Option<String>,
    path: Option<PathBuf>,
}

trait Builder {
    // the parent type
    type P;

    // the target type of the builder
    type T;

    /// Finalizes, constructs and returns the internal object
    fn build(self) -> Self::T;

    /// ends this context and returns the parent context
    /// if this is already the root object, the returned
    /// object will stay the
    fn end(self) -> Self::P;
}

enum BuilderKind {
    PathConfig(PathConfigBuilder),
    Config(ConfigBuilder),
}

impl From<PathConfigBuilder> for BuilderKind {
    fn from(p: PathConfigBuilder) -> Self {
        BuilderKind::PathConfig(p)
    }
}

impl From<ConfigBuilder> for BuilderKind {
    fn from(c: ConfigBuilder) -> Self {
        BuilderKind::Config(c)
    }
}

struct PathConfigBuilder(Option<Box<BuilderKind>>, Option<PathConfig>);

impl PathConfigBuilder {
    pub fn new(parent: Option<Box<BuilderKind>>) -> Self {
        PathConfigBuilder(parent, Some(PathConfig::default()))
    }

    pub fn with_name(mut self, name: String) -> Self {
        let mut path_config = self.1.take().unwrap();
        path_config.name = Some(name);
        self.1 = Some(path_config);

        self
    }

    pub fn with_path(mut self, path: PathBuf) -> Self {
        let mut path_config = self.1.take().unwrap();
        path_config.path = Some(path);
        self.1 = Some(path_config);

        self
    }

    pub fn build(mut self) -> PathConfig {
        self.1.take().unwrap()
    }

    // leaves the current build context, and returns it.
    // if this is the root build context, it will return itself
    pub fn end(self) -> BuilderKind {
        match self.0 {
            Some(ctx) => *ctx,
            None => BuilderKind::PathConfig(self),
        }
    }
}

// container construction stack for storing context the context must be fully
// known at compile time and ideally is wrapped inside an enum
struct ConfigBuilder(Option<Box<BuilderKind>>, Option<Config>);

/// highest level builder struct
impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder(None, Some(Config::default()))
    }

    pub fn with_id(mut self, id: usize) -> Self {
        let mut conf = self.1.take().unwrap();
        conf.id = id;
        self.1 = Some(conf);
        self
    }

    // returns the constructed config so far
    pub fn build(mut self) -> Config {
        self.1.take().unwrap()
    }

    // changes into new path config builder
    pub fn path(self) -> PathConfigBuilder {
        PathConfigBuilder::new(Some(BuilderKind::Config(self).into()))
    }

    // leaves the current build context, and returns it. if this is the root build context,
    // it will return itself
    pub fn end(self) -> BuilderKind {
        match self.0 {
            Some(ctx) => *ctx,
            None => BuilderKind::Config(self),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_builder() {
        let _builder = ConfigBuilder::new();

        // this won't compile, because into() cannot be inferred properly.
        // let config: ConfigBuilder = builder.with_id(1290).path().with_name("name".to_string()).end().into();
    }
}
