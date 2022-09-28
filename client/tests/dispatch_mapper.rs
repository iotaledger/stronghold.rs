// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code, unused_variables, clippy::type_complexity)]

//! simple prototype to show case enum to function mapping. see tests for more info.

// #[cfg(feature = "p2p")]
mod p2p_module {

    pub use futures::{future::Either, lock::Mutex, SinkExt, StreamExt};
    pub use std::{any::Any, collections::HashMap, mem::Discriminant, sync::Arc};

    enum FNType<S, R, E> {
        FN0(Box<dyn Fn(&S) -> Result<R, E> + Send + Sync>),
        FN1(Box<dyn Fn(&S, Box<dyn Any>) -> Result<R, E> + Send + Sync>),
        FN2(Box<dyn Fn(&S, Box<dyn Any>, Box<dyn Any>) -> Result<R, E> + Send + Sync>),
        FN3(Box<dyn Fn(&S, Box<dyn Any>, Box<dyn Any>, Box<dyn Any>) -> Result<R, E> + Send + Sync>),
    }

    pub trait Request {
        type Return;
        type Data;

        fn execute(&self, data: Self::Data) -> Self::Return;
    }

    #[derive(Hash, PartialEq, Eq, Debug)]
    pub enum RequestData {
        WriteU32 { value: u32, path: String },
        ExecuteProcedure { procedure: String },
    }

    impl RequestData {
        fn get_params(&self) -> Vec<Option<Box<dyn Any>>> {
            match self {
                RequestData::ExecuteProcedure { procedure } => {
                    vec![Some(Box::new(procedure.clone()))]
                }
                RequestData::WriteU32 { value, path } => {
                    vec![Some(Box::new(*value)), Some(Box::new(path.clone()))]
                }
            }
        }
    }

    #[derive(Hash, PartialEq, Eq, Debug)]
    pub enum Response {
        Bool(bool),
        Data(Vec<u8>),
        Number(u64),
        String(String),
        Empty,
    }

    pub enum Procedure {
        GenerateKey,
    }

    // #[rpc(kind = "root", target = "Request")]
    pub struct Engine {
        mapper: HashMap<Discriminant<RequestData>, FNType<Self, Response, String>>,
    }

    impl Engine {
        /// this returns the default mappings for engine
        ///
        /// TODO: this should be done by a macro
        pub fn default() -> Self {
            let mut mapper = HashMap::new();

            mapper.insert(
                std::mem::discriminant(&RequestData::ExecuteProcedure {
                    procedure: "val".to_string(),
                }),
                FNType::FN1(Box::new(|s: &Self, a| s.execute(*a.downcast().unwrap()))),
            );
            mapper.insert(
                std::mem::discriminant(&RequestData::WriteU32 {
                    path: String::new(),
                    value: 0,
                }),
                FNType::FN2(Box::new(|s: &Self, a, b| {
                    s.write_u32_to_path(*a.downcast().unwrap(), *b.downcast().unwrap())
                })),
            );

            Engine { mapper }
        }

        // #[rpc(map = "Request::WriteU32", data = "<value>" , data = "<path>")]
        pub fn write_u32_to_path(&self, value: u32, path: String) -> Result<Response, String> {
            Ok(Response::Number(value as u64))
        }

        // #[rpc(map = "Request::ExecuteProcedure", data = "<procedure>")]
        pub fn execute(&self, procedure: String) -> Result<Response, String> {
            Ok(Response::String(procedure))
        }
    }

    impl Engine {
        pub async fn dispatch(&self, item: RequestData) -> Result<Response, String> {
            match self.mapper.get(&std::mem::discriminant(&item)) {
                Some(inner) => {
                    let mut params = item.get_params();

                    match inner {
                        FNType::FN0(f) => f(self),
                        FNType::FN1(f) => f(self, params[0].take().unwrap()),
                        FNType::FN2(f) => f(self, params[0].take().unwrap(), params[1].take().unwrap()),
                        FNType::FN3(f) => f(
                            self,
                            params[0].take().unwrap(),
                            params[1].take().unwrap(),
                            params[2].take().unwrap(),
                        ),
                    }
                }
                None => Err("No mapping to request found".to_string()),
            }
        }
    }

    pub(crate) enum ServeCommand {
        /// Continue Serving
        Continue,

        /// Terminate Serving
        Terminate,
    }

    pub struct Server {
        tx_request: Arc<Mutex<futures::channel::mpsc::Sender<RequestData>>>,
        rx_request: Arc<Mutex<futures::channel::mpsc::Receiver<RequestData>>>,
        tx_response: Arc<Mutex<futures::channel::mpsc::Sender<Response>>>,
        rx_response: Arc<Mutex<futures::channel::mpsc::Receiver<Response>>>,
        engine: Engine,
    }

    impl Server {
        pub fn new(engine: Engine) -> Self {
            let (tx_request, rx_request) = futures::channel::mpsc::channel(1);
            let (tx_response, rx_response) = futures::channel::mpsc::channel(1);
            Server {
                tx_request: Arc::new(Mutex::new(tx_request)),
                rx_request: Arc::new(Mutex::new(rx_request)),
                tx_response: Arc::new(Mutex::new(tx_response)),
                rx_response: Arc::new(Mutex::new(rx_response)),
                engine,
            }
        }

        pub async fn run(&self, mut terminate: futures::channel::mpsc::Receiver<()>) -> Result<(), String> {
            loop {
                match futures::future::select(
                    Box::pin(async {
                        terminate.next().await;
                        ServeCommand::Terminate
                    }),
                    Box::pin(async {
                        let mut rx = self.rx_request.lock().await;
                        if let Some(inner) = rx.next().await {
                            let result = self.engine.dispatch(inner).await;
                            let mut response = self.tx_response.lock().await;
                            response.send(result.unwrap()).await.expect("Cannot send response");
                        }
                        ServeCommand::Continue
                    }),
                )
                .await
                {
                    Either::Left((cmd, _)) | Either::Right((cmd, _)) => {
                        if let ServeCommand::Terminate = cmd {
                            return Ok(());
                        }
                    }
                }
            }
        }

        pub async fn request(&self, request: RequestData) -> Result<Response, String> {
            let mut tx = self.tx_request.lock().await;
            let mut response = self.rx_response.lock().await;
            tx.send(request).await.expect("Failed to send request");

            Ok(response.next().await.unwrap())
        }
    }
}
// --------- tests ---------

#[cfg(feature = "p2p")]
use p2p_module::*;

#[cfg(feature = "p2p")]
#[test]
fn test_enum_map() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .build()
        .expect("failed to create runtime");
    rt.block_on(async {
        let (mut term_tx, term_rx) = futures::channel::mpsc::channel(1);

        let server = Arc::new(Server::new(Engine::default()));
        let server2 = server.clone();

        let handle = tokio::spawn(async move { server2.run(term_rx).await });

        let response = server
            .request(RequestData::WriteU32 {
                path: "hello, world".to_owned(),
                value: 12345678,
            })
            .await;

        assert!(response.is_ok(), "Failed to get response: {:?}", response);
        assert_eq!(response.unwrap(), Response::Number(12345678u64));

        // shut down server
        term_tx.send(()).await.expect("Failed to send termination signal");

        let result = handle.await.expect("");
        assert!(result.is_ok(), "Termination was not successful");
    })
}
