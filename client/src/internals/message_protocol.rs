// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// // "imports"
// type RecordId = ();
// type RequestId = ();
// type Error = ();
// type PeerId = ();

// type RecordPayload = (RecordId, Vec<Flag>);
// type Mail = (PeerId, Vec<u8>, Vec<Flag>);

// enum Digest {
//     SHA1,
//     SHA256,
//     // Password-Based Key Derivation Function 1
//     PBKDF1 { salt: Vec<u8>, rounds: u32, derived_key_length: usize }
// }

// // Flag types
// enum Flag {
//     Read,
//     Write,
//     Bucket,
//     Timestamp,
// }

// // Log Commands
// enum LogCommand {
//     Topology,
//     Help,
//     Peers,
//     Whois,
//     Metadata,
//     HelloJoe,
//     HelloRobert,
// }

// // Input Messages
// enum Input {
//     Const(Vec<u8>),
//     Record(RecordPayload),
//     Envelope(Mail),
// }

// enum Destination {
//     Return,
//     Record(Option<RecordId>),
// }

// enum Output {
//     Return(SomeResult),
//     Record(RecordId),
// }

// enum SignaturePayload {
//     DoHash { data: Vec<u8>, digest: Digest },
//     DontHash { data: Vec<u8>, digest: Digest },
// }

// enum Beget {
//     Output(Output),
//     Failed(Error),
// }

// enum ControlRequest {
//     Ping,
//     Status,
//     Procedure(ProcedureRequest),
//     System(LogCommand),
// }

// enum ControlReponse {
//     Pong,
//     Status(StatusResponse),
//     ProcedureResult(SomeResult),
// }

// struct StatusResponse {
//     uptime: u64,
//     version: String,
// }

// struct SignRequest {
//     private_key: Input,
//     payload: SignaturePayload,
// }

// struct SignResponse {
//     public_key: PublicKey,
//     signature: Vec<u8>,
// }

// struct Encrypt {
//     public_key: PublicKey,
//     payload: Input,
// }

// struct EncryptResult {
//     output: Output,
// }

// struct Verify {

// }

// enum VerifyResult {
//     Valid,
//     Rejected,
// }

// struct Entropy {
//     size: usize,
//     quality: EntropyQuality,
// }

// struct EntropyResult {
//     entropy: Vec<u8>,
//     source: String,
// }

// // procedures produce an outcome
// enum Procedure {
//     Sign(SignRequest),
//     Verify(Verify),
//     StoreMail(Mail),
//     Encrypt(EncryptRequest),
//     Digest(Digest),
//     Entropy(Entropy), // うんちを取りました。
// }

// enum Outcome {
//     Sign(SignResult),
//     Verify(VerifyResult),
//     StoreMail(StoreResult),
//     Encrypt(EncryptResponse),// EncryptResult ?
//     Digest(Digested),
//     Entropy(EntropyResult),
// }

// // a request yields a response
// struct Request {
//     originating_peer: PeerId,
//     id: RequestId,
//     set_id: SetId, // global tracking identifier to debug multi-request scenarios
//     procedure: ProcedureRequest,
//     destination: Destination,
// }

// struct Response {
//     id: RequestId,
//     set_id: SetId,
//     outcome: Result<Outcome, ProcedureError>,
// }

// // trait ReqRes<R> {
// //     type Req = Q;
// //     type Res = S;
// // }

// fn handle_sign_request(req: SignRequest) -> SignResponse {
// }

// fn foo() -> u8 { 7 }

// fn main() {
//     let x = {
//         10,
//     };
// }

// ///
// ///
// /// Client -> Request -> Stronghold -> Data -> Another Stronghold || Client || Self
// ///                       | -> Response -> Client
// ///