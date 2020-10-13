// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::error::P2PResult;
use crate::protocol::{MailboxRequest, MailboxResponse};
#[cfg(feature = "kademlia")]
use core::time::Duration;
#[cfg(feature = "kademlia")]
use libp2p::kad::QueryId;
use libp2p::{
    core::PeerId,
    request_response::{RequestId, ResponseChannel},
};

pub trait CodecContext {
    fn send_request(&mut self, peer_id: PeerId, request: MailboxRequest);

    fn send_response(&mut self, response: MailboxResponse, channel: ResponseChannel<MailboxResponse>);

    #[cfg(feature = "kademlia")]
    fn get_record(&mut self, key_str: String);

    #[cfg(feature = "kademlia")]
    fn put_record_local(
        &mut self,
        key_str: String,
        value_str: String,
        timeout_sec: Option<Duration>,
    ) -> P2PResult<QueryId>;

    fn print_known_peer(&mut self);
}

pub trait Codec {
    fn handle_request_msg(&mut self,
        request: MailboxRequest,
        channel: ResponseChannel<MailboxResponse>,
    );
    fn handle_response_msg(&mut self, response: MailboxResponse, request_id: RequestId);
}
