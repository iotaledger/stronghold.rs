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

use engine::communication::protocol::{Request, Response};
use engine::communication::Codec;
use libp2p::request_response::{RequestId, ResponseChannel};

pub(crate) struct Handler();

impl Codec for Handler {
    fn handle_request_msg(&mut self, request: Request, channel: ResponseChannel<Response>) {
        match request {
            Request::Ping => {
                println!("Received Ping, we will send a Pong back.");
                ctx.send_response(Response::Pong, channel);
            }
            #[cfg(feature = "kademlia")]
            Request::Publish(r) => {
                let duration = Some(Duration::from_secs(r.timeout_sec));
                let query_id = ctx.put_record_local(r.key, r.value, duration);
                if query_id.is_ok() {
                    println!("Successfully stored record.");
                    ctx.send_response(Response::Publish(MessageResult::Success), channel);
                } else {
                    println!("Error storing record: {:?}", query_id.err());
                }
            }
            Request::Message(msg) => {
                println!("Received Message {:?}.", msg);
            }
        }
    }

    fn handle_response_msg(&mut self, response: Response, request_id: RequestId) {
        match response {
            Response::Pong => {
                println!("Received Pong for request {:?}.", request_id);
            }
            #[cfg(feature = "kademlia")]
            Response::Publish(result) => {
                println!("Received Result for publish request {:?}: {:?}.", request_id, result);
            }
        }
    }
}
