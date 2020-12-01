use riker::actors::*;

use crate::hd::{Key, Seed};

#[derive(Debug, Clone)]
pub enum RMsg {}

pub struct Runtime {}

impl ActorFactory for Runtime {
    fn create() -> Self {
        Runtime {}
    }
}

impl Actor for Runtime {
    type Msg = RMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<RMsg> for Runtime {
    type Msg = RMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {}
}
