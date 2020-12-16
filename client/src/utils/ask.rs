// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::sync::{Arc, Mutex};

use futures::{
    channel::oneshot::{channel, Sender as ChannelSender},
    future::RemoteHandle,
    FutureExt,
};

pub fn ask<Msg, Ctx, R, T>(ctx: &Ctx, receiver: &T, msg: Msg) -> RemoteHandle<R>
where
    Msg: Message,
    R: Message,
    Ctx: TmpActorRefFactory + Run,
    T: Tell<Msg>,
{
    let (tx, rx) = channel::<R>();
    let tx = Arc::new(Mutex::new(Some(tx)));

    let props = Props::new_from_args(Box::new(AskActor::boxed), tx);
    let actor = ctx.tmp_actor_of_props(props).unwrap();
    receiver.tell(msg, Some(actor.into()));

    ctx.run(rx.map(|r| r.unwrap())).unwrap()
}

struct AskActor<Msg> {
    tx: Arc<Mutex<Option<ChannelSender<Msg>>>>,
}

impl<Msg: Message> AskActor<Msg> {
    fn boxed(tx: Arc<Mutex<Option<ChannelSender<Msg>>>>) -> BoxActor<Msg> {
        let ask = AskActor { tx };
        Box::new(ask)
    }
}

impl<Msg: Message> Actor for AskActor<Msg> {
    type Msg = Msg;

    fn recv(&mut self, ctx: &Context<Msg>, msg: Msg, _: Sender) {
        if let Ok(mut tx) = self.tx.lock() {
            tx.take().unwrap().send(msg).unwrap();
        }
        ctx.stop(&ctx.myself);
    }
}
