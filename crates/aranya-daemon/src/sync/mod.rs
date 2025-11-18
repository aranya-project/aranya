//! Aranya Daemon Syncer, meant for relaying graph information to other peers.
//!
//! # Architecture
//! The syncer is designed around several main types. The [`SyncManager`] does the heavy lifting of
//! managing all services, scheduling concurrent sync tasks, and cleaning up any side effects of
//! those tasks. It's designed to talk to a [`SyncServer`] on the other end which will respond to
//! all requests and messages. It returns a [`SyncHandle`] that is used to tell the manager to do
//! things such as add or remove a peer. All protocol knowledge is handed off to [`SyncProtocol`],
//! which is responsible for filling buffers with serialized data to send. Once a sync task is
//! scheduled, it calls a transport layer defined by [`Transport`] and [`Handler`] which is
//! responsible for sending a request to a given peer, and receiving either a response, or an empty
//! acknowledgement. There's also several "services" for more complex features, such as
//! [`HelloService`] and [`PushService`], which have their own internal loops that then schedule
//! additional sync tasks with the manager.
