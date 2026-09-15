from pathlib import Path

p = Path("csqtt-2.1.9/rust-client/dispatcher.rs")
s = p.read_text()

old = '''    pub fn register(&self, channels: WorkerChannels) {
        let id = channels.id;
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id);
            updated.push(channels.clone());
            interleave_turn_paths(&mut updated);
            Arc::new(updated)
        });
    }
    pub fn unregister(&self, id: usize, incarnation_id: u64) {
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id || worker.incarnation_id != incarnation_id);
            interleave_turn_paths(&mut updated);
            Arc::new(updated)
        });
    }
'''
new = '''    pub fn register(&self, channels: WorkerChannels) {
        let id = channels.id;
        let incarnation_id = channels.incarnation_id;
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id);
            updated.push(channels.clone());
            interleave_turn_paths(&mut updated);
            Arc::new(updated)
        });
        crate::log_error!(
            "[CSQTT DEBUG] worker registered id={} incarnation={} total={}",
            id,
            incarnation_id,
            self.workers.load().len()
        );
    }
    pub fn unregister(&self, id: usize, incarnation_id: u64) {
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id || worker.incarnation_id != incarnation_id);
            interleave_turn_paths(&mut updated);
            Arc::new(updated)
        });
        crate::log_error!(
            "[CSQTT DEBUG] worker unregistered id={} incarnation={} total={}",
            id,
            incarnation_id,
            self.workers.load().len()
        );
    }
'''
if old not in s:
    raise SystemExit("register/unregister block not found")
s = s.replace(old, new, 1)

old = '''    fn dispatch_now(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
        let Some(ticket) = client_perf::measure_sampled(PerfStage::Scheduler, 64, || {
            scheduler.begin(&self.workers, packet.as_slice())
        }) else {
            return;
        };
        let workers = scheduler.workers();
        if let Err(packet) = enqueue_selected_worker(workers, ticket, packet) {
            let _ = replace_oldest_in_selected_queue(workers, ticket, packet);
        }
    }
'''
new = '''    fn dispatch_now(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
        let packet_len = packet.len();
        let worker_count = self.workers.load().len();
        let Some(ticket) = client_perf::measure_sampled(PerfStage::Scheduler, 64, || {
            scheduler.begin(&self.workers, packet.as_slice())
        }) else {
            crate::log_error!(
                "[CSQTT DEBUG] DISPATCH DROP no_workers len={} registered={}",
                packet_len,
                worker_count
            );
            return;
        };
        let workers = scheduler.workers();
        if let Err(packet) = enqueue_selected_worker(workers, ticket, packet) {
            let queue_len = packet.len();
            if replace_oldest_in_selected_queue(workers, ticket, packet).is_err() {
                crate::log_error!(
                    "[CSQTT DEBUG] DISPATCH DROP queue_reject len={} workers={} slot={} class={}",
                    queue_len,
                    workers.len(),
                    ticket.start_slot,
                    ticket.class.index()
                );
            } else {
                crate::log_error!(
                    "[CSQTT DEBUG] DISPATCH forced_replace len={} workers={} slot={} class={}",
                    queue_len,
                    workers.len(),
                    ticket.start_slot,
                    ticket.class.index()
                );
            }
        } else {
            crate::log_error!(
                "[CSQTT DEBUG] DISPATCH queued len={} workers={} slot={} class={}",
                packet_len,
                workers.len(),
                ticket.start_slot,
                ticket.class.index()
            );
        }
    }
'''
if old not in s:
    raise SystemExit("dispatch_now block not found")
s = s.replace(old, new, 1)

p.write_text(s)
print("dispatcher data-plane diagnostics inserted")
