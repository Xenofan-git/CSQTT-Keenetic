from pathlib import Path
import re

p = Path("csqtt-2.1.9/rust-client/dispatcher.rs")
s = p.read_text()

if "[CSQTT DEBUG] worker registered" in s:
    print("dispatcher diagnostics already present")
    raise SystemExit(0)

register_pattern = re.compile(
    r"(?ms)^    pub fn register\(&self, channels: WorkerChannels\) \{.*?^    \}\n\n    pub fn unregister\(&self, id: usize, incarnation_id: u64\) \{.*?^    \}\n"
)
register_match = register_pattern.search(s)
if not register_match:
    raise SystemExit("register/unregister block not found")

register_replacement = '''    pub fn register(&self, channels: WorkerChannels) {
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
s = s[:register_match.start()] + register_replacement + s[register_match.end():]

dispatch_pattern = re.compile(
    r"(?ms)^    fn dispatch_now\(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf\) \{.*?^    \}\n\n    \#\[cfg\(unix\)\]"
)
dispatch_match = dispatch_pattern.search(s)
if not dispatch_match:
    raise SystemExit("dispatch_now block not found")

dispatch_replacement = '''    fn dispatch_now(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
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

    #[cfg(unix)]'''
s = s[:dispatch_match.start()] + dispatch_replacement + s[dispatch_match.end():]

p.write_text(s)
print("dispatcher data-plane diagnostics inserted")
