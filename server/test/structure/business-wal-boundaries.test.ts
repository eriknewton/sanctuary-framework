// fail-before-exempt: native delivery types and isolated scheduling fixtures are outside server/src.
// Durable delivery and bounded owner schedules remain explicit at composition boundaries.
// W-WAL-STORE
import {expect, it} from "vitest";
import {readFileSync} from "node:fs";
import {resolve, dirname} from "node:path";
import {fileURLToPath} from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../castle-wall-daemon");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");
it("only the WAL mints the adapter delivery token", () => {
  const source = read("src/business_profile/business_wal.rs");
  expect(source).toMatch(/pub struct DeliveryToken\s*\{\s*envelope: Vec<u8>/);
  expect(source).toContain("envelope: &DeliveryToken");
  expect(source).toContain("Result<Option<(BusinessSequence, DeliveryToken)>>");
  expect(source.match(/DeliveryToken\s*\{\s*envelope:/g)?.length).toBe(2); // Declaration and the one WAL mint.
});
it("the trusted sink seal is private and only isolated fixtures can implement it", () => {
  const source = read("src/business_profile/business_wal.rs");
  expect(source).toContain("pub trait TrustedBusinessSink: sink_seal::Sealed + Send");
  expect(source).toContain("mod sink_seal {");
  expect(source).not.toContain("pub mod sink_seal");
  expect(source).toMatch(/#\[cfg\(feature = "test-isolation"\)\]\s*impl<T> Sealed for T/);
});
it("late waves carry one client across repetitions", () => {
  const source = read("tests/support/append_clients.rs");
  const schedule = source.slice(source.indexOf("fn mutation_ownership_survives_refusal_ack_and_forty_late_waves"), source.indexOf("fn drain_slots_roles_operations_and_original_facts_are_correlated"));
  expect(schedule.indexOf("let (mut c, s) = f.drain()")).toBeLessThan(schedule.indexOf("for wave in 0..40"));
  expect(schedule).toContain("late completion cannot revive a closed owner");
});
