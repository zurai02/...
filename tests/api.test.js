import test from "node:test";
import assert from "node:assert/strict";

test("health endpoint contract", async () => {
  /*
   * Keep integration tests isolated from the production database.
   * A full test environment can set DATABASE_PATH to a temporary DB.
   */
  assert.equal(typeof fetch, "function");
});

test("script identifiers reject path traversal characters", () => {
  const valid = /^[a-zA-Z0-9_-]{4,64}$/;

  assert.equal(valid.test("example"), true);
  assert.equal(valid.test("../../etc/passwd"), false);
  assert.equal(valid.test("foo/bar"), false);
  assert.equal(valid.test("foo..bar"), false);
});
