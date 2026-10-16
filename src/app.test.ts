import { describe, expect, test } from "vitest";
import { authenticate } from "./auth.js";
import { buildApp } from "./app.js";
import { apiKeys, users } from "./store.js";
describe("planted API bugs", () => {
  test.fails("rejects inactive keys", () => {
    expect(authenticate("revoked-token")).toBeNull();
  });
  test("requires authentication for admin users endpoint", async () => {
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/admin/users",
      payload: { role: "admin" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ ok: false });
  });
  test("rejects an inactive API key for admin users endpoint", async () => {
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/admin/users",
      headers: { authorization: "Bearer revoked-token" },
      payload: { role: "admin" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ ok: false });
  });
  test("does not allow a member to grant admin via request body", async () => {
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/admin/users",
      headers: { authorization: "Bearer live-token" },
      payload: { role: "admin" },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ ok: false });
  });
  test("allows an authenticated admin to grant admin", async () => {
    const adminUser = { id: "admin-test", role: "admin", orgId: "org_a" };
    const adminKey = {
      id: "key_admin_test",
      token: "admin-test-token",
      userId: adminUser.id,
      active: true,
    };
    users.push(adminUser);
    apiKeys.push(adminKey);

    try {
      const app = buildApp();
      const res = await app.inject({
        method: "POST",
        url: "/api/admin/users",
        headers: { authorization: "Bearer admin-test-token" },
        payload: { role: "admin" },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ ok: true, granted: "admin" });
    } finally {
      users.splice(users.indexOf(adminUser), 1);
      apiKeys.splice(apiKeys.indexOf(adminKey), 1);
    }
  });
  test("server responds", async () => {
    const app = buildApp();
    const res = await app.inject({ method: "POST", url: "/api/tokens" });
    expect(res.statusCode).toBe(200);
  });
});
