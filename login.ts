import { Hono } from "hono";
import { cors } from "hono/cors";
import { SQL } from "bun";

const db = new SQL(Bun.env.DATABASE_URL!);
const ADMIN_EMAIL = "films@ashiakeyz.com";
const ADMIN_PASSWORD = Bun.env.ADMIN_PASSWORD || "";
const SECRET = Bun.env.TOKEN_SECRET || "";
const RESET_ALLOWED = ["aliqays240@gmail.com", "einolem39@gmail.com"];

function hashPassword(password: string): string {
  return new Bun.CryptoHasher("sha256").update(password + SECRET).digest("base64");
}

function makeToken(email: string): string {
  const hmac = new Bun.CryptoHasher("sha256").update(email + SECRET).digest("base64");
  return Buffer.from(email + "|" + hmac).toString("base64");
}

function safeEqual(a: string, b: string): boolean {
  if (!a || !b) return false;
  const ha = new Bun.CryptoHasher("sha256").update(a).digest();
  const hb = new Bun.CryptoHasher("sha256").update(b).digest();
  return ha.length === hb.length && Buffer.compare(Buffer.from(ha), Buffer.from(hb)) === 0;
}

async function findStudent(email: string) {
  const rows = Array.from(db.query("SELECT id, email, name, password FROM students WHERE email = ?", [email]).all() as any[]);
  return rows[0];
}

const app = new Hono();
app.use("*", cors({ origin: "*", allowMethods: ["GET", "POST", "PUT"] }));

// ===== LOGIN =====
app.post("/api/course/login", async (c) => {
  try {
    const { email, password } = await c.req.json();
    if (!email) return c.json({ message: "Email required" }, 400);
    if (!password) return c.json({ message: "Password required" }, 400);
    const lowerEmail = String(email).trim().toLowerCase();

    // Admin account: one login for student and admin portals
    if (lowerEmail === ADMIN_EMAIL) {
      if (!ADMIN_PASSWORD || !safeEqual(password, ADMIN_PASSWORD)) {
        return c.json({ message: "Invalid password" }, 401);
      }
      return c.json({ token: makeToken(lowerEmail), email: lowerEmail, name: "Admin", isAdmin: true });
    }

    const student = await findStudent(lowerEmail);
    if (!student) return c.json({ message: "Email not found" }, 401);

    if (!student.password) {
      if (RESET_ALLOWED.includes(lowerEmail)) {
        return c.json({ needsPasswordSetup: true, email: lowerEmail, name: student.name || lowerEmail, message: "Please create your password" });
      }
      return c.json({ message: "Email not found" }, 401);
    }

    if (!safeEqual(hashPassword(password), student.password)) {
      return c.json({ message: "Invalid password" }, 401);
    }
    return c.json({ token: makeToken(lowerEmail), email: lowerEmail, name: student.name || lowerEmail });
  } catch (e) {
    console.error("Login error:", e);
    return c.json({ message: "Server error" }, 500);
  }
});

// ===== SET / RESET PASSWORD =====
// Only the two allowed accounts. First-time setup needs no current password.
// Changing an existing password requires the current password.
app.post("/api/course/set-password", async (c) => {
  try {
    const { email, password, currentPassword } = await c.req.json();
    if (!email || !password) return c.json({ message: "Email and password required" }, 400);
    if (String(password).length < 6) return c.json({ message: "Password must be at least 6 characters" }, 400);
    const lowerEmail = String(email).trim().toLowerCase();

    if (!RESET_ALLOWED.includes(lowerEmail)) {
      return c.json({ message: "Password setup is not available for this account" }, 403);
    }

    const student = await findStudent(lowerEmail);
    if (!student) return c.json({ message: "Email not found" }, 404);

    if (student.password) {
      if (!currentPassword || !safeEqual(hashPassword(currentPassword), student.password)) {
        return c.json({ message: "Current password is incorrect" }, 401);
      }
    }

    db.run("UPDATE students SET password = ? WHERE email = ?", [hashPassword(password), lowerEmail]);
    return c.json({ token: makeToken(lowerEmail), email: lowerEmail, name: student.name || lowerEmail, message: "Password set successfully" });
  } catch (e) {
    console.error("Set password error:", e);
    return c.json({ message: "Server error" }, 500);
  }
});

// ===== RETIRED ADMIN ROUTES (passwords in web address; removed) =====
app.all("/admin/*", (c) => c.json({ message: "Not available" }, 410));

app.get("/health", (c) => c.json({ status: "ok" }));

export default { port: Number(Bun.env.PORT || 3000), fetch: app.fetch };
