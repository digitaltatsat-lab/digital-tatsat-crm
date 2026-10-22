
const express = require("express");
const WebSocket = require("ws");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");

const app = express();
app.use(express.json({ limit: "300kb" }));

const COOKIE_NAME = "dt_crm_session";

const SOURCES = [
  "Manual",
  "Meta Ads",
  "Google Ads",
  "Website",
  "WhatsApp",
  "Google Business Profile",
  "Referral",
  "Cold Calling",
  "Other"
];

// SUPABASE CONNECTION

function getSupabase(token) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;

  if (!url || !key) {
    throw new Error("Supabase configuration missing");
  }

  const options = {
    realtime: { transport: WebSocket },
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  };

  if (token) {
    options.global = {
      headers: {
        Authorization: `Bearer ${token}`
      }
    };
  }

  return createClient(url, key, options);
}

// SESSION MANAGEMENT

function getSessionToken(req) {
  const item = (req.headers.cookie || "")
    .split(";")
    .map(s => s.trim())
    .find(s => s.startsWith(COOKIE_NAME + "="));

  if (!item) return null;

  try {
    return decodeURIComponent(
      item.slice(COOKIE_NAME.length + 1)
    );
  } catch {
    return null;
  }
}

function clearSession(res) {
  res.clearCookie(COOKIE_NAME, {
    path: "/",
    secure: true,
    sameSite: "lax",
    httpOnly: true
  });
}

// VERIFY ADMIN

async function verifyAdmin(req, res, next) {
  try {
    const token = getSessionToken(req);

    if (!token) {
      return req.path.startsWith("/api/")
        ? res.status(401).json({
            error: "Please log in again."
          })
        : res.redirect("/login");
    }

    const supabase = getSupabase(token);

    const { data: userData, error: userError } =
      await supabase.auth.getUser(token);

    if (userError || !userData.user) {
      clearSession(res);

      return req.path.startsWith("/api/")
        ? res.status(401).json({
            error: "Session expired. Please log in."
          })
        : res.redirect("/login");
    }

    const { data: roleData, error: roleError } =
      await supabase
        .from("crm_user_roles")
        .select("role")
        .eq("user_id", userData.user.id)
        .single();

    if (roleError || roleData?.role !== "admin") {
      return req.path.startsWith("/api/")
        ? res.status(403).json({
            error: "Admin permission required."
          })
        : res.status(403).send(
            "Admin permission required."
          );
    }

    req.crmUser = userData.user;
    req.crmSupabase = supabase;

    next();

  } catch (error) {
    console.error("Auth:", error.message);

    return res.status(503).json({
      error: "Authentication temporarily unavailable."
    });
  }
}

// SAME-ORIGIN REQUEST CHECK

function sameOrigin(req, res, next) {
  const origin = req.get("origin");
  const host =
    req.get("x-forwarded-host") || req.get("host");

  if (origin) {
    try {
      if (new URL(origin).host !== host) {
        return res.status(403).json({
          error: "Invalid request origin."
        });
      }
    } catch {
      return res.status(403).json({
        error: "Invalid request origin."
      });
    }
  }

  next();
}

// VALIDATE LEAD DATA

function cleanLead(raw) {
  if (
    !raw ||
    typeof raw !== "object" ||
    Array.isArray(raw)
  ) {
    return { error: "Invalid lead data." };
  }

  const name =
    typeof raw.name === "string"
      ? raw.name.trim()
      : "";

  const phone =
    typeof raw.phone === "string"
      ? raw.phone.trim()
      : "";

  const email =
    typeof raw.email === "string"
      ? raw.email.trim().toLowerCase()
      : "";

  const lead_source =
    typeof raw.lead_source === "string"
      ? raw.lead_source.trim()
      : "Manual";

  const form_name =
    typeof raw.form_name === "string"
      ? raw.form_name.trim()
      : "";

  if (!name || name.length > 150) {
    return {
      error: "Customer name must be 1–150 characters."
    };
  }

  if (!phone && !email) {
    return {
      error: "Phone or email is required."
    };
  }

  if (
    phone &&
    (
      !/^[+0-9()\-\s]{7,20}$/.test(phone) ||
      phone.replace(/\D/g, "").length < 7
    )
  ) {
    return {
      error: "Invalid phone number."
    };
  }

  if (
    email &&
    (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254
    )
  ) {
    return {
      error: "Invalid email address."
    };
  }

  if (!SOURCES.includes(lead_source)) {
    return {
      error: "Invalid lead source."
    };
  }

  if (form_name.length > 150) {
    return {
      error: "Form name must be 150 characters or fewer."
    };
  }

  return {
    lead: {
      name,
      phone: phone || null,
      email: email || null,
      lead_source,
      form_name: form_name || null,
      status: "New"
    }
  };
}

// DUPLICATE DETECTION

function normalizedPhone(value) {
  return String(value || "").replace(/\D/g, "");
}

function duplicateKey(lead) {
  return [
    lead.phone && "p:" + normalizedPhone(lead.phone),
    lead.email && "e:" + lead.email.toLowerCase()
  ].filter(Boolean);
}

async function leadExists(db, lead) {
  if (lead.email) {
    const { data, error } = await db
      .from("LEADS 1")
      .select("id")
      .eq("email", lead.email)
      .limit(1);

    if (error) throw error;
    if (data.length) return true;
  }

  if (lead.phone) {
    const { data, error } = await db
      .from("LEADS 1")
      .select("id")
      .eq("phone", lead.phone)
      .limit(1);

    if (error) throw error;
    if (data.length) return true;
  }

  return false;
}

// HOMEPAGE

app.get("/", (req, res) => {
  res.redirect("/login");
});

// LOGIN PAGE

app.get("/login", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "login.html")
  );
});

// LOGIN API

app.post("/api/login", sameOrigin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  const { email, password } = req.body || {};

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email.trim() ||
    !password
  ) {
    return res.status(400).json({
      error: "Email and password are required."
    });
  }

  try {
    const { data, error } =
      await getSupabase().auth.signInWithPassword({
        email: email.trim(),
        password
      });

    if (error || !data.session || !data.user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const db = getSupabase(
      data.session.access_token
    );

    const { data: roleData, error: roleError } =
      await db
        .from("crm_user_roles")
        .select("role")
        .eq("user_id", data.user.id)
        .single();

    if (roleError || roleData?.role !== "admin") {
      return res.status(403).json({
        error: "Admin access not authorized."
      });
    }

    res.cookie(
      COOKIE_NAME,
      data.session.access_token,
      {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge:
          Math.min(
            data.session.expires_in || 3600,
            3600
          ) * 1000
      }
    );

    return res.json({
      success: true,
      redirect: "/dashboard"
    });

  } catch (error) {
    console.error("Login:", error.message);

    return res.status(503).json({
      error: "Login temporarily unavailable."
    });
  }
});

// PREMIUM DASHBOARD

app.get("/dashboard", verifyAdmin, (req, res) => {
  res.set("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "dashboard.html")
  );
});

// LOGOUT

app.post("/logout", sameOrigin, (req, res) => {
  clearSession(res);
  res.redirect("/login");
});

// GET ALL LEADS

app.get("/api/leads", verifyAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const all = [];
    let from = 0;
    const pageSize = 500;

    while (true) {
      const { data, error } =
        await req.crmSupabase
          .from("LEADS 1")
          .select(
            "id,name,phone,email,status,lead_source,form_name"
          )
          .order("id", { ascending: false })
          .range(from, from + pageSize - 1);

      if (error) throw error;

      all.push(...data);

      if (data.length < pageSize) break;

      from += pageSize;

      if (from >= 10000) break;
    }

    return res.json({
      success: true,
      count: all.length,
      leads: all,
      truncated: all.length >= 10000
    });

  } catch (error) {
    console.error(
      "Get leads:",
      error.code || error.message
    );

    return res.status(500).json({
      error: "Unable to load leads."
    });
  }
});

// ADD NEW LEAD

app.post(
  "/api/leads",
  sameOrigin,
  verifyAdmin,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    const { lead, error } = cleanLead(req.body);

    if (error) {
      return res.status(400).json({ error });
    }

    try {
      if (
        await leadExists(req.crmSupabase, lead)
      ) {
        return res.status(409).json({
          error:
            "A lead with this phone or email already exists."
        });
      }

      const { error: insertError } =
        await req.crmSupabase
          .from("LEADS 1")
          .insert(lead);

      if (insertError) throw insertError;

      return res.status(201).json({
        success: true,
        message: "Lead added successfully."
      });

    } catch (err) {
      console.error(
        "Add lead:",
        err.code || err.message
      );

      return res.status(500).json({
        error:
          "Unable to add lead. Check table permissions and ID default."
      });
    }
  }
);

// IMPORT LEADS

app.post(
  "/api/leads/import",
  sameOrigin,
  verifyAdmin,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    const rows = req.body?.leads;

    if (
      !Array.isArray(rows) ||
      rows.length < 1 ||
      rows.length > 100
    ) {
      return res.status(400).json({
        error:
          "Import between 1 and 100 leads per batch."
      });
    }

    const results = {
      success: true,
      imported: 0,
      duplicates: 0,
      invalid: 0,
      failed: 0,
      details: []
    };

    const seen = new Set();

    for (let i = 0; i < rows.length; i++) {
      const { lead, error } = cleanLead(rows[i]);

      if (error) {
        results.invalid++;

        results.details.push({
          row: i + 1,
          result: "Invalid",
          reason: error
        });

        continue;
      }

      const keys = duplicateKey(lead);

      if (
        keys.some(key => seen.has(key))
      ) {
        results.duplicates++;

        results.details.push({
          row: i + 1,
          result: "Duplicate",
          reason: "Repeated in this batch"
        });

        continue;
      }

      try {
        if (
          await leadExists(req.crmSupabase, lead)
        ) {
          results.duplicates++;

          results.details.push({
            row: i + 1,
            result: "Duplicate",
            reason: "Already in CRM"
          });

          keys.forEach(key => seen.add(key));
          continue;
        }

        const { error: insertError } =
          await req.crmSupabase
            .from("LEADS 1")
            .insert(lead);

        if (insertError) throw insertError;

        keys.forEach(key => seen.add(key));

        results.imported++;

      } catch (err) {
        console.error(
          "Import row:",
          i + 1,
          err.code || err.message
        );

        results.failed++;

        results.details.push({
          row: i + 1,
          result: "Failed",
          reason: "Database rejected row"
        });
      }
    }

    return res.json(results);
  }
);

// SERVER HEALTH

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    application: "Digital TATSAT CRM"
  });
});

// DATABASE HEALTH

app.get("/db-health", async (req, res) => {
  if (
    !process.env.SUPABASE_URL ||
    !process.env.SUPABASE_ANON_KEY
  ) {
    return res.status(503).json({
      database: "configuration_missing"
    });
  }

  try {
    const { error } = await getSupabase()
      .from("LEADS 1")
      .select("id", { head: true })
      .limit(1);

    if (error) {
      return res.status(503).json({
        database: "connection_or_permission_error"
      });
    }

    return res.json({
      database: "supabase_api_reachable"
    });

  } catch (err) {
    return res.status(503).json({
      database: "connection_error"
    });
  }
});

// START SERVER

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Digital TATSAT CRM running on port ${PORT}`
  );
});
