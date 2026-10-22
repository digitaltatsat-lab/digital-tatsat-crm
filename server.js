
const express = require("express");
const WebSocket = require("ws");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "300kb" }));

const COOKIE_NAME = "dt_crm_session";
const LEADS_TABLE = "LEADS 1";

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

const STATUSES = [
  "New",
  "In Progress",
  "Follow-up",
  "Converted",
  "Lost"
];

const LEAD_FIELDS = [
  "id",
  "name",
  "phone",
  "email",
  "status",
  "lead_source",
  "form_name",
  "company",
  "assigned_to",
  "client_id"
].join(",");

// ==========================================
// SUPABASE CONNECTION
// ==========================================

function getSupabase(token) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;

  if (!url || !key) {
    throw new Error("Supabase configuration missing");
  }

  const options = {
    realtime: {
      transport: WebSocket
    },
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

// ==========================================
// SESSION COOKIE
// ==========================================

function getSessionToken(req) {
  const cookies = req.headers.cookie || "";

  const session = cookies
    .split(";")
    .map(item => item.trim())
    .find(item =>
      item.startsWith(COOKIE_NAME + "=")
    );

  if (!session) return null;

  try {
    return decodeURIComponent(
      session.slice(COOKIE_NAME.length + 1)
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

function authFailure(req, res, status, message) {
  if (req.path.startsWith("/api/")) {
    return res.status(status).json({
      error: message
    });
  }

  if (status === 401) {
    return res.redirect("/login");
  }

  return res.status(status).send(message);
}

// ==========================================
// SAME-ORIGIN PROTECTION
// ==========================================

function checkOrigin(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    return next();
  }

  const origin = req.get("origin");

  if (origin) {
    try {
      const parsed = new URL(origin);

      if (parsed.host !== req.get("host") ||
          parsed.protocol !== "https:") {
        return res.status(403).json({
          error: "Request origin not allowed."
        });
      }
    } catch {
      return res.status(403).json({
        error: "Invalid request origin."
      });
    }
  } else {
    const fetchSite = req.get("sec-fetch-site");

    if (fetchSite && !["same-origin", "none"].includes(fetchSite)) {
      return res.status(403).json({
        error: "Cross-site request blocked."
      });
    }
  }

  next();
}

app.use(checkOrigin);

// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

async function verifyAdmin(req, res, next) {
  try {
    const token = getSessionToken(req);

    if (!token) {
      return authFailure(
        req, res, 401, "Please log in again."
      );
    }

    const supabase = getSupabase(token);

    const { data: userData, error: userError } =
      await supabase.auth.getUser(token);

    if (userError || !userData?.user) {
      clearSession(res);

      return authFailure(
        req, res, 401, "Session expired."
      );
    }

    const { data: roleData, error: roleError } =
      await supabase
        .from("crm_user_roles")
        .select("role")
        .eq("user_id", userData.user.id)
        .single();

    if (roleError || roleData?.role !== "admin") {
      return authFailure(
        req, res, 403, "Admin permission required."
      );
    }

    req.crmUser = userData.user;
    req.supabase = supabase;

    next();

  } catch (error) {
    console.error(
      "Authentication error:",
      error.message
    );

    return res.status(503).json({
      error: "Authentication temporarily unavailable."
    });
  }
}

// ==========================================
// INPUT VALIDATION
// ==========================================

function cleanText(value, maxLength) {
  if (value === undefined || value === null) {
    return "";
  }

  if (typeof value !== "string") {
    throw new Error("Invalid text field.");
  }

  const text = value.trim();

  if (text.length > maxLength) {
    throw new Error(
      `Text exceeds ${maxLength} characters.`
    );
  }

  return text;
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(value);
}

function normalizeLead(input, options = {}) {
  if (!input || typeof input !== "object" ||
      Array.isArray(input)) {
    throw new Error("Invalid lead information.");
  }

  const name = cleanText(input.name, 150);
  const phone = cleanText(input.phone, 20);
  const email = cleanText(input.email, 254)
    .toLowerCase();

  const company = cleanText(input.company, 200);
  const assignedTo = cleanText(input.assigned_to, 150);
  const formName = cleanText(input.form_name, 150);

  const source = cleanText(
    input.lead_source || "Manual", 80
  );

  const status = cleanText(
    input.status || "New", 50
  );

  const clientId = cleanText(
    input.client_id, 36
  );

  if (!name) {
    throw new Error("Customer name is required.");
  }

  if (!phone && !email) {
    throw new Error(
      "Phone number or email is required."
    );
  }

  if (email &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("Invalid email address.");
  }

  if (!SOURCES.includes(source)) {
    throw new Error("Invalid lead source.");
  }

  if (!STATUSES.includes(status)) {
    throw new Error("Invalid lead status.");
  }

  if (clientId && !validUUID(clientId)) {
    throw new Error("Invalid client ID.");
  }

  return {
    name,
    phone: phone || null,
    email: email || null,
    company: company || null,
    assigned_to: assignedTo || null,
    lead_source: source,
    form_name: formName || null,
    status,
    client_id: options.allowClientId && clientId
      ? clientId
      : null
  };
}

// ==========================================
// CLIENT ID VALIDATION
// ==========================================

async function validateClient(supabase, clientId) {
  if (!clientId) return true;

  const { data, error } = await supabase
    .from("crm_clients")
    .select("id")
    .eq("id", clientId)
    .maybeSingle();

  if (error) {
    throw new Error(
      "Client lookup failed. Check CRM client permissions."
    );
  }

  return Boolean(data);
}

// ==========================================
// DUPLICATE CHECK
// ==========================================

async function findDuplicate(supabase, lead) {
  if (lead.phone) {
    const { data, error } = await supabase
      .from(LEADS_TABLE)
      .select("id")
      .eq("phone", lead.phone)
      .limit(1);

    if (error) throw error;
    if (data.length) return data[0];
  }

  if (lead.email) {
    const { data, error } = await supabase
      .from(LEADS_TABLE)
      .select("id")
      .ilike("email", lead.email)
      .limit(1);

    if (error) throw error;
    if (data.length) return data[0];
  }

  return null;
}

// ==========================================
// HOME / LOGIN
// ==========================================

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "login.html")
  );
});

// ==========================================
// LOGIN API
// ==========================================

app.post("/api/login", async (req, res) => {
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
    const supabase = getSupabase();

    const { data, error } =
      await supabase.auth.signInWithPassword({
        email: email.trim(),
        password
      });

    if (error || !data.session || !data.user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const authenticatedSupabase =
      getSupabase(data.session.access_token);

    const { data: roleData, error: roleError } =
      await authenticatedSupabase
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
        maxAge: Math.min(
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
    console.error("Login error:", error.message);

    return res.status(503).json({
      error: "Login temporarily unavailable."
    });
  }
});

// ==========================================
// DASHBOARD
// ==========================================

app.get("/dashboard", verifyAdmin, (req, res) => {
  res.set("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "dashboard.html")
  );
});

// ==========================================
// LOGOUT
// ==========================================

app.post("/logout", (req, res) => {
  clearSession(res);
  res.redirect("/login");
});

// ==========================================
// GET ALL LEADS
// ==========================================

app.get("/api/leads", verifyAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const all = [];
    const pageSize = 500;

    for (let start = 0; start < 10000; start += pageSize) {
      const { data, error } = await req.supabase
        .from(LEADS_TABLE)
        .select(LEAD_FIELDS)
        .order("id", { ascending: false })
        .range(start, start + pageSize - 1);

      if (error) throw error;

      all.push(...data);

      if (data.length < pageSize) break;
    }

    return res.json({
      success: true,
      count: all.length,
      leads: all
    });

  } catch (error) {
    console.error("Lead fetch error:", error.message);

    return res.status(500).json({
      error: "Unable to load leads. Check database columns and permissions."
    });
  }
});

// ==========================================
// ADD NEW LEAD
// ==========================================

app.post("/api/leads", verifyAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const lead = normalizeLead(req.body);

    const duplicate = await findDuplicate(
      req.supabase, lead
    );

    if (duplicate) {
      return res.status(409).json({
        error: "A lead with this phone or email already exists.",
        duplicate_id: duplicate.id
      });
    }

    const { data, error } = await req.supabase
      .from(LEADS_TABLE)
      .insert(lead)
      .select(LEAD_FIELDS)
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      message: "Lead added successfully.",
      lead: data
    });

  } catch (error) {
    if (error.message.startsWith("Invalid") ||
        error.message.includes("required") ||
        error.message.includes("exceeds")) {
      return res.status(400).json({
        error: error.message
      });
    }

    console.error("Add lead error:", error.message);

    return res.status(500).json({
      error: "Unable to add lead."
    });
  }
});

// ==========================================
// UPDATE EXISTING LEAD
// ==========================================

app.patch("/api/leads/:id", verifyAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const id = String(req.params.id);

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        error: "Invalid lead ID."
      });
    }

    const { data: existing, error: findError } =
      await req.supabase
        .from(LEADS_TABLE)
        .select(LEAD_FIELDS)
        .eq("id", id)
        .maybeSingle();

    if (findError) throw findError;

    if (!existing) {
      return res.status(404).json({
        error: "Lead not found."
      });
    }

    const allowed = [
      "name",
      "phone",
      "email",
      "company",
      "assigned_to",
      "status",
      "lead_source",
      "form_name"
    ];

    const submitted = req.body || {};

    if (!submitted ||
        typeof submitted !== "object" ||
        Array.isArray(submitted)) {
      return res.status(400).json({
        error: "Invalid update information."
      });
    }

    const changes = {};

    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(
        submitted, key
      )) {
        changes[key] = submitted[key];
      }
    }

    if (!Object.keys(changes).length) {
      return res.status(400).json({
        error: "No editable fields provided."
      });
    }

    const normalized = normalizeLead({
      ...existing,
      ...changes
    });

    const update = {};

    for (const key of Object.keys(changes)) {
      update[key] = normalized[key];
    }

    const { data, error } = await req.supabase
      .from(LEADS_TABLE)
      .update(update)
      .eq("id", id)
      .select(LEAD_FIELDS)
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      message: "Lead updated successfully.",
      lead: data
    });

  } catch (error) {
    if (error.message.startsWith("Invalid") ||
        error.message.includes("required") ||
        error.message.includes("exceeds")) {
      return res.status(400).json({
        error: error.message
      });
    }

    console.error("Update lead error:", error.message);

    return res.status(500).json({
      error: "Unable to update lead."
    });
  }
});

// ==========================================
// CSV IMPORT API
// ==========================================

app.post("/api/leads/import",
  verifyAdmin,
  async (req, res) => {

  res.set("Cache-Control", "no-store");

  const incoming = req.body?.leads;

  if (!Array.isArray(incoming) ||
      incoming.length === 0 ||
      incoming.length > 100) {
    return res.status(400).json({
      error: "Import between 1 and 100 leads."
    });
  }

  const result = {
    success: true,
    imported: 0,
    duplicates: 0,
    invalid: 0,
    failed: 0,
    details: []
  };

  const seenPhones = new Set();
  const seenEmails = new Set();

  for (let index = 0; index < incoming.length; index++) {
    const rowNumber = index + 1;

    let lead;

    try {
      lead = normalizeLead(incoming[index]);
    } catch (error) {
      result.invalid++;
      result.details.push({
        row: rowNumber,
        status: "invalid",
        reason: error.message
      });
      continue;
    }

    if (
      (lead.phone && seenPhones.has(lead.phone)) ||
      (lead.email && seenEmails.has(lead.email))
    ) {
      result.duplicates++;
      result.details.push({
        row: rowNumber,
        status: "duplicate_in_file"
      });
      continue;
    }

    if (lead.phone) seenPhones.add(lead.phone);
    if (lead.email) seenEmails.add(lead.email);

    try {
      const duplicate = await findDuplicate(
        req.supabase, lead
      );

      if (duplicate) {
        result.duplicates++;
        result.details.push({
          row: rowNumber,
          status: "duplicate_in_crm"
        });
        continue;
      }

      const { error } = await req.supabase
        .from(LEADS_TABLE)
        .insert(lead);

      if (error) throw error;

      result.imported++;

    } catch (error) {
      console.error(
        "Import row error:",
        rowNumber,
        error.message
      );

      result.failed++;
      result.details.push({
        row: rowNumber,
        status: "failed"
      });
    }
  }

  return res.json(result);
});

// ==========================================
// CLIENTS API
// Admin-only, read-only for now.
// ==========================================

app.get("/api/clients", verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await req.supabase
      .from("crm_clients")
      .select("id,name,client_type")
      .order("name");

    if (error) throw error;

    return res.json({
      success: true,
      clients: data
    });

  } catch (error) {
    console.error("Client API:", error.message);

    return res.status(500).json({
      error: "Unable to load clients."
    });
  }
});

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    application: "Digital TATSAT CRM",
    version: "2.0"
  });
});

// ==========================================
// DATABASE HEALTH
// ==========================================

app.get("/db-health", verifyAdmin, async (req, res) => {
  try {
    const { error } = await req.supabase
      .from(LEADS_TABLE)
      .select("id")
      .limit(1);

    if (error) throw error;

    return res.json({
      database: "connected",
      lead_access: "verified"
    });

  } catch (error) {
    console.error("DB health:", error.message);

    return res.status(503).json({
      database: "connection_or_permission_error"
    });
  }
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Digital TATSAT CRM running on port ${PORT}`
  );
});
