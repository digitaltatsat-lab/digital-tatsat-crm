
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
  "Manual", "Meta Ads", "Google Ads", "Website",
  "WhatsApp", "Google Business Profile",
  "Referral", "Cold Calling", "Other"
];

const STATUSES = [
  "New", "In Progress", "Follow-up",
  "Converted", "Lost"
];

const LEAD_FIELDS = [
  "id", "name", "phone", "email", "status",
  "lead_source", "form_name", "company",
  "assigned_to", "client_id"
].join(",");

// =====================================
// SUPABASE CONNECTION
// =====================================

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

// =====================================
// COOKIE MANAGEMENT
// =====================================

function getSessionToken(req) {
  const cookie = (req.headers.cookie || "")
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(COOKIE_NAME + "="));

  if (!cookie) return null;

  try {
    return decodeURIComponent(
      cookie.slice(COOKIE_NAME.length + 1)
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
  if (req.path.startsWith("/api/") ||
      req.path === "/db-health") {
    return res.status(status).json({
      error: message
    });
  }

  if (status === 401) {
    return res.redirect("/login");
  }

  return res.status(status).send(message);
}

// =====================================
// SAME-ORIGIN PROTECTION
// =====================================

function checkOrigin(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"]
      .includes(req.method)) {
    return next();
  }

  const origin = req.get("origin");

  if (origin) {
    try {
      const parsed = new URL(origin);

      if (
        parsed.protocol !== "https:" ||
        parsed.host !== req.get("host")
      ) {
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
    const site = req.get("sec-fetch-site");

    if (site &&
        !["same-origin", "none"].includes(site)) {
      return res.status(403).json({
        error: "Cross-site request blocked."
      });
    }
  }

  next();
}

app.use(checkOrigin);

// =====================================
// AUTHENTICATION
// =====================================

async function verifyUser(req, res, next) {
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

    if (
      roleError ||
      !["admin", "employee"].includes(roleData?.role)
    ) {
      return authFailure(
        req, res, 403,
        "CRM access not authorized."
      );
    }

    req.crmUser = userData.user;
    req.crmRole = roleData.role;
    req.supabase = supabase;

    next();

  } catch (error) {
    console.error("Authentication:", error.message);

    return res.status(503).json({
      error: "Authentication temporarily unavailable."
    });
  }
}

function verifyAdmin(req, res, next) {
  verifyUser(req, res, () => {
    if (req.crmRole !== "admin") {
      return authFailure(
        req, res, 403,
        "Admin permission required."
      );
    }

    next();
  });
}

function verifyEmployee(req, res, next) {
  verifyUser(req, res, () => {
    if (req.crmRole !== "employee") {
      return authFailure(
        req, res, 403,
        "Employee permission required."
      );
    }

    next();
  });
}

// =====================================
// INPUT VALIDATION
// =====================================

function cleanText(value, maxLength) {
  if (value === null || value === undefined) {
    return "";
  }

  if (typeof value !== "string") {
    throw new Error("Invalid text field.");
  }

  const result = value.trim();

  if (result.length > maxLength) {
    throw new Error(
      `Text exceeds ${maxLength} characters.`
    );
  }

  return result;
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(value);
}

function normalizeLead(input, options = {}) {
  if (!input ||
      typeof input !== "object" ||
      Array.isArray(input)) {
    throw new Error("Invalid lead information.");
  }

  const name = cleanText(input.name, 150);
  const phone = cleanText(input.phone, 20);
  const email = cleanText(input.email, 254)
    .toLowerCase();
  const company = cleanText(input.company, 200);
  const assignedTo = cleanText(
    input.assigned_to, 150
  );
  const formName = cleanText(
    input.form_name, 150
  );
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

  if (
    email &&
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
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
    client_id:
      options.allowClientId && clientId
        ? clientId
        : null
  };
}

// =====================================
// DUPLICATE CHECK
// =====================================

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

// =====================================
// LOGIN PAGE
// =====================================

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(
    path.join(__dirname, "login.html")
  );
});

// =====================================
// LOGIN API - ADMIN + EMPLOYEE
// =====================================

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
    const { data, error } =
      await getSupabase()
        .auth.signInWithPassword({
          email: email.trim(),
          password
        });

    if (error || !data?.session || !data?.user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const userClient = getSupabase(
      data.session.access_token
    );

    const { data: roleData, error: roleError } =
      await userClient
        .from("crm_user_roles")
        .select("role")
        .eq("user_id", data.user.id)
        .single();

    if (
      roleError ||
      !["admin", "employee"].includes(roleData?.role)
    ) {
      return res.status(403).json({
        error: "CRM access not authorized."
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
      role: roleData.role,
      redirect:
        roleData.role === "admin"
          ? "/dashboard"
          : "/employee-dashboard"
    });

  } catch (error) {
    console.error("Login:", error.message);

    return res.status(503).json({
      error: "Login temporarily unavailable."
    });
  }
});

// =====================================
// ADMIN DASHBOARD
// =====================================

app.get(
  "/dashboard",
  verifyAdmin,
  (req, res) => {
    res.set("Cache-Control", "no-store");

    res.sendFile(
      path.join(__dirname, "dashboard.html")
    );
  }
);

// =====================================
// EMPLOYEE DASHBOARD
// =====================================

app.get(
  "/employee-dashboard",
  verifyEmployee,
  (req, res) => {
    res.set("Cache-Control", "no-store");

    res.sendFile(
      path.join(
        __dirname,
        "employee-dashboard.html"
      )
    );
  }
);

// =====================================
// EMPLOYEE PROFILE API
// =====================================

app.get(
  "/api/employee/me",
  verifyEmployee,
  (req, res) => {
    res.set("Cache-Control", "no-store");

    return res.json({
      success: true,
      email: req.crmUser.email,
      role: "employee"
    });
  }
);

// =====================================
// LOGOUT
// =====================================

app.post("/logout", (req, res) => {
  clearSession(res);
  res.redirect("/login");
});

// =====================================
// GET ALL LEADS - ADMIN ONLY
// =====================================

app.get(
  "/api/leads",
  verifyAdmin,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    try {
      const all = [];
      const pageSize = 500;

      for (
        let start = 0;
        start < 10000;
        start += pageSize
      ) {
        const { data, error } =
          await req.supabase
            .from(LEADS_TABLE)
            .select(LEAD_FIELDS)
            .order("id", {
              ascending: false
            })
            .range(
              start,
              start + pageSize - 1
            );

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
      console.error(
        "Fetch leads:",
        error.message
      );

      return res.status(500).json({
        error: "Unable to load leads."
      });
    }
  }
);

// =====================================
// ADD LEAD - ADMIN ONLY
// =====================================

app.post(
  "/api/leads",
  verifyAdmin,
  async (req, res) => {
    try {
      const lead = normalizeLead(req.body);

      const duplicate = await findDuplicate(
        req.supabase,
        lead
      );

      if (duplicate) {
        return res.status(409).json({
          error:
            "Phone or email already exists.",
          duplicate_id: duplicate.id
        });
      }

      const { data, error } =
        await req.supabase
          .from(LEADS_TABLE)
          .insert(lead)
          .select(LEAD_FIELDS)
          .single();

      if (error) throw error;

      return res.status(201).json({
        success: true,
        lead: data
      });

    } catch (error) {
      console.error(
        "Add lead:",
        error.message
      );

      const validation =
        /^(Invalid|Customer name|Phone number|Text exceeds)/
          .test(error.message);

      return res.status(
        validation ? 400 : 500
      ).json({
        error: validation
          ? error.message
          : "Unable to add lead."
      });
    }
  }
);

// =====================================
// UPDATE LEAD - ADMIN ONLY
// =====================================

app.patch(
  "/api/leads/:id",
  verifyAdmin,
  async (req, res) => {
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
        "name", "phone", "email",
        "company", "assigned_to",
        "status", "lead_source",
        "form_name"
      ];

      const submitted = req.body;

      if (
        !submitted ||
        typeof submitted !== "object" ||
        Array.isArray(submitted)
      ) {
        return res.status(400).json({
          error: "Invalid update information."
        });
      }

      const changes = {};

      for (const key of allowed) {
        if (
          Object.prototype.hasOwnProperty.call(
            submitted, key
          )
        ) {
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

      const { data, error } =
        await req.supabase
          .from(LEADS_TABLE)
          .update(update)
          .eq("id", id)
          .select(LEAD_FIELDS)
          .single();

      if (error) throw error;

      return res.json({
        success: true,
        message:
          "Lead updated successfully.",
        lead: data
      });

    } catch (error) {
      console.error(
        "Update lead:",
        error.message
      );

      const validation =
        /^(Invalid|Customer name|Phone number|Text exceeds)/
          .test(error.message);

      return res.status(
        validation ? 400 : 500
      ).json({
        error: validation
          ? error.message
          : "Unable to update lead."
      });
    }
  }
);

// =====================================
// CSV IMPORT - ADMIN ONLY
// =====================================

app.post(
  "/api/leads/import",
  verifyAdmin,
  async (req, res) => {
    const incoming = req.body?.leads;

    if (
      !Array.isArray(incoming) ||
      incoming.length === 0 ||
      incoming.length > 100
    ) {
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

    for (
      let index = 0;
      index < incoming.length;
      index++
    ) {
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
        (lead.phone &&
          seenPhones.has(lead.phone)) ||
        (lead.email &&
          seenEmails.has(lead.email))
      ) {
        result.duplicates++;

        result.details.push({
          row: rowNumber,
          status: "duplicate_in_file"
        });

        continue;
      }

      if (lead.phone) {
        seenPhones.add(lead.phone);
      }

      if (lead.email) {
        seenEmails.add(lead.email);
      }

      try {
        const duplicate = await findDuplicate(
          req.supabase,
          lead
        );

        if (duplicate) {
          result.duplicates++;

          result.details.push({
            row: rowNumber,
            status: "duplicate_in_crm"
          });

          continue;
        }

        const { error } =
          await req.supabase
            .from(LEADS_TABLE)
            .insert(lead);

        if (error) throw error;

        result.imported++;

      } catch (error) {
        console.error(
          "Import row:",
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
  }
);

// =====================================
// CLIENTS API - ADMIN ONLY
// =====================================

app.get(
  "/api/clients",
  verifyAdmin,
  async (req, res) => {
    try {
      const { data, error } =
        await req.supabase
          .from("crm_clients")
          .select("id,name,client_type")
          .order("name");

      if (error) throw error;

      return res.json({
        success: true,
        clients: data
      });

    } catch (error) {
      console.error(
        "Client API:",
        error.message
      );

      return res.status(500).json({
        error: "Unable to load clients."
      });
    }
  }
);

// =====================================
// HEALTH CHECK
// =====================================

app.get("/health", (req, res) => {
  return res.json({
    status: "ok",
    application: "Digital TATSAT CRM",
    version: "4.0-login"
  });
});

// =====================================
// DATABASE HEALTH - ADMIN ONLY
// =====================================

app.get(
  "/db-health",
  verifyAdmin,
  async (req, res) => {
    try {
      const { error } =
        await req.supabase
          .from(LEADS_TABLE)
          .select("id")
          .limit(1);

      if (error) throw error;

      return res.json({
        database: "connected",
        lead_access: "verified"
      });

    } catch (error) {
      console.error(
        "DB health:",
        error.message
      );

      return res.status(503).json({
        database:
          "connection_or_permission_error"
      });
    }
  }
);

// =====================================
// START SERVER
// =====================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Digital TATSAT CRM V4 running on port ${PORT}`
  );
});
