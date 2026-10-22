
const express = require("express");
const WebSocket = require("ws");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");

const app = express();

app.use(express.json({ limit: "20kb" }));

const COOKIE_NAME = "dt_crm_session";

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
    .find(item => item.startsWith(COOKIE_NAME + "="));

  if (!session) return null;

  try {
    return decodeURIComponent(
      session.slice(COOKIE_NAME.length + 1)
    );
  } catch {
    return null;
  }
}

// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

async function verifyAdmin(req, res, next) {
  try {
    const token = getSessionToken(req);

    if (!token) {
      return res.redirect("/login");
    }

    const supabase = getSupabase(token);

    const { data: userData, error: userError } =
      await supabase.auth.getUser(token);

    if (userError || !userData.user) {
      res.clearCookie(COOKIE_NAME, { path: "/" });
      return res.redirect("/login");
    }

    const { data: roleData, error: roleError } =
      await supabase
        .from("crm_user_roles")
        .select("role")
        .eq("user_id", userData.user.id)
        .single();

    if (roleError || roleData?.role !== "admin") {
      return res.status(403).send(
        "Access denied. Admin permission required."
      );
    }

    req.crmUser = userData.user;
    next();

  } catch (error) {
    console.error(
      "Session verification error:",
      error.message
    );

    return res.status(503).send(
      "Authentication temporarily unavailable."
    );
  }
}

// ==========================================
// HOMEPAGE
// ==========================================

app.get("/", (req, res) => {
  res.redirect("/login");
});

// ==========================================
// PREMIUM LOGIN PAGE
// ==========================================

app.get("/login", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "login.html")
  );
});

// ==========================================
// ADMIN LOGIN API
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

    if (
      error ||
      !data.session ||
      !data.user
    ) {
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

    if (
      roleError ||
      roleData?.role !== "admin"
    ) {
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
    console.error(
      "Login error:",
      error.message
    );

    return res.status(503).json({
      error: "Login temporarily unavailable."
    });
  }
});

// ==========================================
// PROTECTED PREMIUM DASHBOARD
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
  res.clearCookie(COOKIE_NAME, {
    path: "/",
    secure: true,
    sameSite: "lax",
    httpOnly: true
  });

  res.redirect("/login");
});

// ==========================================
// GET ALL LEADS
// ==========================================

app.get("/api/leads", verifyAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const token = getSessionToken(req);
    const supabase = getSupabase(token);

    const { data, error } = await supabase
      .from("LEADS 1")
      .select("id, name, phone, email, status")
      .order("id", { ascending: false });

    if (error) {
      console.error(
        "Lead fetch failed:",
        error.code
      );

      return res.status(500).json({
        error: "Unable to load leads."
      });
    }

    return res.json({
      success: true,
      count: data.length,
      leads: data
    });

  } catch (error) {
    console.error(
      "Leads API error:",
      error.message
    );

    return res.status(503).json({
      error: "Leads temporarily unavailable."
    });
  }
});

// ==========================================
// ADD NEW LEAD
// ==========================================

app.post("/api/leads", verifyAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const { name, phone, email } = req.body || {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.trim().length > 150
    ) {
      return res.status(400).json({
        error: "Valid customer name is required."
      });
    }

    const cleanPhone =
      typeof phone === "string"
        ? phone.trim()
        : "";

    const cleanEmail =
      typeof email === "string"
        ? email.trim()
        : "";

    if (!cleanPhone && !cleanEmail) {
      return res.status(400).json({
        error: "Phone number or email is required."
      });
    }

    if (
      cleanPhone.length > 20 ||
      cleanEmail.length > 254
    ) {
      return res.status(400).json({
        error: "Contact information is too long."
      });
    }

    const supabase = getSupabase(
      getSessionToken(req)
    );

    const { error } = await supabase
      .from("LEADS 1")
      .insert({
        name: name.trim(),
        phone: cleanPhone || null,
        email: cleanEmail || null,
        status: "New"
      });

    if (error) {
      console.error(
        "Add lead failed:",
        error.code
      );

      return res.status(500).json({
        error: "Unable to add lead."
      });
    }

    return res.status(201).json({
      success: true,
      message: "Lead added successfully."
    });

  } catch (error) {
    console.error(
      "Add lead error:",
      error.message
    );

    return res.status(503).json({
      error: "Lead service temporarily unavailable."
    });
  }
});

// ==========================================
// SERVER HEALTH
// ==========================================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    application: "Digital TATSAT CRM"
  });
});

// ==========================================
// SUPABASE CONNECTION CHECK
// ==========================================

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
    const supabase = getSupabase();

    const { error } = await supabase
      .from("LEADS 1")
      .select("id", { head: true })
      .limit(1);

    if (error) {
      console.error(
        "Database check:",
        error.code
      );

      return res.status(503).json({
        database: "connection_or_permission_error"
      });
    }

    return res.json({
      database: "supabase_api_reachable",
      note: "Lead access not yet verified"
    });

  } catch (error) {
    console.error(
      "Database error:",
      error.message
    );

    return res.status(503).json({
      database: "connection_error"
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
