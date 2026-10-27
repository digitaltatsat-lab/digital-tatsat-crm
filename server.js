const express = require("express");
const WebSocket = require("ws");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "300kb" }));


const COOKIE_NAME = "dt_crm_session";
const REFRESH_COOKIE_NAME = "dt_crm_refresh";
const REFRESH_COOKIE_AGE_MS = 12 * 60 * 60 * 1000;
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
  "assigned_to", "client_id",
  "next_follow_up"
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

function getCookieValue(req, name) {
  const cookie = (req.headers.cookie || "")
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  if (!cookie) return null;

  try {
    return decodeURIComponent(
      cookie.slice(name.length + 1)
    );
  } catch {
    return null;
  }
}

function getSessionToken(req) {
  return getCookieValue(req, COOKIE_NAME);
}

function saveSession(res, session) {
  const options = {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  };

  res.cookie(
    COOKIE_NAME,
    session.access_token,
    {
      ...options,
      maxAge: Math.max(
        1,
        Math.min(
          session.expires_in || 3600,
          3600
        )
      ) * 1000
    }
  );

  res.cookie(
    REFRESH_COOKIE_NAME,
    session.refresh_token,
    {
      ...options,
      maxAge: REFRESH_COOKIE_AGE_MS
    }
  );
}

function clearSession(res) {
  const options = {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  };

  res.clearCookie(COOKIE_NAME, options);
  res.clearCookie(REFRESH_COOKIE_NAME, options);
}

function authFailure(req, res, status, message) {
  if (
    req.path.startsWith("/api/") ||
    req.path === "/db-health"
  ) {
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
  if (
    !["POST", "PUT", "PATCH", "DELETE"]
      .includes(req.method)
  ) {
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

    if (
      site &&
      !["same-origin", "none"].includes(site)
    ) {
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
    let token = getSessionToken(req);

    const refreshToken = getCookieValue(
      req,
      REFRESH_COOKIE_NAME
    );

    let user = null;

    // Check existing access token
    if (token) {
      const check = await getSupabase()
        .auth.getUser(token);

      if (
        !check.error &&
        check.data?.user
      ) {
        user = check.data.user;
      }
    }

    // Refresh expired session
    if (!user && refreshToken) {
      const refreshed = await getSupabase()
        .auth.refreshSession({
          refresh_token: refreshToken
        });

      if (
        !refreshed.error &&
        refreshed.data?.session
      ) {
        token = refreshed.data.session.access_token;

        saveSession(
          res,
          refreshed.data.session
        );

        const check = await getSupabase()
          .auth.getUser(token);

        if (
          !check.error &&
          check.data?.user
        ) {
          user = check.data.user;
        }
      }
    }

    if (!user) {
      clearSession(res);

      return authFailure(
        req,
        res,
        401,
        "Please log in again."
      );
    }

    const supabase = getSupabase(token);

    const { data: roleData, error: roleError } =
      await supabase
        .from("crm_user_roles")
        .select("role")
        .eq("user_id", user.id)
        .single();

    if (
      roleError ||
      !["admin", "employee"].includes(roleData?.role)
    ) {
      return authFailure(
        req,
        res,
        403,
        "CRM access not authorized."
      );
    }

    req.crmUser = user;
    req.crmRole = roleData.role;
    req.supabase = supabase;

    next();

  } catch (error) {
    console.error(
      "Authentication:",
      error.message
    );

    return res.status(503).json({
      error: "Authentication temporarily unavailable."
    });
  }
}

function verifyAdmin(req, res, next) {
  verifyUser(req, res, () => {
    if (req.crmRole !== "admin") {
      return authFailure(
        req,
        res,
        403,
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
        req,
        res,
        403,
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

  saveSession(res, data.session);
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

/* =====================================
   EMPLOYEE ATTENDANCE V4
   Clock In / Clock Out / Status
   ===================================== */

const ATTENDANCE_TABLE = "crm_employee_sessions";

async function getOpenAttendance(req) {
  const { data, error } = await req.supabase
    .from(ATTENDANCE_TABLE)
    .select("id,employee_id,login_at,logout_at")
    .eq("employee_id", req.crmUser.id)
    .is("logout_at", null)
    .order("login_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw error;
  return data;
}

// Today's current attendance status
app.get(
  "/api/employee/attendance",
  verifyEmployee,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    try {
      const session = await getOpenAttendance(req);

      return res.json({
        success: true,
        clocked_in: Boolean(session),
        session: session || null
      });
    } catch (error) {
      console.error("Attendance status:", error.message);
      return res.status(500).json({
        error: "Unable to load attendance."
      });
    }
  }
);

// Employee Clock In
app.post(
  "/api/employee/clock-in",
  verifyEmployee,
  async (req, res) => {
    try {
      const existing = await getOpenAttendance(req);

      if (existing) {
        return res.status(409).json({
          success: false,
          error: "You are already clocked in.",
          session: existing
        });
      }

      const { data, error } = await req.supabase
        .from(ATTENDANCE_TABLE)
        .insert({
          employee_id: req.crmUser.id
        })
        .select("id,employee_id,login_at,logout_at")
        .single();

      if (error) throw error;

      return res.status(201).json({
        success: true,
        message: "Clock-in successful.",
        session: data
      });
    } catch (error) {
      console.error("Clock in:", error.message);
      return res.status(500).json({
        error: "Unable to clock in."
      });
    }
  }
);

// Employee Clock Out
app.post(
  "/api/employee/clock-out",
  verifyEmployee,
  async (req, res) => {
    try {
      const existing = await getOpenAttendance(req);

      if (!existing) {
        return res.status(409).json({
          success: false,
          error: "No active attendance session."
        });
      }

      const { data, error } = await req.supabase
        .from(ATTENDANCE_TABLE)
        .update({
          logout_at: new Date().toISOString()
        })
        .eq("id", existing.id)
        .eq("employee_id", req.crmUser.id)
        .is("logout_at", null)
        .select("id,employee_id,login_at,logout_at")
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        return res.status(409).json({
          error: "Attendance session already closed."
        });
      }

      return res.json({
        success: true,
        message: "Clock-out successful.",
        session: data
      });
    } catch (error) {
      console.error("Clock out:", error.message);
      return res.status(500).json({
        error: "Unable to clock out."
      });
    }
  }
);

/* ==========================================
   DIGITAL TATSAT CRM V4
   EMPLOYEE DAILY ATTENDANCE HISTORY
   ========================================== */


app.get(
  "/api/employee/attendance/history",
  verifyEmployee,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    try {
      const employeeId = req.crmUser.id;
      const now = Date.now();

      const parts = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
      }).formatToParts(new Date(now));

      const part = (type) =>
        parts.find((p) => p.type === type).value;

      const today =
        `${part("year")}-${part("month")}-${part("day")}`;

      const dayStart = Date.parse(
        `${today}T00:00:00+05:30`
      );
      const dayEnd = dayStart + 86400000;
      const startISO = new Date(dayStart).toISOString();
      const endISO = new Date(dayEnd).toISOString();

      const { data, error } = await req.supabase
        .from(ATTENDANCE_TABLE)
        .select("id,login_at,logout_at")
        .eq("employee_id", employeeId)
        .lt("login_at", endISO)
        .or(`logout_at.is.null,logout_at.gt.${startISO}`)
        .order("login_at", { ascending: false });

      if (error) throw error;

      let totalSeconds = 0;

      const sessions = (data || []).map((item) => {
        const loginMs = Date.parse(item.login_at);
        const logoutMs = item.logout_at
          ? Date.parse(item.logout_at)
          : now;

        const overlapStart = Math.max(loginMs, dayStart);
        const overlapEnd = Math.min(
          logoutMs,
          dayEnd,
          now
        );

        const duration =
          Number.isFinite(overlapStart) &&
          Number.isFinite(overlapEnd)
            ? Math.max(
                0,
                Math.floor(
                  (overlapEnd - overlapStart) / 1000
                )
              )
            : 0;

        totalSeconds += duration;

        return {
          id: item.id,
          login_at: item.login_at,
          logout_at: item.logout_at,
          duration_seconds: duration,
          status: item.logout_at
            ? "Completed"
            : "Active"
        };
      });

      return res.json({
        success: true,
        date: today,
        timezone: "Asia/Kolkata",
        total_sessions: sessions.length,
        total_seconds: totalSeconds,
        total_minutes: Math.floor(totalSeconds / 60),
        total_hours: Number(
          (totalSeconds / 3600).toFixed(2)
        ),
        sessions
      });

    } catch (error) {
      console.error(
        "Attendance history error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error: "Unable to load attendance history."
      });
    }
  }
);

/* ==========================================
   END OF ATTENDANCE HISTORY
   ========================================== */

/* ==========================================
   DIGITAL TATSAT CRM V4
   ACTIVE / IDLE TRACKING
   5-minute inactivity threshold
   ========================================== */

const ACTIVITY_TABLE = "crm_employee_daily_activity";
const ACTIVITY_IDLE_MS = 5 * 60 * 1000;
const ACTIVITY_MAX_GAP_MS = 90 * 1000;

// Current date in Indian Standard Time
function activityISTDate(ms) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(new Date(ms));

  const get = type =>
    parts.find(p => p.type === type).value;

  return `${get("year")}-${get("month")}-${get("day")}`;
}

// Next midnight in IST
function activityMidnightAfter(ms) {
  const date = activityISTDate(ms);
  return Date.parse(`${date}T00:00:00+05:30`) + 86400000;
}

// Split a tracked interval into active and idle seconds
function activityIntervals(start, end, activeUntil) {
  const activeMs = Math.max(
    0,
    Math.min(end, activeUntil) - start
  );

  return {
    active: Math.max(0, Math.round(activeMs / 1000)),
    idle: Math.max(
      0,
      Math.round((end - start - activeMs) / 1000)
    )
  };
}

// Save daily totals using optimistic concurrency control
async function activityAdd(
  req, date, active, idle, nowISO, interactionISO
) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const { data: old, error: readError } =
      await req.supabase
        .from(ACTIVITY_TABLE)
        .select(
          "id,active_seconds,idle_seconds,updated_at"
        )
        .eq("employee_id", req.crmUser.id)
        .eq("activity_date", date)
        .maybeSingle();

    if (readError) throw readError;

    if (!old) {
      const { error: insertError } =
        await req.supabase
          .from(ACTIVITY_TABLE)
          .insert({
            employee_id: req.crmUser.id,
            activity_date: date,
            active_seconds: active,
            idle_seconds: idle,
            last_seen_at: nowISO,
            last_heartbeat_at: nowISO,
            last_interaction_at: interactionISO,
            updated_at: nowISO
          });

      if (!insertError) return;

      if (insertError.code === "23505") continue;

      throw insertError;
    }

    const { data: updated, error: updateError } =
      await req.supabase
        .from(ACTIVITY_TABLE)
        .update({
          active_seconds: old.active_seconds + active,
          idle_seconds: old.idle_seconds + idle,
          last_seen_at: nowISO,
          last_heartbeat_at: nowISO,
          ...(interactionISO
            ? { last_interaction_at: interactionISO }
            : {}),
          updated_at: new Date(
            Date.now() + attempt + 1
          ).toISOString()
        })
        .eq("id", old.id)
        .eq("employee_id", req.crmUser.id)
        .eq("updated_at", old.updated_at)
        .select("id")
        .maybeSingle();

    if (updateError) throw updateError;
    if (updated) return;
  }

  throw new Error("Activity update conflict.");
}

// ==========================================
// POST: EMPLOYEE ACTIVITY HEARTBEAT
// ==========================================

app.post(
  "/api/employee/activity/heartbeat",
  verifyEmployee,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    if (typeof req.body?.interacted !== "boolean") {
      return res.status(400).json({
        success: false,
        error: "interacted must be a boolean."
      });
    }

    try {
      // Activity tracking requires manual Clock In.
      // This endpoint NEVER performs Clock Out.
      const attendance = await getOpenAttendance(req);

      if (!attendance) {
        return res.json({
          success: true,
          tracking: false,
          reason:
            "Clock In to start CRM activity tracking."
        });
      }

      const now = Date.now();
      const nowISO = new Date(now).toISOString();
      const date = activityISTDate(now);

      const { data: today, error } =
        await req.supabase
          .from(ACTIVITY_TABLE)
          .select(
            "last_heartbeat_at,last_interaction_at"
          )
          .eq("employee_id", req.crmUser.id)
          .eq("activity_date", date)
          .maybeSingle();

      if (error) throw error;

      let prior = today;

      // Preserve continuity across midnight IST
      if (!prior?.last_heartbeat_at) {
        const {
          data: previous,
          error: prevError
        } = await req.supabase
          .from(ACTIVITY_TABLE)
          .select(
            "last_heartbeat_at,last_interaction_at"
          )
          .eq("employee_id", req.crmUser.id)
          .lt("activity_date", date)
          .order("activity_date", {
            ascending: false
          })
          .limit(1)
          .maybeSingle();

        if (prevError) throw prevError;
        prior = previous;
      }

      const previousHeartbeat =
        prior?.last_heartbeat_at
          ? Date.parse(prior.last_heartbeat_at)
          : NaN;

      const previousInteraction =
        prior?.last_interaction_at
          ? Date.parse(prior.last_interaction_at)
          : NaN;

      const gap = Number.isFinite(
        previousHeartbeat
      )
        ? now - previousHeartbeat
        : 0;

      // Do not count long disconnected periods
      const start =
        gap > 0 && gap <= ACTIVITY_MAX_GAP_MS
          ? previousHeartbeat
          : now;

      const newInteraction =
        req.body.interacted ? nowISO : null;

      const activeUntil =
        req.body.interacted
          ? now
          : Number.isFinite(previousInteraction)
            ? previousInteraction + ACTIVITY_IDLE_MS
            : start;

      let cursor = start;

      while (cursor < now) {
        const finish = Math.min(
          now,
          activityMidnightAfter(cursor)
        );

        const pieces = activityIntervals(
          cursor,
          finish,
          activeUntil
        );

        await activityAdd(
          req,
          activityISTDate(cursor),
          pieces.active,
          pieces.idle,
          nowISO,
          activityISTDate(cursor) === date
            ? newInteraction
            : null
        );

        cursor = finish;
      }

      if (
        start === now ||
        activityISTDate(start) !== date
      ) {
        await activityAdd(
          req,
          date,
          0,
          0,
          nowISO,
          newInteraction
        );
      }

      return res.json({
        success: true,
        tracking: true,
        date,
        timezone: "Asia/Kolkata",
        idle_after_seconds: 300,
        state:
          req.body.interacted ||
          (
            Number.isFinite(previousInteraction) &&
            now - previousInteraction <
              ACTIVITY_IDLE_MS
          )
            ? "Active"
            : "Idle"
      });

    } catch (error) {
      console.error(
        "Activity heartbeat:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error: "Unable to record CRM activity."
      });
    }
  }
);

// ==========================================
// GET: TODAY'S ACTIVE / IDLE HOURS
// ==========================================

app.get(
  "/api/employee/activity/today",
  verifyEmployee,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    try {
      const date = activityISTDate(Date.now());

      const { data, error } =
        await req.supabase
          .from(ACTIVITY_TABLE)
          .select(
            "active_seconds,idle_seconds," +
            "last_interaction_at,last_heartbeat_at"
          )
          .eq("employee_id", req.crmUser.id)
          .eq("activity_date", date)
          .maybeSingle();

      if (error) throw error;

      return res.json({
        success: true,
        date,
        timezone: "Asia/Kolkata",
        idle_after_seconds: 300,
        active_seconds:
          data?.active_seconds || 0,
        idle_seconds:
          data?.idle_seconds || 0,
        last_interaction_at:
          data?.last_interaction_at || null,
        last_heartbeat_at:
          data?.last_heartbeat_at || null
      });

    } catch (error) {
      console.error(
        "Activity today:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error: "Unable to load CRM activity."
      });
    }
  }
);

/* END DIGITAL TATSAT CRM V4 ACTIVITY TRACKING */

// =====================================
// DIGITAL TATSAT CRM V4
// ADMIN EMPLOYEE MONITORING
// READ ONLY - NO AUTOMATIC CLOCK OUT
// =====================================

app.get(
  "/api/admin/employee-monitoring",
  verifyAdmin,
  async (req, res) => {
    res.set("Cache-Control", "no-store");

    try {
      const date = String(
        req.query.date || activityISTDate(Date.now())
      );

      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({
          success: false,
          error: "Invalid date."
        });
      }

      const dayStart = Date.parse(
        date + "T00:00:00+05:30"
      );

      if (
        !Number.isFinite(dayStart) ||
        activityISTDate(dayStart) !== date
      ) {
        return res.status(400).json({
          success: false,
          error: "Invalid calendar date."
        });
      }

      const dayEnd = dayStart + 86400000;

      const startISO =
        new Date(dayStart).toISOString();

      const endISO =
        new Date(dayEnd).toISOString();

      const [
        rolesResult,
        activityResult,
        sessionsResult
      ] = await Promise.all([

        req.supabase
          .from("crm_user_roles")
          .select("user_id,role")
          .eq("role", "employee")
          .limit(1000),

        req.supabase
          .from(ACTIVITY_TABLE)
          .select(
            "employee_id,active_seconds," +
            "idle_seconds,last_heartbeat_at," +
            "last_interaction_at"
          )
          .eq("activity_date", date)
          .limit(1000),

        req.supabase
          .from(ATTENDANCE_TABLE)
          .select(
            "id,employee_id,login_at,logout_at"
          )
          .lt("login_at", endISO)
          .or(
            `logout_at.is.null,logout_at.gt.${startISO}`
          )
          .order("login_at", {
            ascending: false
          })
          .limit(1000)

      ]);

      if (rolesResult.error) {
        throw rolesResult.error;
      }

      if (activityResult.error) {
        throw activityResult.error;
      }

      if (sessionsResult.error) {
        throw sessionsResult.error;
      }

      const employees = new Map();

      for (const row of rolesResult.data || []) {
        employees.set(row.user_id, {
          employee_id: row.user_id,
          label:
            "Employee " + row.user_id.slice(0, 8),
          active_seconds: 0,
          idle_seconds: 0,
          login_seconds: 0,
          clocked_in: false,
          last_heartbeat_at: null,
          last_interaction_at: null,
          sessions: []
        });
      }

      for (const row of activityResult.data || []) {
        const item = employees.get(row.employee_id);

        if (!item) continue;

        item.active_seconds =
          Number(row.active_seconds) || 0;

        item.idle_seconds =
          Number(row.idle_seconds) || 0;

        item.last_heartbeat_at =
          row.last_heartbeat_at;

        item.last_interaction_at =
          row.last_interaction_at;
      }

      const now = Date.now();

      for (const session of sessionsResult.data || []) {
        const item = employees.get(
          session.employee_id
        );

        if (!item) continue;

        const loginMs =
          Date.parse(session.login_at);

        const logoutMs = session.logout_at
          ? Date.parse(session.logout_at)
          : now;

        const seconds =
          Number.isFinite(loginMs) &&
          Number.isFinite(logoutMs)
            ? Math.max(
                0,
                Math.floor(
                  (
                    Math.min(
                      logoutMs,
                      dayEnd,
                      now
                    ) -
                    Math.max(
                      loginMs,
                      dayStart
                    )
                  ) / 1000
                )
              )
            : 0;

        item.login_seconds += seconds;

        if (!session.logout_at) {
          item.clocked_in = true;
        }

        item.sessions.push({
          login_at: session.login_at,
          logout_at: session.logout_at,
          duration_seconds: seconds
        });
      }

      return res.json({
        success: true,
        date,
        timezone: "Asia/Kolkata",
        employees: [...employees.values()]
      });

    } catch (error) {
      console.error(
        "Admin monitoring:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to load employee monitoring. " +
          "Check admin RLS policies."
      });
    }
  }
);

// =====================================
// END ADMIN EMPLOYEE MONITORING
// =====================================



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
  "form_name",
  "next_follow_up"
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
