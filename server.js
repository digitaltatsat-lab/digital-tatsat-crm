
const express = require("express");
const WebSocket = require("ws");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");

// Initialize Express
const app = express();

app.use(express.json());

// =====================================
// DIGITAL TATSAT CRM HOMEPAGE
// =====================================

app.get("/", (req, res) => {
  res.redirect("/login");
});

// =====================================
// PREMIUM CRM LOGIN PAGE
// =====================================

app.get("/login", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "login.html"),
    (error) => {
      if (error) {
        console.error(
          "Login page error:",
          error.message
        );

        if (!res.headersSent) {
          res.status(500).send(
            "Login page unavailable. Check login.html deployment."
          );
        }
      }
    }
  );
});

// =====================================
// SERVER HEALTH CHECK
// =====================================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    application: "Digital TATSAT CRM"
  });
});

// =====================================
// SUPABASE CONNECTION CHECK
// =====================================

app.get("/db-health", async (req, res) => {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;

  if (!url || !key) {
    return res.status(503).json({
      database: "configuration_missing"
    });
  }

  try {
    const supabase = createClient(url, key, {
      realtime: {
        transport: WebSocket
      },
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });

    const { error } = await supabase
      .from("LEADS 1")
      .select("id", { head: true })
      .limit(1);

    if (error) {
      console.error(
        "Supabase connectivity check failed:",
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
      "Supabase connectivity exception:",
      error.message
    );

    return res.status(503).json({
      database: "connection_error"
    });
  }
});

// =====================================
// START DIGITAL TATSAT CRM SERVER
// =====================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Digital TATSAT CRM running on port ${PORT}`
  );
});
