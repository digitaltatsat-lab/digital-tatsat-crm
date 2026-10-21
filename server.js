
const express = require("express");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Digital TATSAT CRM</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>

    <body style="
      margin:0;
      font-family:Arial,sans-serif;
      background:#071426;
      color:white;
      height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      text-align:center;
    ">
      <div>
        <h1>Digital TATSAT CRM</h1>
        <h2>CRM Server is Running Successfully ✅</h2>
        <p>Sales • Leads • Calling • Follow-ups • Pipeline</p>
      </div>
    </body>
    </html>
  `);
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    application: "Digital TATSAT CRM"
  });
});

// Supabase connectivity test — no customer records returned
app.get("/db-health", async (req, res) => {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;

  if (!url || !key) {
    return res.status(503).json({
      database: "configuration_missing"
    });
  }

  try {
    const supabase = createClient(url, key);

    const { error } = await supabase
      .from("LEADS 1")
      .select("id", { head: true })
      .limit(1);

    if (error) {
      console.error("Supabase connectivity check failed:", error.code);
      return res.status(503).json({
        database: "connection_or_permission_error"
      });
    }

    return res.json({
      database: "supabase_api_reachable",
      note: "Lead access not yet verified"
    });

  } catch (error) {
    console.error("Supabase connectivity exception:", error.message);

    return res.status(503).json({
      database: "connection_error"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Digital TATSAT CRM running on port ${PORT}`);
});
