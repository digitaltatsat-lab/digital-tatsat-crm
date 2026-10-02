const express = require("express");

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

        <p>
          Sales • Leads • Calling • Follow-ups • Pipeline
        </p>
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

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Digital TATSAT CRM running on port ${PORT}`);
});
