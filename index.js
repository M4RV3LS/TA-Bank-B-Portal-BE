// path file : bank-portal/bank-b/TA-BANK-B-Portal-BE/index.js
const express = require("express");
const cors = require("cors");
const connection = require("./dbConnection"); // Ensure this points to BANK B's dbConnection.js
const fetch = require("node-fetch");
const { sendToChain } = require("./toChain"); // Ensure this uses BANK B's signer/config

const profileRoutes = require("./routes/profileRoutes");
const checkBlockchain = require("./routes/checkBlokchain"); // Corrected typo: checkBlockchain
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const { ethers, JsonRpcProvider, Wallet, Contract } = require("ethers"); // Consolidate ethers import
const fs = require("fs");

const jwt = require("jsonwebtoken");
const { aesEncrypt, aesDecrypt } = require("./utils/cryptoUtils"); // <--- REQUIRE DECRYPT FUNCTION

const app = express();
const allowedOrigins = [
  // Renamed for clarity
  "http://localhost:3000", // Customer Portal Frontend
  "http://localhost:3001", // BANK B Frontend
  "http://localhost:3003", // BANK B Frontend (assuming it runs on 3003)
  // Add other allowed origins for bank frontends if necessary
];

const GATEWAY_PORTS = {
  BANK_A: 4100,
  BANK_B: 5100,
};

const util = require("util");
const queryAsync = util.promisify(connection.query).bind(connection);

function getGatewayApiBaseUrl(bankId) {
  if (!bankId) return null;
  const port = GATEWAY_PORTS[bankId.toUpperCase()];
  if (!port) {
    console.warn(`[Helper] Gateway port not found for bankId: ${bankId}`);
    return null;
  }
  return `http://localhost:${port}`;
}

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "OPTIONS", "DELETE", "PUT"],
    credentials: true,
  })
);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// --- Ethereum Setup (for BANK B) ---
// Ensure .env variables are loaded for BANK B (PRIVATE_KEY, RPC_URL, KYC_REGISTRY_ADDRESS)
require("dotenv").config(); // Ensure .env is loaded

let provider;
let signer;
let contractWithSigner;

try {
  if (
    !process.env.RPC_URL ||
    !process.env.PRIVATE_KEY ||
    !process.env.KYC_REGISTRY_ADDRESS
  ) {
    throw new Error(
      "Missing required .env variables for Ethereum setup (RPC_URL, PRIVATE_KEY, KYC_REGISTRY_ADDRESS)"
    );
  }
  provider = new JsonRpcProvider(process.env.RPC_URL);
  signer = new Wallet(process.env.PRIVATE_KEY, provider); // BANK B's signer
  const artifact = require(__dirname + "/abi/KycRegistryV3.json");
  contractWithSigner = new Contract(
    process.env.KYC_REGISTRY_ADDRESS,
    artifact.abi,
    signer
  );
  console.log(
    `[ETH Setup BANK B] Connected to contract ${process.env.KYC_REGISTRY_ADDRESS} with signer ${signer.address}`
  );
} catch (ethSetupError) {
  console.error(
    "FATAL: Ethereum setup failed for BANK B backend:",
    ethSetupError
  );
  // Decide if the app should exit or continue with limited functionality
  // process.exit(1);
}

// --- Routes ---

// GET all KYC requests
app.get("/kyc-requests", (req, res) => {
  const { client_id } = req.query;
  let sql = `SELECT * FROM user_kyc_request`;
  const params = [];
  if (client_id) {
    sql += ` WHERE client_id = ?`;
    params.push(client_id);
  }
  sql += ` ORDER BY created_at DESC`;
  connection.query(sql, params, (err, rows) => {
    if (err) {
      console.error("[GET /kyc-requests] MySQL GET error:", err);
      return res.status(500).json({ error: "Failed to fetch requests" });
    }
    res.json(rows);
  });
});

// POST a new KYC request
app.post(
  "/kyc-requests",
  upload.fields([
    { name: "ktp", maxCount: 1 },
    { name: "kyc", maxCount: 1 },
  ]),
  async (req, res) => {
    let {
      client_id,
      customer_name,
      customer_email,
      customer_phone,
      status_request = "new",
      home_bank_code = null,
    } = req.body;

    if (!["new", "update", "reuse_kyc"].includes(status_request)) {
      return res.status(400).json({
        error: "Invalid status_request (must be new, update, or reuse_kyc)",
      });
    }

    if (!client_id || !customer_name) {
      // Email and phone are no longer required here
      return res.status(400).json({
        error: "Missing required fields (client_id, name)",
      });
    }

    let customer_ktp_datauri = null;
    let customer_kyc_datauri = null;
    let profileId = null;

    if (status_request === "new" || status_request === "update") {
      const ktpFile = req.files?.ktp?.[0];
      const kycFile = req.files?.kyc?.[0];

      if (!ktpFile || !kycFile) {
        return res
          .status(400)
          .json({ error: "Missing KTP/KYC files for new/update request" });
      }

      const readUri = (f) => {
        const b = fs.readFileSync(f.path);
        fs.unlinkSync(f.path);
        return `data:${f.mimetype};base64,${b.toString("base64")}`;
      };
      customer_ktp_datauri = readUri(ktpFile);
      customer_kyc_datauri = readUri(kycFile);

      profileId = ethers.solidityPackedKeccak256(
        ["uint256", "string", "string"],
        [client_id, customer_ktp_datauri, customer_kyc_datauri]
      );
    }

    const sql = `
    INSERT INTO user_kyc_request
      (client_id, customer_name, customer_email, customer_phone,
       customer_ktp, customer_kyc, profile_id,
       status_kyc, status_request, home_bank_code)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'submitted', ?, ?)
  `;

    connection.query(
      sql,
      [
        client_id,
        customer_name,
        customer_email || null, // Insert null if not provided
        customer_phone || null, // Insert null if not provided
        customer_ktp_datauri,
        customer_kyc_datauri,
        profileId,
        status_request,
        home_bank_code,
      ],
      (err, result) => {
        if (err) {
          console.error("[POST /kyc-requests] MySQL INSERT error:", err);
          return res
            .status(500)
            .json({ error: "Could not save request", detail: err.message });
        }
        res.status(201).json({
          request_id: result.insertId,
          status_kyc: "submitted",
          status_request,
          profile_id: profileId,
        });
      }
    );
  }
);

// --- ADDED: DB Logger function ---
async function logTransactionToDb(txData) {
  const {
    txHash,
    requestId,
    clientId,
    txType,
    ethAmountWei, // Note: We'll pass Wei directly here
    receipt,
    version, // Will be null for 'pay'
    issuerAddress,
  } = txData;

  const sql = `
    INSERT INTO blockchain_transactions
      (tx_hash, request_id, client_id, tx_type, eth_amount_wei, onchain_status, 
       block_number, gas_used, version, issuer_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  console.log(
    `[DB Logger] Attempting to log tx ${txHash} for request ${requestId}.`
  );
  const dbLogStartTime = Date.now();

  try {
    const params = [
      txHash,
      requestId,
      clientId,
      txType,
      ethAmountWei, // Already in Wei
      receipt.status,
      receipt.blockNumber,
      receipt.gasUsed.toString(),
      version,
      issuerAddress,
    ];

    await queryAsync(sql, params);
    const dbLogEndTime = Date.now();
    const dbLogDurationMs = dbLogEndTime - dbLogStartTime;

    console.log(
      `[DB Logger] Successfully logged tx ${txHash}. DB write took: ${dbLogDurationMs}ms.`
    );
  } catch (dbErr) {
    console.error(
      `[DB Logger] CRITICAL ERROR: Failed to log successful tx ${txHash} to database. Manual check required.`,
      dbErr
    );
  }
}

// STREAM KTP IMAGE
app.get("/kyc-requests/:id/ktp", (req, res) => {
  const { id } = req.params;
  connection.query(
    "SELECT customer_ktp FROM user_kyc_request WHERE request_id = ?",
    [id],
    (err, rows) => {
      if (err) return res.status(500).send("Server error");
      if (rows.length === 0 || !rows[0].customer_ktp)
        return res.status(404).send("KTP Not found or not available");

      const dataUri = rows[0].customer_ktp;
      const parts = dataUri.match(/^data:(.+);base64,(.+)$/);
      if (!parts) return res.status(500).send("Invalid KTP data URI");

      const [, mimeType, b64] = parts;
      const buffer = Buffer.from(b64, "base64");
      res.setHeader("Content-Type", mimeType);
      res.send(buffer);
    }
  );
});

// STREAM KYC PDF
app.get("/kyc-requests/:id/kyc", (req, res) => {
  const { id } = req.params;
  connection.query(
    `SELECT customer_kyc FROM user_kyc_request WHERE request_id = ?`,
    [id],
    (err, rows) => {
      if (err) return res.status(500).send("Server error");
      if (rows.length === 0 || !rows[0].customer_kyc)
        return res.status(404).send("KYC PDF Not found or not available");

      const customerKycDataUri = rows[0].customer_kyc;
      if (!customerKycDataUri) {
        console.warn(
          `[GET /kyc-requests/:id/kyc] customer_kyc data is null/empty for request_id: ${id}.`
        );
        return res
          .status(404)
          .send("KYC document content not available for this request yet.");
      }

      const match = customerKycDataUri.match(/^data:(.+);base64,(.+)$/);
      if (!match)
        return res.status(500).send("Invalid KYC data URI format in database");

      const mimeType = match[1];
      const b64 = match[2];
      const buffer = Buffer.from(b64, "base64");

      res.setHeader("Content-Type", mimeType);
      res.setHeader("Content-Length", buffer.length);
      res.setHeader("Content-Disposition", `inline; filename="kyc-${id}.pdf"`);
      return res.end(buffer);
    }
  );
});

// INLINE-EMBED HTML wrapper for KYC PDF
app.get("/kyc-requests/:id/view", (req, res) => {
  const { id } = req.params;
  connection.query(
    "SELECT customer_kyc FROM user_kyc_request WHERE request_id = ?",
    [id],
    (err, rows) => {
      if (err) return res.status(500).send("Server error");
      if (rows.length === 0 || !rows[0].customer_kyc)
        return res
          .status(404)
          .send("KYC PDF Not found or not available for viewing");

      const dataUri = rows[0].customer_kyc;
      if (!dataUri.startsWith("data:application/pdf;base64,")) {
        return res
          .status(500)
          .send("Invalid or non-PDF KYC data URI for viewing.");
      }

      res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8"/>
            <title>View KYC #${id}</title>
            <style>html,body{margin:0;height:100%}embed{width:100%;height:100%}</style>
          </head>
          <body>
            <embed 
              type="application/pdf" 
              src="${dataUri}" 
              frameborder="0"
            />
          </body>
        </html>
      `);
    }
  );
});

// Send to Dukcapil
app.post("/kyc-requests/:id/send-to-dukcapil", (req, res) => {
  const { id } = req.params;
  connection.query(
    "SELECT * FROM user_kyc_request WHERE request_id = ?",
    [id],
    async (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!rows.length) return res.status(404).json({ error: "Not found" });
      const r = rows[0];

      const payload = {
        bank_request_id: r.request_id,
        client_id: r.client_id,
        customer_name: r.customer_name,
        customer_email: r.customer_email,
        customer_phone: r.customer_phone,
        customer_ktp: r.customer_ktp,
        customer_kyc: r.customer_kyc,
      };
      console.log("[Dukcapil] Sending to Dukcapil:", payload.client_id);

      try {
        const dukRes = await fetch(
          "http://localhost:5002/dukcapil/kyc-requests", // Make sure Dukcapil URL is configurable
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          }
        );
        console.log("[Dukcapil] Dukcapil responded status:", dukRes.status);
        if (!dukRes.ok) {
          const errJson = await dukRes
            .json()
            .catch(() => ({ error: dukRes.statusText }));
          console.error("[Dukcapil] Dukcapil error body:", errJson);
          return res
            .status(502)
            .json({ error: "Dukcapil error", detail: errJson });
        }
      } catch (e) {
        console.error("[Dukcapil] Could not reach Dukcapil:", e);
        return res
          .status(502)
          .json({ error: "Could not reach Dukcapil", detail: e.message });
      }

      connection.query(
        `UPDATE user_kyc_request SET status_kyc = 'in review' WHERE request_id = ?`,
        [id],
        (uErr) => {
          if (uErr) {
            console.error("[Dukcapil] MySQL UPDATE error:", uErr);
            return res
              .status(500)
              .json({ error: "Could not update status", detail: uErr.message });
          }
          console.log(`[Dukcapil] Request ${id} marked “in review” in DB.`);
          res.json({ message: "Sent to Dukcapil", status: "in review" });
        }
      );
    }
  );
});

// Pull status from Dukcapil
app.get("/dukcapil-status/:requestId", async (req, res) => {
  const { requestId } = req.params;
  try {
    const dukRes = await fetch(
      `http://localhost:5002/dukcapil/kyc-requests/${requestId}` // Make sure Dukcapil URL is configurable
    );

    if (!dukRes.ok) {
      const errorJson = await dukRes
        .json()
        .catch(() => ({ error: dukRes.statusText }));
      return res.status(dukRes.status).json(errorJson);
    }
    const { status: dukStatus, note } = await dukRes.json();

    let bankStatus;
    switch (dukStatus) {
      case "in review":
        bankStatus = "in review";
        break;
      case "verified":
        bankStatus = "verified";
        break;
      case "rejected":
        bankStatus = "failed";
        break;
      default:
        bankStatus = "submitted";
        break;
    }
    await new Promise((ok, nok) =>
      connection.query(
        `UPDATE user_kyc_request SET status_kyc = ?, note = ? WHERE request_id = ?`,
        [bankStatus, note, requestId],
        (e) => (e ? nok(e) : ok())
      )
    );
    res.json({ status: bankStatus, note });
  } catch (e) {
    console.error("[Dukcapil Status] Error:", e);
    res.status(502).json({ error: "Could not fetch status from Dukcapil" });
  }
});

// Send to Chain
app.post("/kyc-requests/:id/send-to-chain", async (req, res) => {
  const { id } = req.params;
  console.log(`[send-to-chain] Called for request_id=${id}`);
  connection.query(
    `SELECT request_id, client_id, customer_ktp, customer_kyc, status_kyc, status_request
     FROM user_kyc_request WHERE request_id = ?`,
    [id],
    async (err, rows) => {
      if (err) {
        console.error("[send-to-chain] DB error loading request:", err);
        return res.status(500).json({ error: err.message });
      }
      if (!rows.length) {
        console.warn(`[send-to-chain] No such request ${id}`);
        return res.status(404).json({ error: "Not found" });
      }
      const r = rows[0];
      if (r.status_kyc === "success") {
        console.log(
          `[send-to-chain] Request ${id} already on-chain, skipping.`
        );
        return res.json({
          message: "Already on chain",
          txHash: null,
          status: "success",
        });
      }
      const requestRow = {
        request_id: r.request_id,
        client_id: r.client_id,
        customer_ktp: r.customer_ktp,
        customer_kyc: r.customer_kyc,
        status_kyc: r.status_kyc,
        status_request: r.status_request,
      };
      try {
        const result = await sendToChain(requestRow); // from ./toChain.js
        if (result.success) {
          return res.json({
            message: "Added to chain",
            txHash: result.txHash,
            version: result.version ?? null,
            status: "success",
          });
        } else {
          return res
            .status(500)
            .json({ message: "Chain call failed", error: result.error });
        }
      } catch (e) {
        console.error("[send-to-chain] Error:", e);
        return res
          .status(500)
          .json({ error: "Blockchain write failed", detail: e.message });
      }
    }
  );
});

// Pay endpoint
// In bank-b/backend/index.js (and bank-b/backend/index.js)

// bank-portal/bank-b/backend/index.js (or bank-b/backend/index.js)
// Ensure 'express', 'connection', 'contractWithSigner', 'ethers' are imported/available

// bank-portal/bank-b/backend/index.js (or bank-b/backend/index.js)
// Ensure 'express', 'connection', 'contractWithSigner', 'ethers' are imported/available

app.post("/kyc-requests/:id/pay", express.json(), async (req, res) => {
  const idFromParams = req.params.id;
  const id = Number(idFromParams);
  let paymentAmountInWei = req.body.amount; // Might be undefined

  const bankIdentifier = process.env.THIS_BANK_IDENTIFIER || "UNKNOWN_BANK";

  console.log(
    `[PAY on ${bankIdentifier}] Request for endpoint /kyc-requests/${idFromParams}/pay`
  );
  console.log(
    `[PAY on ${bankIdentifier}] Parsed Request ID: ${id} (Type: ${typeof id})`
  );
  console.log(
    `[PAY on ${bankIdentifier}] Received req.body:`,
    JSON.stringify(req.body)
  ); // Stringify to see empty object vs undefined
  console.log(
    `[PAY on ${bankIdentifier}] Initial paymentAmountInWei from req.body.amount: ${paymentAmountInWei}`
  );

  if (isNaN(id)) {
    console.error(
      `[PAY on ${bankIdentifier}] Invalid Request ID: ${idFromParams}. Must be a number.`
    );
    return res.status(400).json({ error: "Invalid Request ID format." });
  }

  try {
    // 1. Fetch the request details from this bank's database
    const requestRows = await new Promise((resolve, reject) => {
      const sqlQuery =
        "SELECT request_id, client_id, status_request, home_bank_code FROM user_kyc_request WHERE request_id = ?";
      console.log(
        `[PAY on ${bankIdentifier}] Executing SQL: ${sqlQuery} with parameter: [${id}] (Type: ${typeof id})`
      );

      connection.query(sqlQuery, [id], (err, results) => {
        if (err) {
          console.error(
            `[PAY on ${bankIdentifier}] SQL Error for request_id ${id}:`,
            err
          );
          return reject(new Error(`Database query failed: ${err.message}`)); // Reject with a proper error
        }
        if (results && results.length > 0) {
          console.log(
            `[PAY on ${bankIdentifier}] SQL Query successful for request_id ${id}. Row found:`,
            results[0]
          );
        } else {
          console.log(
            `[PAY on ${bankIdentifier}] SQL Query successful but no rows found for request_id ${id}. Results:`,
            results
          );
        }
        resolve(results); // 'results' is typically an array of row objects
      });
    });

    if (!requestRows || requestRows.length === 0) {
      console.warn(
        `[PAY on ${bankIdentifier}] Request not found in database for ID: ${id}.`
      );
      return res
        .status(404)
        .json({ error: "Request not found in this bank's database" });
    }

    const {
      client_id: clientId,
      status_request,
      home_bank_code: requestHomeBankCode, // Used for logging, not critical for payment logic itself here
    } = requestRows[0];

    console.log(
      `[PAY on ${bankIdentifier}] Request found for ID: ${id}. Client ID: ${clientId}, Status Request: ${status_request}, Home Bank Code (from DB): ${requestHomeBankCode}`
    );

    if (!contractWithSigner) {
      console.error(
        `[PAY on ${bankIdentifier}] Ethereum contract (contractWithSigner) is not initialized for ${bankIdentifier}!`
      );
      return res.status(500).json({
        error: "Blockchain service unavailable. Contract not initialized.",
      });
    }

    // 2. Determine the payment amount based on the request type and on-chain state
    if (status_request === "reuse_kyc") {
      console.log(
        `[PAY on ${bankIdentifier}] Handling 'reuse_kyc' for client ${clientId}, request ${id}. Home bank (on-chain target) for this KYC data is: ${requestHomeBankCode}.`
      );

      let contractTotalBill, participantsArray, k_existing;
      try {
        contractTotalBill = await contractWithSigner.totalBill(clientId);
        participantsArray = await contractWithSigner.getParticipatingBanks(
          clientId
        );
        k_existing = BigInt(participantsArray.length);
      } catch (contractError) {
        console.error(
          `[PAY on ${bankIdentifier}] Error fetching data from smart contract for client ${clientId}:`,
          contractError
        );
        return res.status(502).json({
          error: "Failed to query smart contract state.",
          detail: contractError.message,
        });
      }

      const newTotalParticipants = k_existing + 1n; // This bank is the +1

      console.log(
        `[PAY on ${bankIdentifier}] Client ${clientId} - On-chain totalBill: ${contractTotalBill.toString()}, k_existing participants: ${k_existing}`
      );

      if (k_existing === 0n && BigInt(contractTotalBill) === 0n) {
        console.log(
          `[PAY on ${bankIdentifier}] This is the first 'reuse_kyc' participant setting the totalBill.`
        );
        if (!req.body.amount || BigInt(req.body.amount) <= 0n) {
          const errorMsg = `For first 'reuse_kyc' participant (k_existing=0, totalBill=0), an initial payment amount (req.body.amount) must be provided by the client/frontend. None was provided or amount was invalid for request ${id}. Received amount: ${req.body.amount}`;
          console.error(`[PAY on ${bankIdentifier}] ${errorMsg}`);
          return res.status(400).json({
            error:
              "Initial payment amount required from frontend for first reuse participant.",
            detail: errorMsg,
          });
        }
        paymentAmountInWei = req.body.amount.toString();
        console.log(
          `[PAY on ${bankIdentifier}] Using provided amount from frontend: ${paymentAmountInWei} wei to set initial totalBill for client ${clientId}.`
        );
      } else if (BigInt(contractTotalBill) > 0n) {
        if (newTotalParticipants === 0n) {
          // Should be impossible if k_existing >= 0
          console.error(
            `[PAY on ${bankIdentifier}] Pool size calculation error for client ${clientId} - newTotalParticipants is 0, but totalBill > 0.`
          );
          return res.status(500).json({
            error: "Pool size calculation error (newTotalParticipants is 0).",
          });
        }
        const expectedShare = BigInt(contractTotalBill) / newTotalParticipants;
        paymentAmountInWei = expectedShare.toString();
        console.log(
          `[PAY on ${bankIdentifier}] Calculated payment for 'reuse_kyc' (client ${clientId}, request ${id}): ${paymentAmountInWei} wei. (totalBill: ${contractTotalBill}, k_existing: ${k_existing}, newTotalParticipants: ${newTotalParticipants})`
        );
      } else {
        // totalBill is 0 but k_existing > 0. (Unusual state)
        const errorMsg = `Unexpected on-chain payment state for client ${clientId}: totalBill is ${contractTotalBill.toString()} and k_existing is ${k_existing}. Cannot automatically calculate share. An initial amount from frontend might be needed.`;
        console.error(`[PAY on ${bankIdentifier}] ${errorMsg}`);
        if (req.body.amount && BigInt(req.body.amount) > 0n) {
          paymentAmountInWei = req.body.amount.toString();
          console.warn(
            `[PAY on ${bankIdentifier}] Using provided amount ${paymentAmountInWei} due to unclear on-chain state for share calculation (totalBill=0, k_existing>0).`
          );
        } else {
          return res.status(400).json({
            error:
              "Cannot calculate payment share due to unusual on-chain state. Amount required from frontend.",
            detail: errorMsg,
          });
        }
      }
    } else {
      // Not 'reuse_kyc' (e.g., "new" or "update")
      console.log(
        `[PAY on ${bankIdentifier}] Handling '${status_request}' (not reuse_kyc) for client ${clientId}, request ${id}. This typically means payment for new/update KYC.`
      );
      // If this /pay endpoint is used for "new" or "update", frontend MUST provide an amount.
      // `sendToChain` usually handles payments for "new" or "update".
      // This path in /pay might be if payment failed during `sendToChain` and is being retried,
      // or if frontend has a separate pay button for new/update.
      if (!paymentAmountInWei) {
        // paymentAmountInWei was initialized from req.body.amount
        const errorMsg = `Payment amount (req.body.amount) is required in the payload for '${status_request}' payment type at this /pay endpoint. Request ID: ${id}.`;
        console.error(`[PAY on ${bankIdentifier}] ${errorMsg}`);
        return res.status(400).json({
          error: "Payment amount required for this request type.",
          detail: errorMsg,
        });
      }
      console.log(
        `[PAY on ${bankIdentifier}] Using provided amount from frontend for '${status_request}': ${paymentAmountInWei} wei.`
      );
    }

    // 3. Final validation of paymentAmountInWei before sending to contract
    if (!paymentAmountInWei || BigInt(paymentAmountInWei) <= 0n) {
      console.warn(
        `[PAY on ${bankIdentifier}] Final check failed: Missing, zero, or negative payment amount calculated/provided for request ${id}. Amount: ${paymentAmountInWei}`
      );
      return res.status(400).json({
        error:
          "Invalid payment amount (zero, negative, or missing after processing).",
      });
    }

    console.log(
      `[PAY on ${bankIdentifier}] Proceeding with on-chain payment for request ${id}, client ${clientId}. Amount: ${paymentAmountInWei} wei. Using signer: ${signer.address}`
    );

    // 4. Execute on-chain payment

    // --- START: Execution Time Logging ---
    const startTime = Date.now();
    // --- END: Execution Time Logging ---

    const tx = await contractWithSigner.pay(clientId, {
      value: paymentAmountInWei,
    });
    console.log(
      `[PAY on ${bankIdentifier}] Payment transaction sent for request ${id}. Tx hash: ${tx.hash}. Waiting for receipt...`
    );

    const receipt = await tx.wait(); // Wait for transaction to be mined

    // --- START: Execution Time Logging ---
    const endTime = Date.now();
    const executionTime = (endTime - startTime) / 1000; // in seconds
    console.log(
      `[PAY on ${bankIdentifier}] Payment transaction MINED for request ${id}. Execution Time: ${executionTime} seconds.`
    );
    // --- END: Execution Time Logging ---

    console.log(
      `[PAY on ${bankIdentifier}] Payment transaction mined for request ${id}. Block: ${
        receipt.blockNumber
      }, Status: ${receipt.status === 1 ? "Success" : "Failed"}`
    );

    if (receipt.status !== 1) {
      console.error(
        `[PAY on ${bankIdentifier}] On-chain payment transaction failed for request ${id}. Tx hash: ${tx.hash}`
      );
      throw new Error(
        `On-chain payment transaction failed. Tx hash: ${tx.hash}. Status: ${receipt.status}`
      );
    }

    // --- ADDED: Log to DB on success ---
    await logTransactionToDb({
      txHash: receipt.hash,
      requestId: id,
      clientId: clientId,
      txType: "pay",
      ethAmountWei: paymentAmountInWei, // Pass the Wei amount directly
      receipt: receipt,
      version: null, // No specific version for a 'pay' transaction
      issuerAddress: signer.address,
    });
    // --- END ADDED ---

    // 5. Update local database status
    await new Promise((resolve, reject) => {
      connection.query(
        `UPDATE user_kyc_request SET status_kyc = 'paid' WHERE request_id = ?`,
        [id],
        (err, result) => {
          if (err) {
            console.error(
              `[PAY on ${bankIdentifier}] DB Error updating status to 'paid' for request ${id}:`,
              err
            );
            return reject(
              new Error(`Failed to update local DB status: ${err.message}`)
            );
          }
          console.log(
            `[PAY on ${bankIdentifier}] DB status updated to 'paid' for request ${id}. Affected rows: ${result.affectedRows}`
          );
          resolve(result);
        }
      );
    });

    // 6. Respond with success
    const events = receipt.logs
      ?.map((log) => {
        try {
          const parsedLog = contractWithSigner.interface.parseLog(log);
          return parsedLog?.name;
        } catch {
          return "UnknownLog";
        }
      })
      .filter((name) => name !== "UnknownLog");

    console.log(
      `[PAY on ${bankIdentifier}] Payment process completed successfully for request ${id}.`
    );
    return res.json({
      message: "Payment successful and status updated.",
      txHash: tx.hash,
      amountPaid: paymentAmountInWei, // Send back the actual amount processed
      clientId: clientId,
      requestId: id,
      blockNumber: receipt.blockNumber,
      events: events,
      executionTimeSeconds: executionTime,
    });
  } catch (error) {
    console.error(
      `[PAY on ${bankIdentifier}] CATCH BLOCK: Critical error during payment processing for request_id ${id}:`,
      error.message,
      error.stack
    );
    const errorMessage =
      error.reason ||
      error.data?.message ||
      error.error?.message ||
      error.message ||
      "Payment processing failed due to an unexpected error.";

    // Check if the error is from ethers.js, it might have a `data` field with revert reason
    let errorDetail = errorMessage;
    if (error.data && typeof error.data.message === "string") {
      // Ethers.js specific revert reason
      errorDetail = error.data.message;
    } else if (error.error && error.error.message) {
      // Another common pattern for Ethers.js errors
      errorDetail = error.error.message;
    }

    if (!res.headersSent) {
      return res
        .status(500)
        .json({ error: "Payment processing failed", detail: errorDetail });
    }
  }
});

// Get On-Chain History
// bank-portal/bank-b/backend/index.js

app.get("/kyc-requests/:clientId/onchain-history", async (req, res) => {
  const clientId = Number(req.params.clientId);
  if (isNaN(clientId) || clientId <= 0) {
    return res.status(400).json({ error: "Invalid clientId" });
  }

  if (!contractWithSigner) {
    console.error("[onchain-history] Ethereum contract not initialized!");
    return res.status(500).json({ error: "Blockchain service unavailable." });
  }

  try {
    console.log(
      `[onchain-history] Fetching for clientId: ${clientId}, Contract: ${await contractWithSigner.getAddress()}`
    );

    // ✅ Defensive contract call
    // Check if a record exists first by calling a function that we know will revert.
    try {
      await contractWithSigner.getVersionCount(clientId); // This uses the hasKycRecord modifier
    } catch (checkError) {
      // If this call reverts, it's almost certain no record exists.
      console.warn(
        `[onchain-history] No on-chain record found for clientId ${clientId}. Returning empty history.`
      );
      return res.json({ totalBill: "0", versions: [], participatingBanks: [] });
    }

    // If the check above passed, we can safely call the other functions.
    const totalBillBig = await contractWithSigner.totalBill(clientId);
    const versionCountBig = await contractWithSigner.getVersionCount(clientId);
    const participatingBanksRaw =
      await contractWithSigner.getParticipatingBanks(clientId);

    const versionCount = Number(versionCountBig);
    let parsedVersions = [];

    if (versionCount > 0) {
      const rawPromises = [];
      for (let v = 1; v <= versionCount; v++) {
        rawPromises.push(contractWithSigner.getKycByVersion(clientId, v));
      }
      const rawRecords = await Promise.all(rawPromises);
      parsedVersions = rawRecords.map((raw) => ({
        version: Number(raw.version),
        hashKtp: raw.hashKtp,
        hashKyc: raw.hashKyc,
        status: raw.status,
        timestamp: Number(raw.timestamp),
        issuer: raw.issuer,
        revoked: raw.revoked,
      }));
    }

    return res.json({
      totalBill: totalBillBig.toString(),
      versions: parsedVersions,
      participatingBanks: participatingBanksRaw.map((addr) => addr.toString()),
    });
  } catch (err) {
    console.error(`[onchain-history] Error for clientId ${clientId}:`, err);
    return res.status(502).json({
      error: "On-chain lookup failed",
      detail: err.message,
    });
  }
});

// DELETE a KYC request
app.delete("/kyc-requests/:id", (req, res) => {
  const { id } = req.params;
  connection.query(
    `DELETE FROM user_kyc_request WHERE request_id = ?`,
    [id],
    (err) => {
      if (err) {
        console.error("[DELETE /kyc-requests] MySQL DELETE error:", err);
        return res.status(500).json({ error: "Delete failed" });
      }
      connection.query(
        `DELETE FROM user_profile_id WHERE request_id = ?`,
        [id],
        () => {}
      );
      res.json({ message: "Deleted" });
    }
  );
});

// Fetch and Verify Reuse KYC Data (Endpoint called by BANK B's frontend)
app.post(
  "/kyc-requests/:id/fetch-and-verify-reuse",
  express.json(),
  async (req, res) => {
    // --- PERFORMANCE MEASUREMENT START ---
    const startTime = performance.now();
    let durationMs = -1; // Default value
    const { id: requestId } = req.params;
    const thisBankSignerAddress = await signer.getAddress(); // BANK A's address
    const thisBankIdentifier = process.env.THIS_BANK_IDENTIFIER;
    const customerPortalApiKey =
      process.env.CUSTOMER_PORTAL_API_KEY_FOR_THIS_BANK;
    const interBankJwtSecret =
      process.env.GATEWAY_JWT_SECRET_FOR_INTERBANK_AUTH;
    const customerPortalInternalApiUrl =
      process.env.CUSTOMER_PORTAL_INTERNAL_API_URL;

    console.log(
      `[FETCH-REUSE DEBUG] Request ID: ${requestId} - Starting process.`
    );
    console.log(
      `[FETCH-REUSE DEBUG] This Bank Identifier: ${thisBankIdentifier}, Signer Address: ${thisBankSignerAddress}`
    );

    if (
      !thisBankIdentifier ||
      !customerPortalApiKey ||
      !interBankJwtSecret ||
      !customerPortalInternalApiUrl ||
      !contractWithSigner
    ) {
      console.error(
        "[FETCH-REUSE] Missing critical environment variables or contract not initialized."
      );
      return res
        .status(500)
        .json({ error: "Internal server configuration error." });
    }

    try {
      const [requestDetailsArr] = await new Promise((resolve, reject) =>
        connection.query(
          `SELECT client_id, home_bank_code FROM user_kyc_request 
           WHERE request_id = ? AND status_request = 'reuse_kyc' AND status_kyc = 'paid'`,
          [requestId],
          (err, rows) => (err ? reject(err) : resolve([rows]))
        )
      );

      if (!requestDetailsArr || !requestDetailsArr.length) {
        return res.status(404).json({
          error: `Valid 'reuse_kyc' request in 'paid' state not found for ID ${requestId}.`,
        });
      }
      const { client_id: clientId, home_bank_code: actualHomeBankCode } =
        requestDetailsArr[0];
      console.log(
        `[FETCH-REUSE DEBUG] Fetched from DB: clientId=${clientId}, actualHomeBankCode=${actualHomeBankCode}`
      );

      if (!actualHomeBankCode) {
        return res.status(400).json({
          error: "Home bank information not recorded for this reuse request.",
        });
      }

      // 1. Securely request the customerDecryptKey from Customer Portal Backend
      let customerDecryptKey;
      const keyRequestUrl = `${customerPortalInternalApiUrl}/request-decryption-key`; // CP's internal API
      try {
        console.log(
          `[FETCH-REUSE DEBUG] 2.1. Requesting decrypt_key for user ${clientId} from CP (${keyRequestUrl}) as bank ${thisBankIdentifier}`
        );
        const cpResponse = await fetch(keyRequestUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": customerPortalApiKey,
          },
          body: JSON.stringify({
            userId: Number(clientId) /* CP expects userId */,
          }),
        });
        const keyData = await cpResponse.json();
        if (!cpResponse.ok) {
          console.error(
            `[FETCH-REUSE DEBUG] 2.3. Failed to get decrypt_key from CP. Status: ${cpResponse.status}`,
            keyData
          );
          return res.status(502).json({
            error: "Failed to obtain decryption key from Customer Portal.",
            detail: keyData.error,
          });
        }
        customerDecryptKey = keyData.decryptKey;
        if (!customerDecryptKey)
          throw new Error(
            "Customer Portal did not return a valid decryption key."
          );
        // In bank-a/backend/index.js
        console.log(
          `[FETCH-REUSE DEBUG] 2.4. Successfully obtained customerDecryptKey (first 6 chars): ${customerDecryptKey.substring(
            0,
            6
          )}...`
        );
      } catch (keyReqError) {
        console.error(
          "[FETCH-REUSE DEBUG] 2.5. Error requesting/processing decryption key from CP:",
          keyReqError
        );
        return res.status(500).json({
          error: "Could not obtain necessary decryption key.",
          detail: keyReqError.message,
        });
      }

      // 2. Determine Home Bank's Gateway URL
      const homeBankGatewayUrl = getGatewayApiBaseUrl(actualHomeBankCode); // e.g., BANK_A -> http://localhost:4100
      if (!homeBankGatewayUrl) {
        console.error(
          `[FETCH-REUSE DEBUG] 3.2. Gateway URL for Home Bank ${actualHomeBankCode} not found.`
        );
        return res.status(500).json({
          error: `Configuration error for Home Bank Gateway (${actualHomeBankCode}).`,
        });
      }
      console.log(
        `[FETCH-REUSE DEBUG] 3.1. Home Bank Code: ${actualHomeBankCode}, Gateway URL: ${homeBankGatewayUrl}`
      );

      // 3. Generate This Bank's (BANK A's) JWT badge for Home Bank Gateway (BANK A's Gateway)
      const interBankJwtBadge = jwt.sign(
        { address: thisBankSignerAddress },
        interBankJwtSecret,
        { expiresIn: "5m" }
      );
      console.log(
        `[FETCH-REUSE DEBUG] 4.1. Generated Inter-Bank JWT Badge (payload has address: ${thisBankSignerAddress}).`
      );

      // 4. Fetch encrypted bundle from Home Bank Gateway
      console.log(
        `[FETCH-REUSE DEBUG] 5.1. Requesting KYC bundle from Home Bank Gateway: ${homeBankGatewayUrl}/kyc-files/${clientId}`
      );
      const gatewayResp = await fetch(
        `${homeBankGatewayUrl}/kyc-files/${clientId}`,
        {
          headers: { Authorization: `Bearer ${interBankJwtBadge}` },
        }
      );

      console.log(
        `[FETCH-REUSE DEBUG] 5.2. Home Bank Gateway response status: ${gatewayResp.status}`
      );
      if (!gatewayResp.ok) {
        const errorBody = await gatewayResp
          .json()
          .catch(() => ({ error: gatewayResp.statusText }));
        console.error(
          "[FETCH-REUSE DEBUG] 5.3. Error from Home Bank Gateway:",
          errorBody
        );
        return res.status(gatewayResp.status).json({
          error: "Failed to fetch KYC bundle from Home Bank Gateway.",
          detail: errorBody.error || errorBody,
        });
      }
      const encryptedBundleHex = await gatewayResp.text(); // Gateway sends raw text
      if (!encryptedBundleHex) {
        console.error(
          "[FETCH-REUSE DEBUG] 5.4. Home Bank Gateway returned an empty bundle."
        );
        return res
          .status(502)
          .json({ error: "Home Bank Gateway returned an empty KYC bundle." });
      }
      console.log(
        `[FETCH-REUSE DEBUG] 5.5. Received full encryptedBundleHex. Length: ${encryptedBundleHex.length}`
      );
      console.log(
        `[FETCH-REUSE DEBUG] 5.5. Full encryptedBundleHex (first 100 chars): ${encryptedBundleHex.substring(
          0,
          100
        )}...`
      );

      // 5. Decrypt the bundle
      let decryptedKtpDataUri, decryptedKycDataUri;
      try {
        console.log(
          `[FETCH-REUSE DEBUG] 6.1. Attempting to decrypt bundle with key (first 6 chars): ${customerDecryptKey.substring(
            0,
            6
          )}...`
        );
        const decryptedBundleJsonString = aesDecrypt(
          encryptedBundleHex,
          customerDecryptKey
        ); // Using imported decrypt
        const bundleContent = JSON.parse(decryptedBundleJsonString);
        decryptedKtpDataUri = bundleContent.ktpData;
        decryptedKycDataUri = bundleContent.kycData;
        if (!decryptedKtpDataUri || !decryptedKycDataUri)
          throw new Error("Decrypted bundle missing KTP or KYC data.");
        console.log(
          `[FETCH-REUSE DEBUG] 6.3. Successfully decrypted bundle for client ${clientId}.`
        );
      } catch (e) {
        console.error(
          "[FETCH-REUSE DEBUG] 6.5. Decryption of bundle failed:",
          e
        );
        return res
          .status(500)
          .json({ error: "Failed to decrypt KYC bundle.", detail: e.message });
      }

      // 6. Store decrypted data URIs and generate local profile_id hash
      const localGeneratedProfileId = ethers.solidityPackedKeccak256(
        ["uint256", "string", "string"],
        [BigInt(clientId), decryptedKtpDataUri, decryptedKycDataUri]
      );
      await new Promise((ok, nok) =>
        connection.query(
          `UPDATE user_kyc_request SET customer_ktp = ?, customer_kyc = ?, profile_id = ? WHERE request_id = ?`,
          [
            decryptedKtpDataUri,
            decryptedKycDataUri,
            localGeneratedProfileId,
            requestId,
          ],
          (err) => (err ? nok(err) : ok())
        )
      );
      console.log(
        `[FETCH-REUSE DEBUG] 7.1. Stored decrypted data and profile_id for request ${requestId}.`
      );

      // 7. Compute local hashes for on-chain verification
      const localHashKtp = ethers.keccak256(
        ethers.toUtf8Bytes(decryptedKtpDataUri)
      );
      const localHashKyc = ethers.keccak256(
        ethers.toUtf8Bytes(decryptedKycDataUri)
      );
      console.log(
        `[FETCH-REUSE DEBUG] 8.1. Local Hashes: KTP=${localHashKtp}, KYC=${localHashKyc}`
      );

      // 8. Compare with on-chain record
      const onChainRecord = await contractWithSigner.getLatestKyc(clientId);
      const match =
        localHashKtp === onChainRecord.hashKtp &&
        localHashKyc === onChainRecord.hashKyc;
      let finalStatusKyc = match ? "verified" : "failed"; // Set to "verified" if matched

      console.log(
        `[FETCH-REUSE DEBUG] 8.2. On-Chain Hashes: KTP=${onChainRecord.hashKtp}, KYC=${onChainRecord.hashKyc}`
      );
      console.log(
        `[FETCH-REUSE DEBUG] 8.3. Hash comparison result: ${
          match ? "MATCH" : "MISMATCH"
        }`
      );

      if (match) {
        console.log(
          `[FETCH-REUSE DEBUG] 8.4. Data integrity confirmed for request ${requestId}.`
        );
      } else {
        console.warn(
          `[FETCH-REUSE DEBUG] 8.4. Data integrity FAILED for request ${requestId}. Setting status to 'failed'.`
        );
      }

      await new Promise((ok, nok) =>
        connection.query(
          `UPDATE user_kyc_request SET status_kyc = ? WHERE request_id = ?`,
          [finalStatusKyc, requestId],
          (err) => (err ? nok(err) : ok())
        )
      );
      console.log(
        `[FETCH-REUSE DEBUG] 9.1. Final status for request ${requestId} set to ${finalStatusKyc}.`
      );

      durationMs = performance.now() - startTime;
      console.log(
        `[PERF] /fetch-and-verify-reuse for request ${requestId} took ${durationMs.toFixed(
          2
        )} ms. Match: ${match}`
      );

      res.json({
        match,
        localHashes: { ktp: localHashKtp, kyc: localHashKyc },
        onChainHashes: {
          ktp: onChainRecord.hashKtp,
          kyc: onChainRecord.hashKyc,
        },
        finalStatusKyc: finalStatusKyc,
        message: match
          ? "KYC data integrity confirmed and verified."
          : "Data integrity check FAILED.",
      });
    } catch (error) {
      console.error(
        `[FETCH-REUSE DEBUG] Outer error for request ${requestId}:`,
        error
      );
      durationMs = performance.now() - startTime;
      console.error(
        `[PERF-ERROR] /fetch-and-verify-reuse for request ${requestId} failed after ${durationMs.toFixed(
          2
        )} ms. Error: ${error.message}`
      );
      res.status(500).json({
        error: "Server error during KYC reuse fetch/verify.",
        detail: error.message,
      });
    }
  }
);

app.put(
  "/clients/:clientId/contact-sharing",
  express.json(),
  async (req, res) => {
    const { clientId } = req.params;
    const { field, value } = req.body; // field: 'customer_email' or 'customer_phone', value: string or null

    if (!["customer_email", "customer_phone"].includes(field)) {
      return res.status(400).json({ error: "Invalid field specified." });
    }

    if (value && typeof value !== "string") {
      return res
        .status(400)
        .json({ error: "Invalid value provided for update." });
    }

    // This SQL query now uses `WHERE client_id = ?` to update ALL records for the user.
    const sql = `UPDATE user_kyc_request SET ${field} = ? WHERE client_id = ?`;

    connection.query(sql, [value, clientId], (err, result) => {
      if (err) {
        console.error(
          `[CONTACT-SHARING] MySQL UPDATE error for client ${clientId}:`,
          err
        );
        return res
          .status(500)
          .json({ error: "Database update failed", detail: err.message });
      }
      console.log(
        `[CONTACT-SHARING] Updated '${field}' for client_id ${clientId}. Affected rows: ${result.affectedRows}`
      );
      res.json({
        message: `Sharing preference for '${field}' was updated for all of the client's records.`,
      });
    });
  }
);

app.use("/profile-ids", profileRoutes);
app.use("/check-blockchain", checkBlockchain); // Corrected typo

const PORT = process.env.PORT || 5000; // For BANK B, should be 5000
app.listen(PORT, () =>
  console.log(`🚀 BANK B backend running on http://localhost:${PORT}`)
);
