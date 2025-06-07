// bank-b/backend/routes/checkBlockchain.js
const express = require("express");
const { ethers } = require("ethers");
const connection = require("../dbConnection");
require("dotenv").config();

const artifact = require(__dirname + "/../abi/KycRegistryV3.json");
const PROVIDER = new ethers.JsonRpcProvider(process.env.RPC_URL);
const CONTRACT = new ethers.Contract(
  process.env.KYC_REGISTRY_ADDRESS,
  artifact.abi,
  PROVIDER
);

const router = express.Router();

/**
 * POST /check-blockchain
 * body: {
 *   profile_id: string,
 *   customer_ktp: dataURI,
 *   customer_kyc: dataURI
 * }
 */
router.post("/", express.json(), async (req, res) => {
  const { profile_id, customer_ktp, customer_kyc } = req.body;
  if (!profile_id || !customer_ktp || !customer_kyc) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // 1) find clientId from user_profile_id
  const [[row]] = await new Promise((ok, nok) =>
    connection.query(
      "SELECT client_id FROM user_profile_id WHERE profile_id = ?",
      [profile_id],
      (e, rows) => (e ? nok(e) : ok([rows]))
    )
  );
  if (!row) return res.status(404).json({ error: "Unknown profile_id" });
  const clientId = row.client_id;

  // 2) fetch on-chain hashes
  let onChain;
  try {
    onChain = await CONTRACT.getLatestKyc(clientId);
  } catch (e) {
    return res
      .status(500)
      .json({ error: "Chain lookup failed", detail: e.message });
  }

  // 3) compute local hashes (must match addKycVersion)
  const localHashKtp = ethers.keccak256(ethers.toUtf8Bytes(customer_ktp));
  const localHashKyc = ethers.keccak256(ethers.toUtf8Bytes(customer_kyc));

  // 4) comparison
  const match =
    localHashKtp === onChain.hashKtp && localHashKyc === onChain.hashKyc;

  // 5) if match, ensure our user_profile_id row exists (upsert)
  if (match) {
    await new Promise((ok, nok) =>
      connection.query(
        `INSERT INTO user_profile_id
             (client_id, request_id, profile_id)
         VALUES
             (?, NULL, ?)
         ON DUPLICATE KEY UPDATE client_id = VALUES(client_id)`,
        [clientId, profile_id],
        (e) => (e ? nok(e) : ok())
      )
    );
  }

  return res.json({
    match,
    local: { hashKtp: localHashKtp, hashKyc: localHashKyc },
    onChain: { hashKtp: onChain.hashKtp, hashKyc: onChain.hashKyc },
  });
});

module.exports = router;
