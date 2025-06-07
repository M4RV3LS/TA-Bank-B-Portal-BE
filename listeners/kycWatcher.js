// bank-portal/bank-b/backend/listeners/kycWatcher.js
const { ethers } = require("ethers");
const connection = require("../dbConnection");
const fs = require("fs");
require("dotenv").config();

const artifact = require("../abi/KycRegistryV3.json");

const contractAddress = process.env.KYC_REGISTRY_ADDRESS;
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);

const contract = new ethers.Contract(contractAddress, artifact.abi, provider);

// Watch ProofNotarized → sync encrypted bundle
contract.on("ProofNotarized", async (clientId, newHash, costSlice) => {
  console.log(`🔔 Notarized for client ${clientId}, newHash=${newHash}`);
  // 1) Update local hash cache table
  await new Promise((ok, nok) =>
    connection.query(
      `UPDATE user_hash_cache
         SET latest_hash = ?
       WHERE client_id = ?`,
      [newHash, clientId],
      (e) => (e ? nok(e) : ok())
    )
  );

  // 2) Fetch encrypted bundle from home bank
  const homeBankUrl = process.env.HOME_BANK_GATEWAY + `/kyc-files/${clientId}`;
  // kycWatcher.js
  const token = process.env.HOME_BANK_GATEWAY_TOKEN;

  const resp = await fetch(homeBankUrl, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) {
    return console.error("Failed to fetch bundle:", resp.statusText);
  }
  const buffer = await resp.arrayBuffer();

  // 3) Store it in your local user_profiles
  await new Promise((ok, nok) =>
    connection.query(
      `UPDATE user_profiles SET encrypted_bundle = ? WHERE client_id = ?`,
      [Buffer.from(buffer), clientId],
      (e) => (e ? nok(e) : ok())
    )
  );

  console.log("✅ Local bundle updated for client", clientId);
});

// Kick it off
console.log("👉 KYC watcher started, listening for ProofNotarized...");
