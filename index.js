const {
  Ed25519VerificationKey2018,
} = require("@digitalbazaar/ed25519-verification-key-2018");
const {
  Ed25519Signature2018,
} = require("@digitalbazaar/ed25519-signature-2018");
const fs = require("fs");
const path = require("path");
const rawKeyJson = require("./__fixtures__/key.json");
const documentLoader = require("./documentLoader");
const credential = require("./__fixtures__/credentials/credential-0.json");
const credential1 = require("./__fixtures__/credentials/credential-1.json");

let keyPair;
let suite;
let proof;

(async () => {
  keyPair = await Ed25519VerificationKey2018.from(rawKeyJson);
  suite = new Ed25519Signature2018({
    key: keyPair,
    date: credential.issuanceDate,
  });
  proof = await suite.createProof({
    document: credential,
    purpose: {
      validate: () => {
        return { valid: true };
      },
      update: (proof) => {
        proof.proofPurpose = "assertionMethod";
        return proof;
      },
    },
    documentLoader,
    compactProof: false,
  });
  const suite2 = new Ed25519Signature2018();
  const result = await suite2.verifyProof({
    proof,
    document: credential1,
    purpose: {
      validate: () => {
        return { valid: true };
      },
      update: (proof) => {
        proof.proofPurpose = "assertionMethod";
        return proof;
      },
    },
    documentLoader,
    compactProof: false,
  });

  if (result.verified) {
    // This should not happen since, credential1 has an empty credential subject and removed other root property like related link.
    // but it verifies the same.
    console.log('Successfully verified');
    fs.writeFileSync(
      path.resolve(__dirname, "./__fixtures__/output/digitalbazaar-credential0-proof.json"),
      JSON.stringify(proof, null, 2)
    );
    fs.writeFileSync(
      path.resolve(__dirname, "./__fixtures__/output/digitalbazaar-credential0.json"),
      JSON.stringify(credential, null, 2)
    );
  } else {
    console.warn('Failed to verify!');
  }
})();
