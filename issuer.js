const http = require('http');
const readline = require('readline');
const { createEd25519KeyPair, createProof, createVerificationMethodId, crypto } = require('./shared');

const PORT = 3001;
const ISSUER_DID = `did:web:localhost:${PORT}`;

const { publicKey, privateKey } = createEd25519KeyPair();
const verificationMethod = createVerificationMethodId(publicKey, ISSUER_DID);

let credentialTypeFromCLI = "VerifiableCredential";
let credentialSubjectFromCLI = {};

function createSignedVC(subjectId, type, subjectData) {
  console.log(`[Issuer] Creating a VC of type "${type}" for subject ${subjectId}.`);
  const unsignedVC = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", type],
    issuer: ISSUER_DID,
    issuanceDate: new Date().toISOString(),
    credentialSubject: { id: subjectId, ...subjectData }
  };
  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: new Date().toISOString(),
    verificationMethod: verificationMethod,
    proofPurpose: "assertionMethod"
  };
  const dataToSign = { ...unsignedVC, proof };
  const signature = createProof(dataToSign, privateKey);
  return { ...unsignedVC, proof: { ...proof, proofValue: signature } };
}

const server = http.createServer((req, res) => {
  console.log(`\n[Issuer] Request received: ${req.method} ${req.url}`);
  if (req.method === 'POST' && req.url === '/issue') {
    console.log('[Issuer] --> /issue: A Holder is requesting a credential.');
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const { subjectId } = JSON.parse(body);
      const vc = createSignedVC(subjectId, credentialTypeFromCLI, credentialSubjectFromCLI);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(vc, null, 2));
      console.log('[Issuer] --> /issue: Signed VC successfully created and sent to Holder.');
    });
  } else if (req.method === 'GET' && req.url === '/public-key') {
      console.log('[Issuer] --> /public-key: A Verifier is requesting our public key.');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ publicKeyBase64: publicKey }));
  } else {
    res.writeHead(404).end('Not Found');
  }
});

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function askForSubjectData() {
  rl.question('  Enter data KEY (or press ENTER to finish): ', (key) => {
    if (key.trim() === '') {
      startServer();
      return;
    }
    rl.question(`    Enter value for "${key}": `, (value) => {
      credentialSubjectFromCLI[key] = value;
      askForSubjectData();
    });
  });
}

function startServer() {
  rl.close();
  console.log('\n--- Issuer Service Started ---');
  console.log('============================');
  console.log(`Issuer DID: ${ISSUER_DID}`);
  console.log(`Verification Method: ${verificationMethod}`);
  server.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
}

console.log('--- Interactive Issuer Setup ---');
rl.question('Enter the credential type (e.g., "EmployeeID"): ', (type) => {
  credentialTypeFromCLI = type;
  console.log('\nNow, define the credential subject data (key-value pairs).');
  askForSubjectData();
});