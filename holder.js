const http = require('http');
const { createEd25519KeyPair, createProof, createVerificationMethodId, crypto } = require('./shared'); 

const PORT = 3002;
const HOLDER_DID = `did:web:localhost:${PORT}`;

const { publicKey, privateKey } = createEd25519KeyPair();
const verificationMethod = createVerificationMethodId(publicKey, HOLDER_DID);

let credentialStore = [];

// Now accepts an array of VCs
function createSignedPresentation(vcs) {
  const unsignedVP = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"],
    holder: HOLDER_DID,
    verifiableCredential: vcs
  };
  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: new Date().toISOString(),
    verificationMethod: verificationMethod, 
    proofPurpose: "authentication"
  };
  const dataToSign = { ...unsignedVP, proof };
  const signature = createProof(dataToSign, privateKey);
  return { ...unsignedVP, proof: { ...proof, proofValue: signature } };
}

const server = http.createServer(async (req, res) => {
  console.log(`\n[Holder] Request received: ${req.method} ${req.url}`);
  if (req.method === 'POST' && req.url === '/store') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      // --- THIS IS THE MAJOR CHANGE ---
      const originalVC = JSON.parse(body);
      console.log('[Holder] --> /store: Received a credential for internal storage in my wallet.');
      console.log('[Holder] --> /store: Storing ORIGINAL credential. Subject details:');
      console.log(JSON.stringify(originalVC.credentialSubject, null, 2));

      // 1. Duplicate the credential
      const catifiedVC = JSON.parse(JSON.stringify(originalVC));
      
      // 2. Give it a new unique ID
      catifiedVC.id = `urn:uuid:${crypto.randomUUID()}`;

      // 3. "Catify" the contents (tamper with it)
      console.log('[Holder] --> /store: Duplicating and "catifying" the credential...');
      for (const key in catifiedVC.credentialSubject) {
        // Keep the holder's ID, but change everything else to "meow"
        if (key !== 'id') {
          catifiedVC.credentialSubject[key] = 'meow';
        }
      }
      // CRITICAL: We do NOT re-sign it. Its proof is now invalid for its content.
      
      console.log('[Holder] --> /store: Storing TAMPERED "catified" credential. Subject details:');
      console.log(JSON.stringify(catifiedVC.credentialSubject, null, 2));

      // 4. Store both in the wallet
      credentialStore = [originalVC, catifiedVC];

      res.writeHead(200).end('Credentials stored');
    });
  } else if (req.method === 'GET' && req.url === '/present') {
    console.log('[Holder] --> /present: A Verifier is asking me to prove something.');
    if (credentialStore.length === 0) {
        console.log('[Holder] --> /present: I have no credentials in my wallet to present.');
        res.writeHead(404).end(JSON.stringify({ error: "No credentials to present."}));
        return;
    }
    console.log('[Holder] --> /present: Accessing my stored credentials to create and sign a presentation...');
    const signedPresentation = createSignedPresentation(credentialStore); // Pass the whole array
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(signedPresentation, null, 2));
    console.log('[Holder] --> /present: Sent the signed presentation (containing BOTH credentials) to the Verifier.');
  } else if (req.method === 'GET' && req.url === '/public-key') {
      console.log('[Holder] --> /public-key: A Verifier is requesting my public key.');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ publicKeyBase64: publicKey }));
  } else {
    res.writeHead(404).end('Not Found');
  }
});

server.listen(PORT, () => {
  console.log('--- Holder Service Started ---');
  console.log(`Holder DID: ${HOLDER_DID}`);
  console.log(`Listening on http://localhost:${PORT}`);
  
  setTimeout(() => {
    console.log('\n-------------------------------------------------------------');
    console.log('[Holder] (Simulation) I need a credential to operate.');
    console.log(`[Holder] (Simulation) Requesting one from the Issuer for my DID: ${HOLDER_DID}`);
    console.log('-------------------------------------------------------------');
    const postData = JSON.stringify({ subjectId: HOLDER_DID });
    const request = http.request({
      hostname: 'localhost', port: 3001, path: '/issue', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, (response) => {
      let data = '';
      response.on('data', (chunk) => data += chunk);
      response.on('end', () => {
        if (response.statusCode === 200) {
          console.log('[Holder] (Simulation) SUCCESS: Received signed credential from the Issuer.');
          console.log('[Holder] (Simulation) Saving it to my secure wallet via my own /store endpoint.');
          const storeRequest = http.request({
            hostname: 'localhost', port: PORT, path: '/store', method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          storeRequest.write(data);
          storeRequest.end();
        } else {
          console.error(`[Holder] (Simulation) ERROR: Issuer responded with status ${response.statusCode}`);
        }
      });
    });
    request.on('error', (e) => console.error(`[Holder] (Simulation) ERROR: Could not connect to issuer: ${e.message}`));
    request.write(postData);
    request.end();
  }, 2000);
});