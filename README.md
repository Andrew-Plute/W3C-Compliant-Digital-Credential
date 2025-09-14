The goal of this project was to create a W3C Compliant digital credential infrastructure. This contains an issuer, holder, and verifier.
There will be an issuer that creates a credential, a holder than stores the credential, and a verifier to verify data about the holder.
But wait, there's a cat around. When creating a credential, that credential will be duplicated with the subject data changed to "meow".

To run the code, create 3 seperate terminals with access to node.js (the node command). The code should be run in this exact order or else there will be problems...

Step 1: Start Issuer Server (node issuer.js)
  Input credential type (e.g., "License") and subject data (e.g., name: "Andrew")
  Server runs on http://localhost:3001
  
Step 2: Start Holder Server (node holder.js)
  Automatically requests a VC from the Issuer
  Stores the original VC and creates a tampered version (changes subject data to "meow")
  Server runs on http://localhost:3002
  
Step 3: Start Verifier Server (node verifier.js)
  Server runs on http://localhost:3003
  
Step 4: Trigger Verification
  Run curl http://localhost:3003/verify or open address in browser
  Verifier requests VP from Holder and verifies signatures
  Expected Output:
    Presentation signature: Valid (confirms Holder’s identity)
    Credential 1: Valid (original VC from Issuer)
    Credential 2: Invalid (tampered VC detected)
    Overall result: Contains invalid credentials
