const SERVER_URL = "http://localhost:8000";

let voterToken = null; 
let tokenSignature = null; 

// Fetch one time voting token 
async function getToken(){
    const res = await fetch (`${SERVER_URL}/issue-token`);
    const data = await res.json()

    voterToken = data.token;
    tokenSignature = data.signature;

    document.getElementById("tokenStatus").innerText = "Token issued (stored locally).";
}