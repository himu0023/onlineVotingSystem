// This is only educationla implementation 
// Real system use WebCrypto or WASM crypto libs.

const P = BigInt("208351617316091241234326746312124448251235562226470491514186331217050270460481");
const G = 2n;

// Public key must match server election key 
// In production this is fetched from election config

const PUBLIC_KEY ={
    h: null
};

// Simple modular exponentiation 
function modExp(base, exp, mod){
    let result = 1n; 
    base = base % mod; 

    while (exp > 0){
        if (exp%2n == 1n){
            result = (result*base)%mod;
        }
        exp = exp /2n;
        base = (base * base)%mod;
    }
    return result;
}


// Random bigint
function randBigInt(){
    return BigInt(Math.floor(Math.random()*1e9))+1n;
}

// Encrypt vote 
function encryptVote(vote){
    const r = randBigInt();

    const c1 = modExp(G,r,P);
    const c2 = (modExp(PUBLIC_KEY.h,r,,P)* modExp(G, BigInt(vote),P))%P;

    return {
        c1: c1.toString(), 
        c2: c2.toString(), 
        r:r // only for ZK proof generation
    };
}

// Main voting action 
async function castVote(){


    if (!voterToken){
        alert("Get token first!");
        return;
    }

    const choice = document.querySelector('input[name="vote"]:checked');

    if (!choice){
        alert("Select a vote");
        return;
    }

    const voteValue = parseInt(choice.value);

    // Encrypt 
    const encrypted = encryptVote(voteValue);

    // ZK proof generation should happen here 
    // For broweser demo: placeholder proof 
    const proof = {
        placeholder = true
    };

    const payload = {
        ballot: {
            ciphertext: {
                c1: encrypted.c1,
                c2: encrypted.c2
            },
            proof: proof
        },
        token: voterToken,
        signature: tokenSignature
    };

    const result = await submitBallot(payload);

    document.getElementById("status").innerText = JSON.stringify(result, null, 2);
}