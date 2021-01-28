import { Stronghold, Location } from 'tauri-stronghold-api'

const stronghold = new Stronghold('./example.stronghold', 'password')
const vault = stronghold.getVault('exampleVault', [])
const location = Location.generic('vault', 'record')

let response = null
let record

function _updateResponse(returnValue) {
  response = typeof returnValue === 'string' ? returnValue : JSON.stringify(returnValue)
}

_runProcedures().then(() => alert('procedures finished')).catch(e => alert('error running procedures: ' + e))

async function _runProcedures() {
  const seedLocation = Location.generic('vault', 'seed')
  await vault.generateBIP39(seedLocation)
  const privateKeyLocation = Location.generic('vault', 'derived')
  await vault.deriveSLIP10([0, 0, 0], 'Seed', seedLocation, privateKeyLocation)
  const publicKey = await vault.getPublicKey(privateKeyLocation)
  alert('got public key ' + publicKey)
  const message = 'Tauri + Stronghold!'
  const signature = await vault.sign(privateKeyLocation, message)
  alert(`Signed "${message}" and got sig "${signature}"`)
}

function save() {
  vault.insert(location, record)
}

function read() {
  vault.get(location)
    .then(_updateResponse)
    .catch(_updateResponse)
}

export default async (/* { app, router, Vue ... } */) => {
    Vue.$prototype(stronghold) = st
}

