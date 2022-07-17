import { test } from 'tape'
import * as ethers from 'ethers'
import ganache from 'ganache'
import { readFileSync } from 'fs'
import path from 'path'

const U256_MAX = 2n ** 256n - 1n

const eoa = new ethers.utils.SigningKey(ethers.utils.randomBytes(32))
const provider = ganache.provider({
  wallet: {
    accounts: [
      { secretKey: eoa.privateKey.toString('hex'), balance: (2n ** 128n) }
    ]
  },
  logging: {
    quiet: true
  }
})

const web3 = new ethers.providers.Web3Provider(provider)
const signer = new ethers.Wallet(eoa.privateKey, web3)

const abi = JSON.parse(readFileSync(new URL('../build/Test.abi', import.meta.url), 'utf-8'))
const bytecode = readFileSync(new URL('../build/Test.bin', import.meta.url), 'utf8')
const TestContractFactory = new ethers.ContractFactory(abi, bytecode, signer)

test('', async (assert) => {
  const contract = await TestContractFactory.deploy()
  await contract.deployTransaction.wait()

  const { hash, validators, signatures } = generateKeys(10)

  {
    const tx = await contract.callStatic.verify2(U256_MAX, hash, ethers.utils.hexConcat(validators), ethers.utils.hexConcat(signatures))
    assert.equal(0n, BigInt(tx.pre, '16'))
    assert.equal(0n, BigInt(tx.post, '16'))
    assert.ok(tx.validSignatures.eq(10))
  }

  {
    const tx = await contract.callStatic.verify2(5, hash, ethers.utils.hexConcat(validators), ethers.utils.hexConcat(signatures))
    assert.equal(0n, BigInt(tx.pre, '16'))
    assert.equal(0n, BigInt(tx.post, '16'))
    assert.ok(tx.validSignatures.eq(5))
  }

  {
    const tx = await contract.callStatic.verify2(U256_MAX, hash, ethers.utils.hexConcat(validators), ethers.utils.hexConcat(signatures.reverse()))
    assert.equal(0n, BigInt(tx.pre, '16'))
    assert.equal(0n, BigInt(tx.post, '16'))
    assert.ok(tx.validSignatures.eq(1))
  }

  {
    const tx = await contract.callStatic.verify2(U256_MAX, hash, ethers.utils.hexConcat(validators.reverse()), ethers.utils.hexConcat(signatures))
    assert.equal(0n, BigInt(tx.pre, '16'))
    assert.equal(0n, BigInt(tx.post, '16'))
    assert.ok(tx.validSignatures.eq(1))
    console.log(tx.validSignatures.toString())
  }

  {
    const tx = await contract.callStatic.verify2(U256_MAX, hash, ethers.utils.hexConcat(validators), ethers.utils.hexConcat(signatures.concat(signatures)))
    assert.equal(0n, BigInt(tx.pre, '16'))
    assert.equal(0n, BigInt(tx.post, '16'))
    assert.ok(tx.validSignatures.eq(10))
  }

  // const res = await tx.wait()

  // console.dir(await web3.send('debug_traceTransaction', [tx.hash]), { depth: null })

  // verify(U256_MAX, new Uint8Array(32), new Uint8Array(0), new Uint8Array(0))

  // for (let threshold = 0; threshold < validators.length; threshold++) {
  //   verify(threshold, hash, validators, signatures) === threshold
  // }

  // unique signers, multiple signatures
  // multiple signers, multiple signatures
  // shuffle

  // signature with no match
  // signature matching last validator
  // signature matching every 2nd validator
  // reverse signatures list (should match very last validator)
})

test('', async () => {})

function generateKeys(n) {
  const hash = ethers.utils.randomBytes(32)
  const validators = []
  const signatures = []

  for (let i = 0; i < n; i++) {
    const keys = new ethers.utils.SigningKey(ethers.utils.randomBytes(32))
    const address = ethers.utils.computeAddress(keys.publicKey)

    validators.push(address)
    const sig = keys.signDigest(hash)
    signatures.push(ethers.utils.hexConcat([sig.v, sig.r, sig.s]))
  }

  return { hash, validators, signatures }
}
