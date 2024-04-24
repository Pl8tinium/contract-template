// Wip

export function validateTxProof() {
    const {proof} = args

    const bundleHeaders = await state.pull(`headers/${calcKey(proof.confirming_height)}`) || {}

    const header = bundleHeaders[proof.confirming_height]


    const decodeHex = new Uint8Array(Buffer.from(header, 'hex'))
    const prevBlock = Buffer.from(utils.bitcoin.BTCUtils.extractPrevBlockLE(decodeHex)).toString('hex');
    // const timestamp = utils.bitcoin.BTCUtils.extractTimestampLE(decodeHex)
    const merkleRoot = Buffer.from(utils.bitcoin.BTCUtils.extractMerkleRootLE(decodeHex)).toString('hex')
    // console.log(timestamp.toString())
    const headerHash = Buffer.from(utils.bitcoin.BTCUtils.hash256(decodeHex)).toString('hex');

    const confirming_header = {
        raw: header,
        hash: headerHash,
        height: proof.confirming_height,
        prevhash: prevBlock,
        merkle_root: merkleRoot,
    }

    const fullProof = {
        ...proof,
        confirming_header
    }
    let validProof = utils.bitcoin.ValidateSPV.validateProof(utils.bitcoin.ser.deserializeSPVProof(JSON.stringify(fullProof)))

    if(validProof) {
        await state.update(`txs/${proof.tx_id}`, proof)
    }

    // just return if valid or not, DONT UPDATE STATE, PUT TO SDK AFTERWARDS WHEN IT WORKS
}