import { logs, contract, reset, stateCache } from "./mocks";
import { firstTenBTCBlocks } from "./firstTenBTCBlocks"

// import { beforeEach, describe, it } from "mocha";
import { expect } from "chai";

beforeEach(reset);

xdescribe("parseHex", () => {
  it("should convert hex into a byte array", () => {
    const expected = new Uint8Array([0, 0, 0, 32, 135, 183, 196, 61, 230, 155, 214, 166, 52, 122, 176, 137, 172, 30, 216, 142, 66, 194, 182, 15, 48, 44, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 159, 94, 82, 192, 130, 171, 47, 178, 247, 162, 118, 75, 240, 188, 85, 67, 67, 212, 235, 17, 28, 234, 234, 238, 83, 28, 177, 92, 52, 244, 60, 181, 38, 50, 250, 101, 89, 90, 3, 23, 157, 208, 77, 51])

    const result = contract.parseHex(
      "0000002087b7c43de69bd6a6347ab089ac1ed88e42c2b60f302c010000000000000000009f5e52c082ab2fb2f7a2764bf0bc554343d4eb111ceaeaee531cb15c34f43cb52632fa65595a03179dd04d33",
    )

    expect(result).to.deep.equal(expected);
  });
});

xdescribe("getPreheaders", () => {
  it("should get BTC headers from storage", () => {
    stateCache.set("pre-headers/main", JSON.stringify(firstTenBTCBlocks));

    contract.getPreheaders()

    expect(true).to.equal(true);
  });
});


describe("processHeaders", () => {
  it("should process and verify BTC headers", () => {
    // stateCache.set("pre-headers/main", JSON.stringify(firstTenBTCBlocks));
    const testHeaders = [
      "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
      "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
      "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
      "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
      "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
      "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
      "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
      "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
      "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
      "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
      "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
    ]

    const result = contract.processHeaders(testHeaders)

    expect(true).to.equal(true);
  });
});



































// describe("processHeaders", () => {
//   it("should process and verify BTC headers", () => {
//     const expected = new Uint8Array([0,0,0,32,135,183,196,61,230,155,214,166,52,122,176,137,172,30,216,142,66,194,182,15,48,44,1,0,0,0,0,0,0,0,0,0,159,94,82,192,130,171,47,178,247,162,118,75,240,188,85,67,67,212,235,17,28,234,234,238,83,28,177,92,52,244,60,181,38,50,250,101,89,90,3,23,157,208,77,51])

//     const testHeaders = [
//       "0000002087b7c43de69bd6a6347ab089ac1ed88e42c2b60f302c010000000000000000009f5e52c082ab2fb2f7a2764bf0bc554343d4eb111ceaeaee531cb15c34f43cb52632fa65595a03179dd04d33",
//       "0400003800590c6c42facbe232d39ab813687f02532a71c7682f010000000000000000001441df4357842a8d3a7189418a9b2ca737ed561385c991dc46bc4779f11013f6a63bfa65595a031729b4811d",
//       "00004525943da8726819bb3e288d17249e4c09199023685bec3502000000000000000000950d46da0e472b256c68f4430c5a881d25bba39a2fdcc25043d1cb777d7b394db6c7fb65595a031725b9f519",
//       "00400f20156ffed839ed161ffad0fa6756105fcdffbbaded4519020000000000000000000a92a2e06a3630fc38247050e536367baf87ad5a03b046c6664b6b1bb57566cdb829fc65595a03174a51b537",
//       "0000ea264c2fcb1c2dcd236b0bc255e11b535e27414d9132022f0200000000000000000012088d67f9e05d32d9f744b09194f846d84e002e81c6443aa002e6952d25a17e772efc65595a0317c201c97d",
//       "00005627b54ac6b61da348948d05c103aedcb2cafabc69409403010000000000000000000cddf0e741e65853b395e647546ce96fb625161e15b4d335051df0e3104ed39e6030fc65595a03176f9acb15",
//       "0080cc25f0e1c763d03827fe33ffdd4c589a59008c9bb07edf2f0000000000000000000011e51f61c2b2290d1a59d3b51a5eb9f9bd476643301a6181d79af4a339c7bdb33032fc65595a0317a6decef6",
//       "00a05425af1c80120145942f4029eb464df20d07b46492bff30600000000000000000000b7528e43d6b5c72fcf4b758b5e7bad9c54ff0d83b74151b546320f5a3b1bf1310c33fc65595a03175e96872f",
//       "0020a7262e03b55e383fe2ef4444138d6420412082ea815b3ead000000000000000000008c584d93feff8e51b023d0cd5291b5eb4189bdb157c0cf165aa8a91adc139ba10d35fc65595a0317945050cc",
//       "00006020eb9c2b6e17e8e0bd9e10daefc19238f9ed3d67abe0e401000000000000000000e62095e72b3a4787b40b7727d4d28582f3c5516c434eef908add1609953e8f2e9136fc65595a0317683ad3b4",
//       "000060207b70a8d81fa2ed3eaa9e302c10abd87da0a34f55853a03000000000000000000876d0eaa056eca47285e2e8bebdf30e4f94c343b6ab848d96492b051d04aee2a643afc65595a03179ac4d903"
//     ]

//     const result = contract.processHeaders(testHeaders)

//     expect(true).to.equal(true);
//   });
// });