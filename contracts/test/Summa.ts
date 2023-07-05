import { expect } from "chai";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { MockERC20, Summa } from "../typechain-types";
import { defaultAbiCoder, solidityKeccak256 } from "ethers/lib/utils";
import { BigNumber } from "ethers";

describe("Summa Contract", () => {
  async function deploySummaFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3] = await ethers.getSigners();

    const mockERC20 = await ethers.deployContract("MockERC20");
    await mockERC20.deployed();

    const verifier = await ethers.deployContract(
      "src/SolvencyVerifier.sol:Verifier"
    );
    await verifier.deployed();

    const summa = await ethers.deployContract("Summa", [verifier.address]);
    await summa.deployed();

    return {
      summa: summa as Summa,
      mockERC20,
      owner,
      addr1,
      addr2,
      addr3,
    };
  }

  describe("verifyProofOfSolvency", () => {
    let exchangeId: string;
    let cexAddresses: string[];
    let balancesToProve: BigNumber[];
    let cexSignatures: string[];
    let erc20ContractAddresses: string[];
    let mstRoot: BigNumber;
    let summa: Summa;
    let mockERC20: MockERC20;
    let address1: string;
    let address2: string;
    let proof: string;
    //let ethAccount3;

    beforeEach(async () => {
      const deployemtnInfo = await loadFixture(deploySummaFixture);
      summa = deployemtnInfo.summa as Summa;
      mockERC20 = deployemtnInfo.mockERC20 as MockERC20;
      address1 = deployemtnInfo.addr1.address;
      address2 = deployemtnInfo.addr2.address;
      //ethAccount3 = deployemtnInfo.addr3;

      await mockERC20.mint(address2, 556863);

      //Reference signing procedure:
      // const message = ethers.utils.defaultAbiCoder.encode(
      //   ["string", "string"],
      //   ["Summa proof of solvency for ", "CryptoExchange"]
      // );
      // const hashedMessage = ethers.utils.solidityKeccak256(
      //   ["bytes"],
      //   [message]
      // );
      // const signature = await ethAccount2.signMessage(
      //   ethers.utils.arrayify(hashedMessage)
      // );
      // console.log("signature", signature);

      exchangeId = "CryptoExchange";
      cexAddresses = [address1, address2];
      cexSignatures = [
        "0xea576c302228671c074bdf26fbd757d9c64016aa9974eaeb911274d1458a49f05aa5d4b9df5c0a4a68d2256bea8a6c762130e538b41f47fd54b2cbbdccd6a9de1c",
        "0x5dc26d1b8cf94a11897872bbba7301fcf9e16a9767b4170b978586659b9ec52842621d323f42bf398ae23970fa21194ba8319faea4b2fd85e133a112702e21ab1b",
      ];
      erc20ContractAddresses = [mockERC20.address];
      balancesToProve = [BigNumber.from(556863), BigNumber.from(556863)];
      mstRoot =
        BigNumber.from(
          1300633067792667740851197998552728163078912135282962223512949070409098715333n
        );
      proof =
        "0x1b531702eb8124c58c0691d2b5293d41d6f86eda516a14629af3304a69dee6121f41a2f37101cc5c7141cb4d5111aeebb7482efc7dc0d9c2930ad4849ed3012528594c3ac2e2852d9fcae5c092d9747875e7587f5875184b263a158d9b93d3da21f854d412bef9ff730c023e33e73c96149b2cbcd6a64b94719bb7778ab91a4126eb960525dd35e31c736de87cc993458883224801ec059db2a1866b17208f822328136b19d4231f4f4ef53eaf4b55f4438da656c48a5a998821217b7329074a16e2089f730191067b45f23fa546aa2b9170675a72ca91a52443978dee507b20150b7153f947eaf9945d31c112a9d33c15c0299904f36a8f6f30d61ece884615114fb5df0268a0555777ec236c1b447009fc21c9e4f46bb40bd4386066f9a86c2f5df3f2ad11dd2756c25af2b80b811c9a39ebe822173ed0ef6574f966bcccc514b98dd8da5672337f345297f1b09275f0b367b59bb8797134593a90eb3e939820ca20fa72be051f47e8033d0e3477efe4de3574046cadc3ae24012ce1874648193adfd7da3e5fdd62d8d923be6dd3076663d6cf96ebc4dcf47d60cba70492ef1654326fe57ff5c91cc697738b8b9ab3a316659f9c5561c968f28951670fc8d31151888eef09ce7feed2b7af2bba339aa76bca36a6e32d646415e448ab55dd4513d8c3c78f53dae778f3e7234bc3add935fe020397f0a9249514a1b1060702040e102d8683c4801c0538dcdd28d6eb8567366f012e6402d87fae1beea0250e33093362899af4f360289dab8e6f04a4a5d320546816b62a0225b0464e2e49e5391b3f67bf1be5fb777b336db9f999a1ff1d1e2023672a1f28ceff27db8d115cf71de31ace31db47d66a529de90ca2e17fd66e6d048c30fb814224e61a7dec343419871d070ed9d4fe8de05cd61fcd43e0bde9924848c1d38296f3a0e528c7e6f81e203b1f2f5e6c4b82530b8e302521e07dcbcf4a252eb97d94bf80c9c234f24505fcafe98e4021728af2480144b949243af46bd62c3078d4c6b0d712eb25edd70c39152a80e14a127a14854426516921c80801eb3d2bf504ced8034bcf095eb212a92e7912df88780612d63f5f37a80451dcdbde819d95f7481e8b56af7d1ce9217e4d7e9a362b22379401e71e25495240cee82f89fd3f29157740ee23b93f9f2f0fc12038e98bf463fc85d509704ea0fe333e54bc3a0fac16962ffafea8b2a10ae961cf12537f2edfea731c92041f999096c05a66bb6ad75df7db4ab524d0730f0592d7a2fbb3b0044918fa00ea9d9e6ba2a5248588103e4dec74e80cff3a42050b2186b4817723c298138c2503b8a39ddb32a14587229cf94933e3fd1c4c3a0d8793ab7c354709c4a33c3e948dd6c5827be7b282a8a2f555c5492e635548271b7fc962c849d1d053964d205e6288d188fe119107b2878ffe182e0396c8f8872bb1f0db65c5e9ea6ef527313599b29c7e820532ed50a356af3246536c0a8f071c20d48876a3e2b5782e8055d4bfea7caa31f2c3a9816071b70b3b2499c3f37c1fab4a5a07462d8f3219d457b5eb7c36c6bd9105b259bf8627e18e3af4650dfc0ba3306f9cccd0f8b31f5bb6ec8de445915a183a1f5f773d0625f30945aba4f50a3d94b5569d3f053ebd08ef2e8aac477f533fe102c9f0b9804c8933cb95f33328d5cb6e986e3a5d7872b79398ee57fa83dbaf2294a57bce122167126c9b63721464c8eab88e60ef3e448b49edadc7d5e31763d83121af77b9bc1b521f5d6a0a2abb4314cf8fa737c1daf925bfae2459b47d5c43f9a9e3148f19df647a15798c134e9225d8ccbefbd90094962347f758241da5cffa1e406e2ffab12aff2da9bc2e85492a255b44e5ff7d09dc16f8d8aee36d2bba3d9b0a5d6b794a5478771bb70446cd5bcd0fc45e7e9d6587b220972fbbb757359a98df9b731ddf7d36acfc0009e77671648d7e09c987fe7778a1c57d7b3b52e3410664bb9aecec35ccb39fe81ba42d1b28bb951c44a1a87da187a23df55d5086fcde81de5303810b4308c04802e08559a52421fae1680c3705a8db0b213c3306f45cd3f7bff37b3c7387188713723713e7b95dd8b4f21fe8923a855047b5fe6f30613d005ecb152cc5cac09d18ef2c575c23f3ac10f1c3507fe2f4eff9b53c29a98e24386032eb5c62f66bc920e55d5be8625b8aafdbb6374a85d22d61d3d0359efd88cd729cfff0809bc39f155a7c9f755669785a1a9da8e4a51322b62387a8bde98ee4612f9da3957dea7827bd9646cd86947dcd0cb6dfb4afd89ce6d1a9b9d6c547bf4d45be9f07a7a01823bbe6bbff643d8b0b50b3f79ba354671ed8f342b6d8b612c5de1438d7a3f615";
    });

    it("should verify the proof of solvency for the given public input", async () => {
      const exchangeIdHash = ethers.utils.keccak256(
        defaultAbiCoder.encode(["string"], ["CryptoExchange"])
      );
      //calldata: (
      //Bytes(0x1b531702eb8124c58c0691d2b5293d41d6f86eda516a14629af3304a69dee6121f41a2f37101cc5c7141cb4d5111aeebb7482efc7dc0d9c2930ad4849ed3012528594c3ac2e2852d9fcae5c092d9747875e7587f5875184b263a158d9b93d3da21f854d412bef9ff730c023e33e73c96149b2cbcd6a64b94719bb7778ab91a4126eb960525dd35e31c736de87cc993458883224801ec059db2a1866b17208f822328136b19d4231f4f4ef53eaf4b55f4438da656c48a5a998821217b7329074a16e2089f730191067b45f23fa546aa2b9170675a72ca91a52443978dee507b20150b7153f947eaf9945d31c112a9d33c15c0299904f36a8f6f30d61ece884615114fb5df0268a0555777ec236c1b447009fc21c9e4f46bb40bd4386066f9a86c2f5df3f2ad11dd2756c25af2b80b811c9a39ebe822173ed0ef6574f966bcccc514b98dd8da5672337f345297f1b09275f0b367b59bb8797134593a90eb3e939820ca20fa72be051f47e8033d0e3477efe4de3574046cadc3ae24012ce1874648193adfd7da3e5fdd62d8d923be6dd3076663d6cf96ebc4dcf47d60cba70492ef1654326fe57ff5c91cc697738b8b9ab3a316659f9c5561c968f28951670fc8d31151888eef09ce7feed2b7af2bba339aa76bca36a6e32d646415e448ab55dd4513d8c3c78f53dae778f3e7234bc3add935fe020397f0a9249514a1b1060702040e102d8683c4801c0538dcdd28d6eb8567366f012e6402d87fae1beea0250e33093362899af4f360289dab8e6f04a4a5d320546816b62a0225b0464e2e49e5391b3f67bf1be5fb777b336db9f999a1ff1d1e2023672a1f28ceff27db8d115cf71de31ace31db47d66a529de90ca2e17fd66e6d048c30fb814224e61a7dec343419871d070ed9d4fe8de05cd61fcd43e0bde9924848c1d38296f3a0e528c7e6f81e203b1f2f5e6c4b82530b8e302521e07dcbcf4a252eb97d94bf80c9c234f24505fcafe98e4021728af2480144b949243af46bd62c3078d4c6b0d712eb25edd70c39152a80e14a127a14854426516921c80801eb3d2bf504ced8034bcf095eb212a92e7912df88780612d63f5f37a80451dcdbde819d95f7481e8b56af7d1ce9217e4d7e9a362b22379401e71e25495240cee82f89fd3f29157740ee23b93f9f2f0fc12038e98bf463fc85d509704ea0fe333e54bc3a0fac16962ffafea8b2a10ae961cf12537f2edfea731c92041f999096c05a66bb6ad75df7db4ab524d0730f0592d7a2fbb3b0044918fa00ea9d9e6ba2a5248588103e4dec74e80cff3a42050b2186b4817723c298138c2503b8a39ddb32a14587229cf94933e3fd1c4c3a0d8793ab7c354709c4a33c3e948dd6c5827be7b282a8a2f555c5492e635548271b7fc962c849d1d053964d205e6288d188fe119107b2878ffe182e0396c8f8872bb1f0db65c5e9ea6ef527313599b29c7e820532ed50a356af3246536c0a8f071c20d48876a3e2b5782e8055d4bfea7caa31f2c3a9816071b70b3b2499c3f37c1fab4a5a07462d8f3219d457b5eb7c36c6bd9105b259bf8627e18e3af4650dfc0ba3306f9cccd0f8b31f5bb6ec8de445915a183a1f5f773d0625f30945aba4f50a3d94b5569d3f053ebd08ef2e8aac477f533fe102c9f0b9804c8933cb95f33328d5cb6e986e3a5d7872b79398ee57fa83dbaf2294a57bce122167126c9b63721464c8eab88e60ef3e448b49edadc7d5e31763d83121af77b9bc1b521f5d6a0a2abb4314cf8fa737c1daf925bfae2459b47d5c43f9a9e3148f19df647a15798c134e9225d8ccbefbd90094962347f758241da5cffa1e406e2ffab12aff2da9bc2e85492a255b44e5ff7d09dc16f8d8aee36d2bba3d9b0a5d6b794a5478771bb70446cd5bcd0fc45e7e9d6587b220972fbbb757359a98df9b731ddf7d36acfc0009e77671648d7e09c987fe7778a1c57d7b3b52e3410664bb9aecec35ccb39fe81ba42d1b28bb951c44a1a87da187a23df55d5086fcde81de5303810b4308c04802e08559a52421fae1680c3705a8db0b213c3306f45cd3f7bff37b3c7387188713723713e7b95dd8b4f21fe8923a855047b5fe6f30613d005ecb152cc5cac09d18ef2c575c23f3ac10f1c3507fe2f4eff9b53c29a98e24386032eb5c62f66bc920e55d5be8625b8aafdbb6374a85d22d61d3d0359efd88cd729cfff0809bc39f155a7c9f755669785a1a9da8e4a51322b62387a8bde98ee4612f9da3957dea7827bd9646cd86947dcd0cb6dfb4afd89ce6d1a9b9d6c547bf4d45be9f07a7a01823bbe6bbff643d8b0b50b3f79ba354671ed8f342b6d8b612c5de1438d7a3f615),
      //[1300633067792667740851197998552728163078912135282962223512949070409098715333, 556863, 556863]
      //)

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      )
        .to.emit(summa, "ProofOfSolvencySubmitted")
        .withArgs(exchangeIdHash, mstRoot);
    });

    it("should revert if a signature is invalid", async () => {
      //Invalid signature
      cexSignatures[0] =
        "0x9a9f2dd5ad8242b8feb5ad19e6f5cc87693bc2335ed849c8f9fa908e49c047d0250d001da1d1a83fed254171f1c686e83482b9b927702768efdaafac7375eac91d";

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("ECDSA: invalid signature");
    });

    it("should revert if the signer is invalid", async () => {
      //Invalid signer (account #3)
      cexSignatures[0] =
        "0x2cb485683668d6a9e68b27763fb40bffe6953c7ba81490f28d1b39584778568d481bca493437d9c0f2c3f0ccd989cdde746eef49faa3d6b5a4f924107684383b1b";

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("Invalid signer for ETH address");
    });

    it("should revert if not all signatures are provided", async () => {
      cexSignatures.pop();

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("CEX addresses and signatures count mismatch");
    });

    it("should revert if actual ETH balance is less than the proven balance", async () => {
      balancesToProve[0] = (await ethers.provider.getBalance(address1))
        .add(await ethers.provider.getBalance(address2))
        .add(BigNumber.from(1000));

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith(
        "Actual ETH balance is less than the proven balance"
      );
    });

    it("should revert if actual ERC20 balance is less than the proven balance", async () => {
      balancesToProve[1] = BigNumber.from(556864);

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith(
        "Actual ERC20 balance is less than the proven balance"
      );
    });

    it("should revert if not all ERC20 token addresses are provided", async () => {
      erc20ContractAddresses = [];

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("ERC20 addresses and balances count mismatch");
    });

    it("should revert with invalid MST root", async () => {
      mstRoot = BigNumber.from(0);
      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("Invalid zk proof");
    });

    it("should revert with invalid proof", async () => {
      proof = "0x000000";
      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWithoutReason();
    });
  });
});
