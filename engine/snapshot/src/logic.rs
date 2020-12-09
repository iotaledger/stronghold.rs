// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{rename, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crypto::ciphers::chacha::xchacha20poly1305;

/// PARTI in binary
const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

/// version 1.0 in binary
const VERSION: [u8; 2] = [0x1, 0x0];

const KEY_SIZE: usize = 32;
pub type Key = [u8; KEY_SIZE];

/// encrypt and write a serialized snapshot
pub fn write<O: Write>(input: &[u8], out: &mut O, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    out.write_all(&MAGIC)?;
    out.write_all(&VERSION)?;

    let mut nonce = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
    crypto::rand::fill(&mut nonce)?;
    out.write_all(&nonce)?;

    let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];
    let mut ct = vec![0; input.len()];
    xchacha20poly1305::encrypt(&mut ct, &mut tag, input, key, &nonce, associated_data)?;

    out.write_all(&tag)?;
    out.write_all(&ct)?;

    Ok(())
}

/// decrypt a snapshot and return its serialized bytes
pub fn read<I: Read>(input: &mut I, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    // check the header
    check_header(input)?;

    let mut nonce = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
    input.read_exact(&mut nonce)?;

    let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];
    input.read_exact(&mut tag)?;

    let mut ct = Vec::new();
    input.read_to_end(&mut ct)?;

    let mut pt = vec![0; ct.len()];
    xchacha20poly1305::decrypt(&mut pt, &ct, key, &tag, &nonce, associated_data)?;

    Ok(pt)
}

pub fn write_to(input: &[u8], path: &Path, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    // TODO: if path exists and is a symlink, resolve it and then append the salt
    // TODO: if the sibling tempfile isn't writeable (e.g. directory permissions), write to
    // env::temp_dir()

    let mut salt = [0u8; 6];
    crypto::rand::fill(&mut salt)?;

    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(hex::encode(salt));
    let tmp = Path::new(&s);

    let mut f = OpenOptions::new().write(true).create_new(true).open(tmp)?;
    write(input, &mut f, key, associated_data)?;
    f.sync_all()?;

    rename(tmp, path)?;

    Ok(())
}

pub fn read_from(path: &Path, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    let mut f: File = OpenOptions::new().read(true).open(path)?;
    check_min_file_len(&mut f)?;
    read(&mut f, key, associated_data)
}

/// check to see if the file is long enough.
fn check_min_file_len(input: &mut File) -> crate::Result<()> {
    let min = MAGIC.len()
        + VERSION.len()
        + xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE
        + xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE;
    if input.metadata()?.len() >= min as u64 {
        Ok(())
    } else {
        Err(crate::Error::SnapshotError("Snapshot is too short to be valid".into()))
    }
}

fn check_header<I: Read>(input: &mut I) -> crate::Result<()> {
    // check the magic bytes
    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(crate::Error::SnapshotError(
            "magic bytes mismatch, is this really a snapshot file?".into(),
        ));
    }

    // check the version
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;
    if version != VERSION {
        return Err(crate::Error::SnapshotError("snapshot version is incorrect".into()));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{corrupt, corrupt_file_at, fresh};

    #[test]
    fn test_write_read() -> crate::Result<()> {
        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        let mut buf = Vec::new();
        write(&bs0, &mut buf, &key, &ad)?;
        let bs1 = read(&mut buf.as_slice(), &key, &ad)?;

        assert_eq!(bs0, bs1);

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_corrupted_read_write() {
        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        let mut buf = Vec::new();
        write(&bs0, &mut buf, &key, &ad).unwrap();
        corrupt(&mut buf);
        read(&mut buf.as_slice(), &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot() -> crate::Result<()> {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write_to(&bs0, &pb, &key, &ad)?;
        let bs1 = read_from(&pb, &key, &ad)?;
        assert_eq!(bs0, bs1);

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_currupted_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write_to(&bs0, &pb, &key, &ad).unwrap();
        corrupt_file_at(&pb);
        read_from(&pb, &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot_overwrite() -> crate::Result<()> {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        write_to(&fresh::bytestring(), &pb, &rand::random(), &fresh::bytestring())?;

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();
        write_to(&bs0, &pb, &key, &ad).unwrap();
        let bs1 = read_from(&pb, &key, &ad)?;
        assert_eq!(bs0, bs1);

        Ok(())
    }

    struct TestVector {
        key: &'static str,
        ad: &'static str,
        data: &'static str,
        snapshot: &'static str,
    }

    #[test]
    fn test_vectors() -> crate::Result<()> {
        let tvs = [
            TestVector {
                key: "aba93968fac84e4fcb9acef1e3a1721ce48ad9e68d4f02a3acb978466020ad42",
                ad: "",
                data: "3a5496ad0ef74e99b5cde8bed5ad4821de97e9bd888287d485f4261e29dedc847805ce705a1693d2560823416151af9d0843795ef2d33645cbcafb725e9375ca02b1001421506f2485353a6065e91d78b75365fa5168bbe84b831239e9610494cc0f4ca9d53cd92d05d3c80d47fce54dabe462167688c3b01037f1eb5746972d50426728697f03e38ceff1653ee8b36befb9e7886a72810e275951ccf31f0cb1ae99742e8e5b1355729ef68c4030d01e06dac2a0928837ed001c9bd5f4e7ca1af0ae8b0228379dbfe05d9aa2df904c4054a0adc4e3273e84b73a1fc670e34b3844be6bfc329de622092c8e351e91cddceeae665a492648147e99e70d9bb1fa3fcf901f723043519a0374b1be5940d8e484f2fba46b7d19141538ac2396f95c25dc6b2bf738fc07a530e2e9798390916d0a377290723f3ee082df416abbb0402eeb3e24f51df728289f9dfef6ebf4fca5e869d0b71ff7f467a0b05379b8aa7b2c2ec7f5b730f9df1fe693746889c54800af172bcf1e49b92c73f0936aabb16778685c3d8b14651dc4e8dd0a1c6e4460c6e1c3efa2bcaabb8dbc68091154e99fa2ff5782343d5b285d2e1646abb45109f4fb60e38a379399938f225e3802c969e8b6d4cc6fb541e76a101591661a6a426bd255d011644abffccfa84b45a6d3a0420c7b6f8dcabf39d4507ba1cd66c4521d8bf8cfecad12da7bcad2359c36d93136d6028a39fd92689c58ba616d16672ca892e865d4a5a75f428ee5c0ba94a04f72f63ce9f61f4267367f9e9f3331d0bc71320c803172a15c732d95dc73bfe587f90d3863435dbb8a23880dc23e75b180ae99d393cbe8a5ad5a136e3a2d67ee2290e4493565399ee64bf5d62e7b849a1f94eb61e13cc6e7e40f4d9be1df727942f52d97120fb25909c038001e36bef15ccec0947ae90496f56d3e5f1b40062d94396d86e1f545ac88e6cccceab516147d6b973e2cab37f33b97129c7490c7c7d40ec02f84ea8883b013b9accef3cedf3caa25810acd0544e09b92da8a937924efe11d08a49c1a7047d4ba5ba8485014115c",
                snapshot: "504152544901000d89fdf89b0addc849a21ac6d61e3613f6cba26ea6483f73be566feec0f44213b541a45fc9606eff8287b33446dc57418712a6b6a1c114d533f9066eb6a7f4d52498b838f269bacdd32da526fe73fd838e3efaff6bb8fe6a70b79be478ee1ce10a0865ef75081706e19fe896ff2535480063c68e43e9a3b7a5c2ef5ca3799fd72f35ffc29ebf421de55cccc30f34069bc6a9819b0d27273de9cafbfb04a9dc2632d2f6c3c813efb4085c404a2f7c4074c60fa53abf058d76b7be4e7af8aa33a3f1f64fac5a80ecc6471f2953c1c74c74515ae8d144acfc39c67b6543dc14b45adeef3e6aa563c5b0dc206b83f1ed23a4e0405fd7d70a8bbc9d547519e686ea7fc738a575452bb8b306a248102c24eac03b7f5c5f7f813bf8c4dbe9367e3362cfff24d3fc2917fcea2b4d9429a13080a57761b6a83022b9738edb1e3f68a256d13e0190f2c5f26c3337f8719d364992c5324f1bbf6096883b93c168354388cf2f53195d77494fd610e94afca7dc242e3abdf0200d5ca6a6d10cfba40ae88200c1b5e311eec4ef7bada0fc2b52c82cb5c6503067552afe34f4d52d9043b46853934aa59366592f75b0a1fcbdfa30f2cdd7c9813f58f9347cc4fb9169d75fa351ba74f5a35b8f58ad3d212e85da07f9c280f69c08f28dfdc6b98498bc04f38e53a3600842921f90d58ec956e82c80c6783723e9001a13ad068cfa999f6b26edc95a488bc3a3ae7a779a6291773801a768d66f695658421e80a743bbe597e7290309061dae5bb3724717b0a1f81c08b73190b3f09abf4109a730f5eb3fe0ccede504f4073485b83a3f7731877c9a00c682f8f662ffe26c53c2dfdd43dce6f60798c58b666121c5a0265c94b93c2e3be894d37a1fb7a61722cda21ee2872d3da97a49f617e405f0690ae62c0e45b979a0c0d8bad313562621752ae2c53314e31a2fff2e18f804ae699aa4529ef00064cccc2958e88476a13d364360d76c032bd5e878cdcc0f5be81b32d3f64f00c804a4e743387fbdc8f8ce70e9033d863032648abb9dcc4a641176581ce44e27871352f150dd05fd23e154e755399817921af2f47459eb6b19a01708eaa4802d37c53050e351714f4591e0c284",
            },
            TestVector {
                key: "5f316b7cf9d1816ed6ec0534c5fe52886056429a1597708203d87974079a4aaa",
                ad: "ce594deb99320e33bfa7205c74ae9bbf7cde97474abf932939cd09ffed398cdd18d5f78cb8540bca74e7ba8f44d4d10118d9b0c00c8ae698cc9a3191454595928c73935fd133dd7dfa1dc879d044e14e324fc0fd3bf7cecf31b3902c633e86b26090b5551480b02601ae5492a712b008724255aa64533f1d6963f6c7f4be17cf5fbbcfccefbaffe3354c197b4ba62ab6e1054e52065228de2d7329ed2be197face5ca435eeecbf2e7659cd6405d43cbb1beda69efbe4b62eebcd91f570f9567b7a681f17b2625678b790c27840f6e3f30771d87d9c3de58f13d9fcbe694d0e9cc62c56d069c67e3cc11597b9761394c2fedc5d9b02b1c3d3f000b9e9f17c25c868cc60125427213b103dd15cd6001879baab9684483b736918a53eb7fa8d2a80a17991f86c3b80d470850dbe837a74976d51f262b6717ca5ef3587c1a8608b311cdfe9cff994db1f097198838e254d39492d3d3499fdc521b030af9ef7df070d1264f54f32abd0914bd6a3ab4b9fdef986e5c32ea4b19a19ada7833944be88e5b1fe208437b1e61094f15aa64a83a90a59354802cf8a032d630084d95aaf81adde47dd3052f4fac4de36ac14412c4cf98d275719d1b4cfa0a554538962c04994237870f42b5d86256c6846b0116c0963db1bd288a5a5f0c9476c2ce2b8037ecb5375632ed564b5247e575810c8b798eb609625781906d1a7e5c3e8ad442776b81a3c4211691d639fdd60c4ca1f408f473d61bb3f674f7350ad2e5eb7a219d79f75192c0964721b56096f13c8551a0cee2ba230fd8eb86f3486fcb6ac9b1f8c5f659fc6bdee029cd59a5cec4ac8b488fc4cf4d83b7e101e3e8a37dfae05e29654af2b7ad0317bc21b8806e422c9cd21186d5dfd3140d8017ecddb4a1ed4262766ae228a12f8fe3d9320f2c18f9a5e16e1a800edee0c225ce4291a311d756a471561a8baec4f5438918898dd37d1a77b121aa2487398743fab1c364c44fe4e6a85d44984e494959d4da20a28d8547723103aca462fc3c8141222a3a77aa573b7836685587ab24d1f51f007d158b712408c630df4e5f7ecabb581e9f69baf3789abbd9a8b751f0b6ae41301386a07b8e44040aa94b807a536e42d2dfad2d7e9a806b70ecfbd3fd92953ffd3abc8c24fc322d88ed034e0e5f642be30e47f5cea3e4c47f0a24473f0e597d4ee4dbd26dcc257f9dff6768fc5b8a7422f5a1f6614086a4822a3b670739b143b943322d40f1a3d47539c367a5ce020685e5be33a9bb73924c4cadca09a118c5ffea7da0aa73447b424ca464b5311321f9384364e8550cede449dc8ac65d75cbbfb97e1a94577d7c9afcb3481888688da4fc6ab39763c93c634a92a0b2c4b7be883d0249a7b55c5c601c009520a99cc2904e1aef1e11df2644ee51c1acbcad49ec5e2c97a5b8ab1cd998f7845bc49e6c6a057394afd98462e7b89126bd17f70b43db53d5a73700cc91117f9c5315c687ba7ff60d757061f06b21bbedcfdddb6861bba9e3dfb8a56210db0bbf27cb492acff7d93809c82a1356a44cc0d907337f0618cce76c23b65ac8c976087e2f5a1e20da64fe278ba26bdcdaf9b856439030d155c52870e8b0805946e23fcee379db8a3fc4c4a6156c7ec9bc89672092f92193c92bae7120556059f57e723a73f53f1eb202cc6b758c9f59e2366260d3e374a8d620ccac989068fa48294f0cab670add0b94459a3929baf41f845634fdecb4f",
                data: "",
                snapshot: "504152544901009612ed70700da18a76a2d55a507083c5483d81bd22302727ca6a323fd7e1f2b23df22190fa3f7868",
            },
            TestVector {
                key: "439f6aad93184f4f72d40c29c6cb3a1929e8ab170b72ead1967a8c331161403b",
                ad: "22a02c4cd209ac5772834e5a8cbda2a006ac88ce43089453a7dae06de70310f623afda8f7e86101e635d20fd6cca8aeba6254ab8c715983d2d484307d1501b157dc7959b3bbfc3bae999e9f4e20ded73cbd8c5660ca69f22cc07a9d6336822da84d6339bd64318cf108f023b966a310bcf338d35b14378eaf7b81e20fc8d9953981e52f1f81155a778dba6a0c972f95b3bc5a6ffc6810d13c7f9d1709e8bac52bf70f0a34d36df5116d7f7396317b98b8fdf0f6e005da73e0d5573b6979298ccbaa2517831c2d6b92316b2dede3f9b01e31bc8f800d9f1cf238de7f10058f73bc440222ac240184410ca44eb77d5616dfb0ddb7d9cdebb2c3f9703d9e53195c5063ef11444af2f396391dc8946355a786fcd725af664fc26caf0964b78e890f37d9bffa24918c5893c1bb45ac1a5eaab67372739372aa921d65578fd8b4364837054f41a53c75d02886fc3c55471bc5ca990c2ba89af213c8e43ea92e35d47ed323509e21d8d89783eb83885e0d65504cb1b2567d8f559ebdd447cff6592ce5b9e18e950630edd72dd9b33a49f244e25c3f1dd825c9e38e0564c99c098e945ea6a76febd8139d80e4e843a7a1d93022b296123c086c3237b0a21270520347391625bf686b4ca6a37dfb8ea65c1ffa1ef7f8eafc526ebeba49608e48ddef7fe171a1559ccf1d40ff7b75c9747e8b382ef3afd0319afeeaf443a5ea2d52e1d7cc7b44e848f544d15c0673f8199bb3ecfda21c2996d3faa53a4d10d847a1945eb7a6e6c490ed1658ff2d2b5bea7074ef07c15090677c1e417af02ad0a9799b89128a9570bd0810f095caa3740ffd86cdc9e42cc202cda796a670a638c81e3a42471e697a1a1ed4af9a5a9c9f67dea09a571df37e85c5ab55e7cd80a52c25895c851933a23388d20ff970cdc53fcb2865ed27f225d2f7e4fcec4cfc4f85afc777318a650f0fb7fa62d277ec5a3668e883bbbed007bc22347f220cfaf2020f11af90311c52b0dafe5d1cb41a68f16ff806367c04f021d78c2341d925f13d12b911c59ee813acb35a66db3c0177bf39992be0ce566c293b4c8789c72128190c83ddd2769304ff8f95fdb4f059159cb34c520751de74419a8bc97fde1677a6724059224c7b218e609cce07cd4b3c4b76a50cd7d55185768b5bda1b924954a9cd796b5bb3275ce5cc4b355f1cd7351d04632286038e19239fd40dc3f4083176af7e32beda249aaeded5314d89daead1c4e23b83742087d38f3fcb5548388d7861d80baad8fd3d74693e871590b8ddcfba1bd7c9b25449a8badc549bb2bff99b5629b705f7631412d165a0ca44e87c59b9c5cc6153856e4aa8e81df785d590affa09242b0eb87ce53f64eb3636aafb6c32f3e5048926f64d01b07a7b58cb9374b94fca1f35ffd3fa2e4cc29aa756889987947467003b9df86193f962b52d302ef4415895f977caef1dc032b7056c48aca0eda85ec9826af413d56305bd23362d8af2be12142e692984ad66e830b972f6e752597153c54c160364f7a5a146d237c327413d5afebba415732dabec4fe7af4fb0eeb3651b8b8662e945d9f600220ff01ca657f89ddc609dabff96a88a93b676a58151c2e449e3bee0462836117eb994f556fe976e03464b62fa7ecc681f093354e986e8c85529e60e4b88d370caeb23dbdb01cf9c8f6bd54fff9fc4e67e67f381f8f239d23463aed2b743023305d218da146f36f69d098b24899e6e353f37287d268a80e6783d5808e24c53062f9e9b2e0e1b66097331f5ca2b789c8f5446b49b09fc35a3d9d5f9da3097256aba46a34e09c3d74a742f5437885ca6c9b64237842d200062c02a71818df6c6b22015e3c9971a7084593e39a02c7cd6d16afc61e96c6538d25e2717e7ce68091cea7e6d30fe60740ae4a31ceba4ae2e4bd8f8e96273e1adf6011c082bd63d7e3a53adcb552f0603b8dd1cd225332a742ab0c5837daff1877ea3c9faa44339eeefba8396def213c9b02354fee72096f66fcbe5db1f390c75fd219bc52d109f53ade43d309757ad15f6abbb1a9ecb32278bde934889a2708510aad7d57caa934f979b86b4bc7eedd1f5dd5c8e5dcc9b6076a221217f555c4db0395d9b6b49f9a061a294534b5e615cf6274974bf1c301929577112b67c1424fdacea7cc0b1a08a532ff5ce41f73d9d1b839e041fe72a0eb0bd8dc8f31899a36c0ac15f652165ad6fac8fd61a10435120a80dd692cba69e612dfdd458bd8331560b74e49b5635fa35959bc44790c0565663ee023e86dc25948e530e4e59feb22d6b8fff2893bf84431e60ecc389fe2a0730783c2e7120878a4008e89869d3e8898fbaecb1dc99748cd04c3d8591a4f330114eefa34981da97354b9dacbf6967e67776eb720b2d1e6819c7fbc35744186d7706862fec117e2614a89d38ba188e67d144062d9e804d0bbb5b06a52abe155d3483bc83d3dfa401ebdff3c82255dbe2d3fb8295a6ca6aa03ad4b7f4796190734e8cbca539dc79e1875a6e89b7e97e5c9b6726a787295a1d53648cbb0218ba1ccc06c7cac804401853f2389a100b51f74c024c3d3838fe255e8613eb0d493b1da1fffa3e6efc40bc0bd8fea9dedb2482106a781ce05af105466c07a41bf09a73ccb5c26df4e10454e559743f0c6b6c30999f4a1a54eb81d807cbae18f87910473c80fcd81732995f59457223cebc862cf49295b88c3d3590b27737ac3b42e819e92a56ff6b7778102ff22e2944b90656f86ef6511cadacc1e48dd165e243cb0278ac44f15e01d01a374c55839df26f64f928611a338e8efe77d74192f617f69fc4afed51a425828bb1e2c4d4246c81714794e2f3ec1fc7829b3c6c439245dff23d9d10cd92df0973b07fc002321cfa06719d5189456a2ca2680ed4e33230039bc5af8e8faad56c1262f534c230a9e615c2f27198523819810eaa9f2a3acabe61566d66787f2dffa7f43deafe9259279c5ccb3c93478d8bab875c74907f0bc369f7eed72b89b3a560eaa05b2ce02ad76662f0a47687d7c6fdcf7c4dc0d7b460d6fa269655bf366595d3bad871c3bde1790413aeb2b95268a8e9785580020400d8c43adf919a88fa2f6735f2b488e33b8a4e78a69f890a254231294d3ba73f046cdf6933619a4ddcb1f8f6c29842160f637dc25f2b44896e62a5ecbcb8f20d666bab09cf0eda159a2d6cd39679a27d9fbb3a5276ffb050ab1839095102f23ffb12090ea985456bb9bd235ca7974b01f4be2b5eb7b78add822838c6a889309575d7a1c5577d835daba983cbee914aa8475af110d5c4058f706b3690787b496097c9b7f83ce65f3c2c81875c354a474f4c30d61511e3c629ca8e06bd444db97b1debd3bb6c5d825870830103935b97d488004da28fbf8fd5d997d73e2df75be0d62285e13f2ab15a543a456f540238c501fa0ddfeaa9c7b9116fda9a6c40f73fb980e0c234ae7563080f5ad0ef4de81d500b80006fe1b26f7d4389f148b8278d78ea254a96c81611b56cd26355fce4f0f4f26f2ef3293daff96912f7e18f931943e086b3849256ad4d2b1f09aa9a9f592f291837668d265993357d81f4710689801d199d6d72a28658ea69c511dab65a6931b045c028b5a1f11726dc699f0053ed48744a3050fede3e02e8286d95edd36fc79a473976aec6ac93b2aa8bf279ffecc8781ad85922d2f497f2d35f6bb401ed356dcd4bc401d35dd8d4b06335049026a2dadadaa245f0b5278ceee0d0b99b824df83a61f1b012137533bc59082003dc92e1c08b751b256aec4661f7099ebbeef71f8ec7fe054798935cc8ff3bcb1d9e70dd4505a45d370489d17862facb68d25e26cd602d7d81344210738c919e63b3313542adeb41835d99cf70fc63befaed4e542d8176e9c8779b29133d461634e73b24d5e4da8e3351f279af8864fa4ecac7806f4e8255f6f2bf045e2e68bf5c4b3cb5833b24b59912ecb99953b897f2042aa01cb6473e7710b201b99af99985e54f7e0a6935aee492f1f8023f4f8586f1b0ed62a5debdd360815b06d9f8d00caca57d4676ca36c55ddf8671c0f8a63b6b39d77ad1c45ecea2c59131b8e242bd377d5b9e1cdb922ba8bb9bca00fa217f3d1ab676e34f81e14856127c4e557c193d37dbdb4cf379eca86fa9aa0718f66a637f55ee5968df9bed7fbb2e18cf67a1eca5be9fcb6dbb27b298e31a90b63b06f8458fcb0a202f027a8347f0cdabac449f9d141b64920cadd3a2f0d880e72adac08fdb0ae1b6320d065cc6fa02d7a88a15987d48e4df7df70b429ed2b2ec1619272168c97a57c418243dfba067f55648e18bfd22d11d517d91b99bd64a414f8ce81a5db85816499349b7c35c741b96cd618a7d23457d8041b08c87701302fbef1609995544ed1256ed57181b6d845d2a900b53bf3c6d96092ea11f3d84d58ad3d648ebfc98f7b6337fc479a6c75314fdbd4376ac8a854f1952119c8cb95d4aae740a227b5512b14d9fc27ce303f8962c1f6327453566f77c511b05ac7856c56381fd5f69431da24b23aa0020ac5299972dfced6d15124f80868fa6d1967e8ecd0085b5e37844ed8b336ac4a5f10feff129513dcecf6bd460dff05004fc695909d600545d350ef3ddd34816376549880a3d80ebdc56ff5d4dbd45eace21acfcb450476c9522c2c7d70fed35c53d280add7802588becf25f171c6be76bb5c4e0343ea4ccd80786ed0762e276e4a0d704599c9feb7e08e691fccf5fee707edd554a070f6d6c43b2dbe1c6d9b0c7612b657c9223d881fbe6fa170ab34328c14c717b468bafe3a612b354f194df2b8ef08718e23d1c0baaa97f0d0f4605fa3c725fc916d355301cf5a277ecdf8d84f8bef833baa7182af1523fb6c062519b33ef7bf95154da4f745aebc875f5ddf35f760b182e2cbbad230808c41bf3c7ff455d65a491c2744b50bfa3c3144d3eb2c9c6435c789fb08cbd49f6cd5c606a5ea7208c4ee011c1f306e338dfe53965f5d58032aa09822e75bb145371c0e1afc6220b55811a0871a0f78e0a39c67a6fb56d768a425b0593abfa2c5c08752f3edacc002164d05716404069372bd5b0140927ded9f88ef4eeb19f0b11190b886cea502a92e4b69fdde14915fba806d6af7435d1d148842969c3cee043da86325e0969f969b889a3f68582f45a1aaf51e0f632f8cd1b449976dc23ce4a2719c98393d334e2ad82a3e9c4206c975e4513da79ec4f36d6a109486425f3fdafe672abe8401f12563810293697576142ab0bcd23293e146fd51b33ca3f14e57de2477586a813a",
                data: "1515552c05ca16d763d9b4a30e1f32b6000175e40848304e4551",
                snapshot: "50415254490100445ca85f1c0cade9ba606f11277faa1a193b68c45b747737d52836ce42b5962612c16da9972633c41fcfe44da42a4fd3554fc23fed6f957e1168de7c38bdc2f15549",
            },
        ];

        for tv in &tvs {
            let mut key = [0; KEY_SIZE];
            hex::decode_to_slice(&tv.key, &mut key).unwrap();
            let ad = hex::decode(tv.ad).unwrap();
            let data = hex::decode(tv.data).unwrap();
            let snapshot = hex::decode(tv.snapshot).unwrap();

            assert_eq!(data, read(&mut snapshot.as_slice(), &key, &ad)?);
        }

        Ok(())
    }
}
