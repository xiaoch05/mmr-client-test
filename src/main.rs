use merkle_mountain_range::mmr;
use std::env;
use std::fmt;
use serde::{Deserialize, Serialize};

use cmmr::Merge;
use merkle_mountain_range::mmr::merge;
struct MergeHash;
impl Merge for MergeHash {
    type Item = [u8; 32];
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Self::Item {
        merge(lhs, rhs)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peak {
    pub hash: String,
    id: String,
    position: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeEntities {
    pub node_entities: Vec<Peak>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubgraphData {
    pub data: NodeEntities,
}

pub async fn query_subql(url: &str, positions: &str) -> SubgraphData {
    let client = reqwest::Client::new();
    let res = client.post(url)
        .header("Content-Type", "application/json")
        .body(String::from("{\n\"query\":\"{\\n nodeEntities(where: {position_in: [") + positions + "]}) {\\n    id\\n    position\\n    hash\\n  }\\n}\\n\",\n    \"variables\":null\n}")
        .send()
        .await.unwrap()
        .text().await.unwrap();
    serde_json::from_str(&res).unwrap()
}

pub async fn query_positions(url: &str, positions: Vec<u64>) -> Vec<(u64, [u8; 32])> {
    let positions_str = positions.iter().fold(
        String::from(""),
        |pre, &next| {
        pre + ", \\\"" + &next.to_string() + "\\\""
        }
    );
    let query_data = query_subql(&url, &positions_str).await;
    let mut unsorted: Vec<(u64, [u8; 32], usize)> = query_data.data.node_entities.iter().map(|hash| {
        let h = String::from(&hash.hash[2..]);
        let xx = hex::decode(h.clone()).expect("Decoding failed");
        let mut dest = [0; 32];
        dest.copy_from_slice(xx.as_slice());
        let pos = hash.position.parse::<u64>().unwrap();
        let index = positions.iter().position(|&x| x == pos).unwrap();
        let ret = (hash.position.parse::<u64>().unwrap(), dest, index);
        ret
    }).collect();
    unsorted.sort_by(|x, y| x.2.partial_cmp(&y.2).unwrap());
    unsorted.iter().map(|v| (v.0, v.1)).collect()
}

pub struct CheckPointInfo {
    block_number: u64,
    position: u64,
    peaks: Vec<(String, String)>,
    mmr_root: String,
}

impl fmt::Display for CheckPointInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{\n")?;
        write!(f, "    \"blocknum\": {},\n", self.block_number)?;
        write!(f, "    \"position\": {},\n", self.position)?;
        write!(f, "    \"parent_mmr_root\": {},\n", String::from("0x") + &self.mmr_root)?;
        write!(f, "    \"peaks\": [\n")?;
        for (count, v) in self.peaks.iter().enumerate() {
            if count != 0 { write!(f, ",\n")?; }
            write!(f, "        {}: {}", v.0, String::from("0x") + &v.1)?;
        }
        write!(f, "\n    ]\n")?;
        write!(f, "}}\n")
    }
}

#[tokio::main]
async fn main() {
    // ############## checkpoint #################
    let args: Vec<String> = env::args().collect();
    let url = args[1].clone();
    let block_num = args[2].parse::<u64>().unwrap();
    let verify_num = args[3].parse::<u64>().unwrap();
    if verify_num >= block_num {
        println!("verify_num cannot bigger then block_num");
        return
    }
    let target_pos = mmr::leaf_index_to_pos(block_num);
    let target_peaks = mmr::get_peaks(target_pos);
    let print_peaks = target_peaks.iter().fold(
        String::from(""),
        |pre, &next| {
        pre + ", \\\"" + &next.to_string() + "\\\""
        }
    );
    let subdata = query_subql(&url, &print_peaks).await;
    let peaks: Vec<(String, String)> = subdata.data.node_entities.iter().map(|peak| {
        (peak.position.clone(), String::from(&peak.hash[2..]))
    }).collect();

    let targetpeak_hashs = peaks.iter().map(|x| {
        let xx = hex::decode(x.1.clone()).expect("Decoding failed");
        let mut dest = [0; 32];
        dest.copy_from_slice(xx.as_slice());
        dest
    }).collect();

    let mmr_root = mmr::bag_rhs_peaks(targetpeak_hashs).unwrap();
    let checkpoint = CheckPointInfo {
        block_number: block_num,
        position: target_pos,
        peaks: peaks.clone(),
        mmr_root: hex::encode(mmr_root),
    };
    println!("{}", checkpoint);
    // ############## checkpoint end #################

    // ############## generate mmr proof #################
    // 1. cal proof positions
    let check_pos = mmr::leaf_index_to_pos(verify_num);
    let mmr_size = mmr::leaf_index_to_pos(block_num);
    let (merkle_proof_pos, peaks_pos, peak_pos) = mmr::gen_proof_positions(check_pos, mmr_size);

    // 2. query hash by positions from thegraph
    let proof_peaks = query_positions(&url, peaks_pos).await;
    let merkle_proof_nodes = query_positions(&url, merkle_proof_pos).await;
    let merkle_proof: Vec<[u8; 32]> = merkle_proof_nodes.iter().map(|x| { x.1 }).collect();

    // we need reverse here because the response from thegraph is sorted by id
    //merkle_proof.reverse();

    // 3. gen proof by hashes
    let mmr_proof = mmr::gen_proof(merkle_proof, proof_peaks, peak_pos);
    println!("mmr proof");
    for (_, v) in mmr_proof.iter().enumerate() {
        println!("{:?}", hex::encode(v));
    }
    // ############## generate mmr proof end #################

    // ############## verify mmr proof #################
    // verify proof
    let proof = cmmr::MerkleProof::<[u8;32], MergeHash>::new(mmr_size, mmr_proof);
    let checked_position = query_positions(&url, vec![check_pos]).await;
    let checked = checked_position[0].1;
    // this should return true
    println!("{:?}", proof.verify(mmr_root, vec![(check_pos, checked)]).unwrap());
    // ############## verify mmr proof end #################
}

