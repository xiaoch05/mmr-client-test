use cmmr::helper;
use merkle_mountain_range::mmr;
use std::env;
use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Peak {
    pub hash: String,
    id: String,
    position: String,
}

#[serde(rename_all = "camelCase")]
#[derive(Serialize, Deserialize, Debug)]
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
    query_data.data.node_entities.iter().map(|hash| {
        let h = String::from(&hash.hash[2..]);
        let xx = hex::decode(h.clone()).expect("Decoding failed");
        let mut dest = [0; 32];
        dest.copy_from_slice(xx.as_slice());
        (hash.position.parse::<u64>().unwrap(), dest)
    }).collect()
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
        write!(f, "    \"mmr_root\": {},\n", String::from("0x") + &self.mmr_root)?;
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
    let args: Vec<String> = env::args().collect();
    let url = args[1].clone();
    let block_num = args[2].parse::<u64>().unwrap();
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
    let checkPoint = CheckPointInfo {
        block_number: block_num,
        position: target_pos,
        peaks: peaks.clone(),
        mmr_root: hex::encode(mmr_root),
    };

    println!("{}", checkPoint);

    // cal proof
    let check_pos = mmr::leaf_index_to_pos(block_num - 1);
    let mmr_size = helper::leaf_index_to_mmr_size(block_num);
    let (merkle_proof_pos, peaks_pos, peak_pos) = mmr::gen_proof_positions(check_pos, mmr_size);
    let proof_peaks = query_positions(&url, peaks_pos).await;
    let merkle_proof_nodes = query_positions(&url, merkle_proof_pos).await;

    let merkle_proof = merkle_proof_nodes.iter().map(|x| {
        x.1
    }).collect();

    // 3. gen proof
    let mmr_proof = mmr::gen_proof(merkle_proof, proof_peaks, peak_pos);
    println!("mmr proof");
    for (idx, v) in mmr_proof.iter().enumerate() {
        println!("{:?}", hex::encode(v));
    }
}
