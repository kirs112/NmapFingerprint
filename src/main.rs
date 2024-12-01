use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::{env, fmt};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use regex::{Regex, RegexBuilder, RegexSet};
use anyhow::{Context, Result};
use tokio::time::{self, Duration, Instant};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ProbesProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub class: String,
    pub service: String,
    pub pattern: String,
    pub versioninfo: String,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.service)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub protocol: ProbesProtocol,
    pub probename: String,
    pub probestring: String,
    pub no_payload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProbe {
    pub probe: Probe,
    pub matchs: Vec<Match>,
    pub softmatchs: Vec<Match>,
    pub ports: Option<Vec<u16>>,
    pub sslports: Option<Vec<u16>>,
    pub totalwaitms: Option<u64>,
    pub tcpwrappedms: Option<u64>,
    pub rarity: Option<u64>,
    pub fallback: Option<Vec<String>>,
}

impl ServiceProbe {

    // Check if a given port is within the port range (supports ranges like "80-90" and comma-separated lists)
    fn is_port_in_range(port: u16, nmap_port_rule: &str) -> bool {
        let ports = nmap_port_rule.split(',').map(|s| s.trim()).collect::<Vec<&str>>();

        for port_range in ports {
            if let Some((start, end)) = port_range.split_once('-') {
                // Handle port ranges (e.g., "80-90")
                let start_port: u16 = start.parse().unwrap_or(0);
                let end_port: u16 = end.parse().unwrap_or(0);
                if port >= start_port && port <= end_port {
                    return true;
                }
            } else if let Ok(single_port) = port_range.parse::<u16>() {
                // Handle single ports (e.g., "80")
                if port == single_port {
                    return true;
                }
            }
        }

        false
    }

    // Filter probes based on the given port and its rarity (sort by rarity)
    fn filter_probes_by_port(port: u16, probes: &mut Vec<ServiceProbe>) -> (Vec<ServiceProbe>, Vec<ServiceProbe>) {
        let mut included = Vec::new();
        let mut excluded = Vec::new();



        for probe in probes.iter_mut() {
            if let Some(ports) = &probe.ports {
                if ServiceProbe::is_port_in_range(port, &ports.iter().map(|&p| p.to_string()).collect::<Vec<String>>().join(",")) {
                    if probe.rarity.is_none() {
                        probe.rarity = Some(0);  // Default rarity if not present
                    }
                    included.push(probe.clone());
                } else {
                    if probe.rarity.is_none() {
                        probe.rarity = Some(0);  // Default rarity if not present
                    }
                    excluded.push(probe.clone());
                }
            } else if let Some(sslports) = &probe.sslports {
                if ServiceProbe::is_port_in_range(port, &sslports.iter().map(|&p| p.to_string()).collect::<Vec<String>>().join(",")) {
                    if probe.rarity.is_none() {
                        probe.rarity = Some(0);  // Default rarity if not present
                    }
                    included.push(probe.clone());
                } else {
                    if probe.rarity.is_none() {
                        probe.rarity = Some(0);  // Default rarity if not present
                    }
                    excluded.push(probe.clone());
                }
            } else {
                // If neither ports nor sslports exist
                if probe.rarity.is_none() {
                    probe.rarity = Some(0);  // Default rarity if not present
                }
                excluded.push(probe.clone());
            }
        }

        // Sort both included and excluded probes by rarity in descending order
        included.sort_by(|a, b| b.rarity.cmp(&a.rarity));
        excluded.sort_by(|a, b| b.rarity.cmp(&a.rarity));

        (included, excluded)
    }
}

fn ports_parser(ports: &str) -> Result<Vec<u16>, anyhow::Error> {
    let mut ret = Vec::new();
    let ports_split: Vec<&str> = ports.split(",").map(|s| s.trim()).collect();
    for ps in ports_split {
        if ps.contains("-") {
            let ps_split: Vec<&str> = ps.split("-").collect();
            let ps_start: u16 = ps_split[0].parse()?;
            let ps_end: u16 = ps_split[1].parse()?;
            for p in ps_start..=ps_end {
                ret.push(p);
            }
        } else {
            let p: u16 = ps.parse()?;
            ret.push(p);
        }
    }
    Ok(ret)
}

pub fn nsp_parser(lines: &[String]) -> Result<Vec<ServiceProbe>, anyhow::Error> {

    let mut regexs_pattern: Vec<String> = Vec::new();
    let mut ret: Vec<ServiceProbe> = Vec::new();
    let mut probe_global: Option<Probe> = None;
    let mut matchs_global: Vec<Match> = Vec::new();
    let mut softmatchs_global: Vec<Match> = Vec::new();
    let mut ports_global: Option<Vec<u16>> = None;
    let mut sslports_global: Option<Vec<u16>> = None;
    let mut totalwaitms_global: Option<u64> = None;
    let mut tcpwrappedms_global: Option<u64> = None;
    let mut rarity_global: Option<u64> = None;
    let mut fallback_gloabl: Option<Vec<String>> = None;
    for line in lines {
        if line.contains("#") {
            continue;
        } else if line.contains("Exclude") {
            continue;
        }

        if line.starts_with("Probe") {
            match probe_global {
                Some(p) => {
                    let sp = ServiceProbe {
                        probe: p,
                        matchs: matchs_global,
                        softmatchs: softmatchs_global,
                        ports: ports_global.clone(),
                        sslports: sslports_global.clone(),
                        totalwaitms: totalwaitms_global,
                        tcpwrappedms: tcpwrappedms_global,
                        rarity: rarity_global,
                        fallback: fallback_gloabl.clone(),
                    };
                    ret.push(sp);
                    matchs_global = Vec::new();
                    softmatchs_global = Vec::new();
                    ports_global = None;
                    sslports_global = None;
                    totalwaitms_global = None;
                    tcpwrappedms_global = None;
                    rarity_global = None;
                    fallback_gloabl = None;
                }
                None => (),
            }

            let line_split: Vec<&str> = line.split(" ").collect();
            let protocol = match line_split[1] {
                "TCP" => ProbesProtocol::Tcp,
                "UDP" => ProbesProtocol::Udp,
                _ => panic!("new protocol: {}", line_split[1]),
            };
            let probename = line_split[2].to_string();
            let probelast = line_split[3..].to_vec().join(" ");
            let probelast_split: Vec<&str> = probelast.split("|").map(|s| s.trim()).collect();
            let probestring = probelast_split[1].to_string();
            let no_payload = if probelast.contains("no-payload") {
                true
            } else {
                false
            };
            let sp = Probe {
                protocol,
                probename,
                probestring,
                no_payload,
            };
            probe_global = Some(sp);
        } else if line.starts_with("match") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let class = line_split[0].to_string();
            let service = line_split[1].to_string();
            let line_other = line_split[2..].to_vec().join(" ");

            let line_other_replace = line_other.replace("|s", "|");
            let line_other_split: Vec<&str> = line_other_replace.split("|").collect();
            let mut pattern = line_other_split[1].to_string();
            regexs_pattern.push(pattern.clone());
            // if line_other.contains("|s") {
            // 	pattern += r"\s"
            // } else if line_other.contains("|i") {
            // 	pattern += r"\i";
            // }

            let versioninfo = line_other_split[line_other_split.len() - 1]
                .trim()
                .to_string();

            let m = Match {
                class,
                service,
                pattern,
                versioninfo,
            };
            matchs_global.push(m);
        } else if line.starts_with("softmatch") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let class = line_split[0].to_string();
            let service = line_split[1].to_string();
            let line_other = line_split[2..].to_vec().join(" ");

            let line_other_replace = line_other.replace("|s", "|");
            let line_other_split: Vec<&str> = line_other_replace.split("|").collect();
            let  pattern = line_other_split[1].to_string();
            // if line_other.contains("|s") {
            // 	pattern += r"\s"
            // } else if line_other.contains("|i") {
            // 	pattern += r"\i";
            // }

            let versioninfo = line_other_split[line_other_split.len() - 1]
                .trim()
                .to_string();

            let m = Match {
                class,
                service,
                pattern,
                versioninfo,
            };
            softmatchs_global.push(m);
        } else if line.starts_with("ports") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let ports_line = line_split[1..].to_vec().join(" ");
            let ports = ports_parser(&ports_line)?;
            ports_global = Some(ports);
        } else if line.starts_with("sslports") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let sslports_line = line_split[1..].to_vec().join(" ");
            let sslports = ports_parser(&sslports_line)?;
            sslports_global = Some(sslports);
        } else if line.starts_with("totalwaitms") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let totalwaitms: u64 = line_split[1].parse()?;
            totalwaitms_global = Some(totalwaitms);
        } else if line.starts_with("tcpwrappedms") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let tcpwrappedms: u64 = line_split[1].parse()?;
            tcpwrappedms_global = Some(tcpwrappedms);
        } else if line.starts_with("rarity") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let rarity: u64 = line_split[1].parse()?;
            rarity_global = Some(rarity);
        } else if line.starts_with("fallback") {
            let line_split: Vec<String> = line.split(" ").map(|s| s.to_string()).collect();
            let fallback = line_split[1..].to_vec();
            fallback_gloabl = Some(fallback);
        }
    }
    match probe_global {
        Some(p) => {
            let sp = ServiceProbe {
                probe: p,
                matchs: matchs_global,
                softmatchs: softmatchs_global,
                ports: ports_global,
                sslports: sslports_global,
                totalwaitms: totalwaitms_global,
                tcpwrappedms: tcpwrappedms_global,
                rarity: rarity_global,
                fallback: fallback_gloabl,
            };
            ret.push(sp);
        }
        None => (),
    }
    Ok(ret)
}

async fn send_tcp_request(
    host: &str,
    port: u16,
    payload: Vec<u8>,
    timeout_duration: Duration
) -> Result<String> {
    // 记录请求开始时间

    // 设置超时
    let connection_future = TcpStream::connect((host, port));
    let mut stream = time::timeout(timeout_duration, connection_future)
        .await
        .context("Connection timed out")??;

    // 构建要发送的 payload
    // let payload = parse_escape_sequence(&probe.probe.probestring);

    // let test:Vec<u8> = vec![0, 0, 0, 164, 255, 83, 77, 66, 114, 0, 0, 0, 0, 8, 1, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 1, 0, 0, 129, 0, 2, 80, 67, 32, 78, 69, 84, 87, 79, 82, 75, 32, 80, 82, 79, 71, 82, 65, 77, 32, 49, 46, 48, 0, 2, 77, 73, 67, 82, 79, 83, 79, 70, 84, 32, 78, 69, 84, 87, 79, 82, 75, 83, 32, 49, 46, 48, 51, 0, 2, 77, 73, 67, 82, 79, 83, 79, 70, 84, 32, 78, 69, 84, 87, 79, 82, 75, 83, 32, 51, 46, 48, 0, 2, 76, 65, 78, 77, 65, 78, 49, 46, 48, 0, 2, 76, 77, 49, 46, 50, 88, 48, 48, 50, 0, 2, 83, 97, 109, 98, 97, 0, 2, 78, 84, 32, 76, 65, 78, 77, 65, 78, 32, 49, 46, 48, 0, 2, 78, 84, 32, 76, 77, 32, 48, 46, 49, 50, 0];
    //
    // let test =vec![71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 48, 13, 10, 13, 10];


    // 异步写入数据到流
    let send_result = time::timeout(timeout_duration, stream.write_all(&payload)).await;
    if let Err(e) = send_result {
        // 处理超时或其他错误，打印警告并返回默认值
        println!("Warning: Failed to send probe data: {:?}", e);
        return Ok(String::from("")); // 返回一个空的响应，继续执行
    }


    // 异步读取响应
    let mut buffer = vec![0; 1024];
    let read_result = time::timeout(timeout_duration, stream.read(&mut buffer)).await;
    let bytes_read = match read_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_e)) => {
            // println!("Warning: Failed to read response: {:?}", e);
            return Ok(String::from("")); // 返回一个空的响应，继续执行
        }
        Err(_e) => {
            // println!("Warning: Read operation timed out: {:?}", e);
            return Ok(String::from("")); // 返回一个空的响应，继续执行
        }
    };


    // 将响应转换为 String
    let response = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

    Ok(response)
}

async fn scan_with_probes(host: &str, port: u16, protocol: &str, included: Vec<ServiceProbe>, excluded: Vec<ServiceProbe>) -> Result<HashMap<String, String>> {
    let mut record = HashMap::new();
    for probe in included {
        let mut payload = probe.probe.probestring.clone();
        if payload.contains("\\r")|| payload.contains("\\n"){
            payload = payload.replace("\\r","\r");
            payload = payload.replace("\\n","\n");
        }
        let payload = parse_escape_sequence(&payload);
        // 发送探测报文并接收响应
        let response = send_tcp_request(&host, port, payload, Duration::from_millis(1000)).await?;

        if response.is_empty() {
            // println!("response is empty");
            continue;
        }

        let (nmap_pattern, nmap_fingerprint) = match_probe_pattern(&response, &probe);
        //
        if nmap_pattern.is_empty() && nmap_fingerprint.is_empty() {
            continue;
        }else {
            record.insert("probe_name".to_string(), probe.probe.probename.clone());
            record.insert("probe_string".to_string(), probe.probe.probestring.clone());
            record.insert("pattern".to_string(), nmap_pattern);

            // Inserting versioninfo if available
            if let Some(versioninfo) = nmap_fingerprint.get("versioninfo") {
                record.insert("versioninfo".to_string(), versioninfo.clone());
            }
        }

    }if record.is_empty() {
        for probe in excluded {

            let mut payload = probe.probe.probestring.clone();
            if payload.contains("\\r")|| payload.contains("\\n"){
                payload = payload.replace("\\r","\r");
                payload = payload.replace("\\n","\n");
            }
            let payload = parse_escape_sequence(&payload);
            // 发送探测报文并接收响应
            let response = send_tcp_request(&host, port, payload, Duration::from_millis(1000)).await?;
            if response.is_empty() {
                // println!("response is empty");
                continue;
            }
            let (nmap_pattern, nmap_fingerprint) = match_probe_pattern(&response, &probe);
            if nmap_pattern.is_empty() && nmap_fingerprint.is_empty() {
                continue;
            }else {
                record.insert("probe_name".to_string(), probe.probe.probename.clone());
                record.insert("probe_string".to_string(), probe.probe.probestring.clone());
                record.insert("pattern".to_string(), nmap_pattern);
                // Inserting versioninfo if available
                if let Some(versioninfo) = nmap_fingerprint.get("versioninfo") {
                    record.insert("versioninfo".to_string(), versioninfo.clone());
                }
            }
        }
    }
    Ok(record)
}


fn match_probe_pattern(data: &str, probe: &ServiceProbe) -> (String, HashMap<String, String>) {
    let mut nmap_pattern = String::new();
    let mut nmap_fingerprint = HashMap::new();


    if data.is_empty() {
        return (nmap_pattern, nmap_fingerprint);
    }


    // Iterate over matches and attempt to match patterns
    for m in &probe.matchs {
        let pattern = &m.pattern;

        let re = match  regex::RegexBuilder::new(&pattern).octal(true).build() {

            Ok(re) => re,
            Err(_) => {
                continue
            }, // Skip if the regex is invalid
        };



        let service = &m.service;


        if let Some(rfind) = re.captures(data) {
            let mut versioninfo = m.versioninfo.clone();
            for (i, capture) in rfind.iter().enumerate() {
                let dollar_name = format!("${}", i + 1);
                if let Some(capture_value) = capture {
                    versioninfo = versioninfo.replace(&dollar_name, capture_value.as_str());
                }
            }

            nmap_pattern = pattern.clone();

            // Match versioninfo and convert Vec<String> to String
            let mut fingerprint_str = String::new();
            if !versioninfo.is_empty() {
                fingerprint_str = versioninfo;
            }

            nmap_fingerprint.insert("service".to_string(), service.clone());
            nmap_fingerprint.insert("versioninfo".to_string(), fingerprint_str);

            break;
        }
    }

    (nmap_pattern, nmap_fingerprint)
}


fn capture_regex(text: &str, pattern: &str) -> Option<Vec<String>> {
    let re = Regex::new(pattern).ok()?;
    let captures: Vec<String> = re.captures_iter(text)
        .map(|cap| cap[1].to_string())
        .collect();

    if captures.is_empty() {
        None
    } else {
        Some(captures)
    }
}

fn match_versioninfo(versioninfo: &str) -> HashMap<String, Vec<String>> {
    let mut record: HashMap<String, Vec<String>> = HashMap::new();

    // Match various patterns
    if let Some(vendor_product_name) = capture_regex(versioninfo, r"p/([^/]*)/") {
        record.insert("vendorproductname".to_string(), vendor_product_name);
    }

    if let Some(version) = capture_regex(versioninfo, r"v/([^/]*)/") {
        record.insert("version".to_string(), version);
    }

    if let Some(info) = capture_regex(versioninfo, r"i/([^/]*)/") {
        record.insert("info".to_string(), info);
    }

    if let Some(hostname) = capture_regex(versioninfo, r"h/([^/]*)/") {
        record.insert("hostname".to_string(), hostname);
    }

    if let Some(operating_system) = capture_regex(versioninfo, r"o/([^/]*)/") {
        record.insert("operatingsystem".to_string(), operating_system);
    }

    if let Some(device_type) = capture_regex(versioninfo, r"d/([^/]*)/") {
        record.insert("devicetype".to_string(), device_type);
    }

    if let Some(cpe_name) = capture_regex(versioninfo, r"cpe:/a:([^/]*)/") {
        record.insert("cpename".to_string(), cpe_name);
    }

    record
}


fn parse_escape_sequence(input: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with("\\x") {
            let hex_str = &input[i + 2..i + 4];
            let byte = u8::from_str_radix(hex_str, 16).unwrap();
            output.push(byte);
            i += 4; // Skip over the `\\x` and the two hex digits
        } else if input[i..].starts_with("\\0") {
            output.push(0);
            i += 2; // Skip over the `\\0`
        } else {
            // If it's any other character, just add it as is
            output.push(input[i..i + 1].as_bytes()[0]);
            i += 1;
        }
    }
    output
}


use serde_json::{to_writer_pretty, Value};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let query = &args[1];
    let port = &args[2];
    let mut file = OpenOptions::new().append(true).create(true).open("foo.txt").unwrap();


    let nsp_str = include_str!("../nmap-service-probes.txt");
    let mut nsp_lines = Vec::new();
    for l in nsp_str.lines() {
        nsp_lines.push(l.to_string());
    }

    let  mut service_probes = nsp_parser(&nsp_lines)?;




    let (included, excluded) = ServiceProbe::filter_probes_by_port(port.parse()?, &mut service_probes);


    let test = scan_with_probes(query, port.parse()?, "TCP", included, excluded).await?;
    println!("{:?}", test);
    //
    // let match_versioninfo = match_versioninfo(&test.get("versioninfo").unwrap());
    // let ret: Vec<_> = match_versioninfo.iter().map(|(_, value)| value.clone()).collect();
    //
    //
    // println!("{:?}", ret);




    Ok(())
}