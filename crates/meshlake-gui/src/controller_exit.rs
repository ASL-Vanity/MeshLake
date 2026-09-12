use super::*;
use serde_json::Value;

// Same compact policy representation used by `controller exit set/clear`.
// Preserve split routes, DNS and other exit candidates when changing one device.
fn policy_update(
    manifest: &Value,
    device: Uuid,
    capability: Option<(bool, bool)>,
) -> Result<Value, String> {
    let routes = manifest["routes"]
        .as_array()
        .ok_or("控制器路由列表无效")?
        .iter()
        .map(|route| {
            let prefix = route["prefix"].as_str().ok_or("路由缺少前缀")?;
            let gateway = route
                .pointer("/gateway_certificate/claims/device_id")
                .and_then(Value::as_str)
                .ok_or("路由缺少网关设备")?;
            Ok(json!({"prefix": prefix, "gateway_device_id": gateway}))
        })
        .collect::<Result<Vec<Value>, String>>()?;
    let mut exits = Vec::new();
    if let Some(nodes) = manifest.get("exit_nodes") {
        for node in nodes.as_array().ok_or("出口列表无效")? {
            let gateway = node
                .pointer("/gateway_certificate/claims/device_id")
                .and_then(Value::as_str)
                .ok_or("出口缺少设备 ID")?;
            let id = Uuid::parse_str(gateway).map_err(|_| "出口设备 ID 无效")?;
            let v4 = node["supports_ipv4"]
                .as_bool()
                .ok_or("出口缺少 IPv4 能力")?;
            let v6 = node["supports_ipv6"]
                .as_bool()
                .ok_or("出口缺少 IPv6 能力")?;
            if id != device {
                exits.push(
                    json!({"gateway_device_id": gateway, "supports_ipv4": v4, "supports_ipv6": v6}),
                );
            }
        }
    }
    if let Some((v4, v6)) = capability {
        if !v4 && !v6 {
            return Err("至少选择一种地址协议。".into());
        }
        exits.push(json!({"gateway_device_id": device, "supports_ipv4": v4, "supports_ipv6": v6}));
    }
    Ok(
        json!({"routes": routes, "exit_nodes": exits, "dns": manifest.get("dns").cloned().unwrap_or(json!({}))}),
    )
}

impl App {
    pub(super) fn update_controller_exit_sync(&mut self, grant: bool) {
        let result = (|| -> Result<(), String> {
            let network = self.selected_network.ok_or("请先选择控制器网络。")?;
            let device = Uuid::parse_str(self.candidate_device.trim())
                .map_err(|_| "设备 ID 必须是 UUID。")?;
            let path = format!("/v1/networks/{network}/policy");
            let capability = grant.then_some((self.candidate_ipv4, self.candidate_ipv6));
            if capability == Some((false, false)) {
                return Err("至少选择一种地址协议。".into());
            }
            let response = self
                .controller_request(reqwest::Method::GET, path.clone(), false)?
                .send()
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("读取策略失败：HTTP {}", response.status()));
            }
            let manifest: Value = response.json().map_err(|e| e.to_string())?;
            let body = policy_update(&manifest, device, capability)?;
            let response = self
                .controller_request(reqwest::Method::POST, path, true)?
                .json(&body)
                .send()
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("更新策略失败：HTTP {}", response.status()));
            }
            self.policy_editor.invalidate_after_exit_update();
            Ok(())
        })();
        self.message = match result {
            Ok(()) => if grant {
                "出口候选授权已保存。策略草稿已保留，请重新读取策略后再保存。 / Exit granted. Policy draft retained; reload before saving."
            } else {
                "出口候选授权已撤销。策略草稿已保留，请重新读取策略后再保存。 / Exit revoked. Policy draft retained; reload before saving."
            }
            .into(),
            Err(error) => error,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changing_candidate_preserves_routes_dns_and_other_candidates() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let manifest = json!({"routes": [{"prefix": "10.0.0.0/24", "gateway_certificate": {"claims": {"device_id": other}}}], "dns": {"servers": ["10.0.0.1"]}, "exit_nodes": [
            {"gateway_certificate": {"claims": {"device_id": target}}, "supports_ipv4": true, "supports_ipv6": false},
            {"gateway_certificate": {"claims": {"device_id": other}}, "supports_ipv4": true, "supports_ipv6": true}
        ]});
        let result = policy_update(&manifest, target, Some((false, true))).unwrap();
        assert_eq!(result["dns"], manifest["dns"]);
        assert_eq!(result["routes"][0]["gateway_device_id"], other.to_string());
        assert_eq!(result["exit_nodes"].as_array().unwrap().len(), 2);
        assert_eq!(result["exit_nodes"][1]["supports_ipv6"], true);
        let cleared = policy_update(&manifest, target, None).unwrap();
        assert_eq!(cleared["exit_nodes"].as_array().unwrap().len(), 1);
        assert_eq!(
            cleared["exit_nodes"][0]["gateway_device_id"],
            other.to_string()
        );
    }
    #[test]
    fn malformed_policy_is_not_replaced_with_empty_routes() {
        assert!(policy_update(&json!({}), Uuid::new_v4(), None).is_err());
        assert!(
            policy_update(&json!({"routes": []}), Uuid::new_v4(), Some((false, false))).is_err()
        );
    }
}
