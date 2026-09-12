use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PendingAction {
    StopAgent,
    StartService {
        binary: String,
        args: Vec<String>,
    },
    StopService(Uuid),
    StopAdapter,
    Leave(Uuid),
    DeleteNetwork(Uuid),
    RemoveMember(Uuid, Uuid),
    Backup(bool),
    NativeTask {
        label: String,
        binary: String,
        args: Vec<String>,
    },
    ClearExit(Uuid),
    DisableGateway(Uuid),
    RevokeExit(Uuid, Uuid),
}

impl PendingAction {
    fn description(&self, language: Language) -> String {
        let zh = language == Language::Chinese;
        match self {
            Self::StartService { binary, args } => format!("{}\n{binary}\n{}", if zh { "启动以下本机服务？请核对监听地址、配置和状态文件。" } else { "Start this local service? Review listener, configuration and state paths." }, args.join("\n")),
            Self::StopService(id) => format!("{}\n{id}", if zh { "终止本次启动的进程？未保存的运行中操作可能中断；不会终止其他同名实例。" } else { "Terminate this owned process? In-flight operations may be interrupted. Other instances are unaffected." }),
            Self::NativeTask { label, binary, args } => format!("{}\n{label}\n{binary}\n{}", if zh { "确认执行以下维护操作？" } else { "Confirm this maintenance operation?" }, args.join("\n")),
            Self::ClearExit(network) => format!("{}\n{network}", if zh { "清除出口选择及故障关闭设置？流量可能恢复使用本机网络。" } else { "Clear exit selection and kill switch? Traffic may return to the local network." }),
            Self::DisableGateway(network) => format!("{}\n{network}", if zh { "停止此网络的出口网关？使用它的设备可能失去连接。" } else { "Disable this exit gateway? Devices using it may lose connectivity." }),
            Self::RevokeExit(network, device) => format!("{}\nNetwork: {network}\nDevice: {device}", if zh { "撤销此设备的出口授权？" } else { "Revoke this device's exit authorization?" }),
            Self::Backup(restore) => if *restore {
                if zh { "恢复备份中的身份与网络配置？请先停止对应服务；勾选覆盖时会替换当前状态。" } else { "Restore identity and networks? Stop the matching service first. Enabling replacement overwrites current state." }
            } else {
                if zh { "创建加密备份并允许覆盖目标文件？" } else { "Create an encrypted backup and allow replacing the target file?" }
            }.into(),
            Self::StopAgent => if zh {
                "停止本机后台服务及当前网络会话？GUI 将保持打开。"
            } else {
                "Stop the local agent and its network sessions? The GUI stays open."
            }
            .into(),
            Self::StopAdapter => if zh {
                "停止虚拟网卡？当前连接会中断。"
            } else {
                "Stop the virtual adapter? Current connectivity will be interrupted."
            }
            .into(),
            Self::Leave(id) => format!(
                "{}\n{id}",
                if zh {
                    "离开以下网络？重新加入需要有效邀请。"
                } else {
                    "Leave this network? Rejoining requires a valid invitation."
                }
            ),
            Self::DeleteNetwork(id) => format!(
                "{}\n{id}",
                if zh {
                    "删除控制器上的以下网络？成员将失去该网络授权。"
                } else {
                    "Delete this controller network? Members will lose authorization."
                }
            ),
            Self::RemoveMember(network, device) => format!(
                "{}\nNetwork: {network}\nDevice: {device}",
                if zh {
                    "移除以下成员并轮换网络密钥？"
                } else {
                    "Remove this member and rotate the network key?"
                }
            ),
        }
    }
}

impl App {
    pub(super) fn confirm_action(&mut self, action: PendingAction) {
        if self.can_start_action() {
            self.pending_action = Some(action);
        }
    }
    pub(super) fn confirmation_ui(&mut self, context: &egui::Context) {
        if self.show_close_confirmation {
            return;
        }
        let Some(action) = self.pending_action.clone() else {
            return;
        };
        let mut execute = false;
        let mut cancel = false;
        let response = egui::Modal::new(egui::Id::new("confirm-operation"))
            .frame(egui::Frame::window(&context.style()).inner_margin(egui::Margin::same(18)))
            .show(context, |ui| {
                ui.set_max_width(460.0);
                ui.heading(self.t("确认操作", "Confirm operation"));
                egui::ScrollArea::vertical()
                    .max_height((context.screen_rect().height() - 180.0).max(80.0))
                    .show(ui, |ui| {
                        ui.label(action.description(self.settings.language));
                        if matches!(action, PendingAction::Backup(_)) {
                            ui.label(if self.maintenance.controller_state {
                                "Controller"
                            } else {
                                "Agent"
                            });
                            if !self.maintenance.state_file.trim().is_empty() {
                                ui.monospace(&self.maintenance.state_file);
                            }
                            ui.monospace(&self.maintenance.path);
                        }
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    cancel = ui.button(self.t("取消", "Cancel")).clicked();
                    execute = ui.button(self.t("确认执行", "Confirm")).clicked();
                });
            });
        if execute {
            self.pending_action = None;
            match action {
                PendingAction::StartService { binary, args } => self.launch_service(binary, args),
                PendingAction::StopService(id) => self.stop_owned_service(id),
                PendingAction::NativeTask { binary, args, .. } => {
                    self.run_native_task(binary, args)
                }
                PendingAction::StopAgent => self.stop_agent(),
                PendingAction::StopAdapter => self.adapter(false),
                PendingAction::Leave(id) => self.leave_network(id),
                PendingAction::DeleteNetwork(id) => self.delete_managed_network(id),
                PendingAction::RemoveMember(network, device) => self.remove_member(network, device),
                PendingAction::Backup(restore) => self.execute_backup(restore),
                PendingAction::ClearExit(id) => {
                    self.exit_network_id = id.to_string();
                    self.clear_exit_selection();
                }
                PendingAction::DisableGateway(id) => {
                    self.exit_network_id = id.to_string();
                    self.remove_exit_gateway();
                }
                PendingAction::RevokeExit(network, device) => {
                    self.selected_network = Some(network);
                    self.candidate_device = device.to_string();
                    self.update_controller_exit(false);
                }
            }
        } else if cancel || response.should_close() {
            self.pending_action = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requesting_confirmation_never_starts_network_work() {
        let mut app = App::default();
        let id = Uuid::new_v4();
        app.confirm_action(PendingAction::Leave(id));
        assert_eq!(app.pending_action, Some(PendingAction::Leave(id)));
        assert!(app.job.is_none());
        assert!(app
            .pending_action
            .as_ref()
            .unwrap()
            .description(Language::English)
            .contains(&id.to_string()));
    }
}
