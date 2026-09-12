use super::*;

#[derive(Debug, PartialEq, Eq)]
enum CloseAction {
    Hide,
    Ask,
    Exit,
}

fn close_action(explicit: bool, minimize: bool, ask: bool, tray: bool, busy: bool) -> CloseAction {
    if !explicit && minimize && tray {
        return CloseAction::Hide;
    }
    if busy || (!explicit && (ask || (minimize && !tray))) {
        CloseAction::Ask
    } else {
        CloseAction::Exit
    }
}

impl App {
    pub(super) fn can_start_action(&self) -> bool {
        self.job.is_none() && self.pending_action.is_none() && !self.show_close_confirmation
    }

    pub(super) fn request_close(&mut self, context: &egui::Context, explicit: bool) {
        match close_action(
            explicit,
            self.settings.minimize_on_close,
            self.settings.ask_on_close,
            self.tray.is_some(),
            self.job.is_some() || self.pending_action.is_some(),
        ) {
            CloseAction::Hide => context.send_viewport_cmd(egui::ViewportCommand::Visible(false)),
            CloseAction::Exit => exit_gui(),
            CloseAction::Ask => {
                self.show_close_confirmation = true;
                self.dont_ask_again = false;
                context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                context.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                context.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
        }
    }

    pub(super) fn close_confirmation_ui(&mut self, context: &egui::Context) {
        if !self.show_close_confirmation {
            return;
        }
        let busy = self.job.is_some() || self.pending_action.is_some();
        let mut choice = None;
        let response = egui::Modal::new(egui::Id::new("close-gui"))
            .frame(egui::Frame::window(&context.style()).inner_margin(egui::Margin::same(18)))
            .show(context, |ui| {
            ui.set_max_width(440.0);
            ui.heading(self.t("关闭 MeshLake", "Close MeshLake"));
            ui.label(self.t("退出图形界面后，后台网络服务继续独立运行。", "Background network services keep running after the GUI exits."));
            if busy {
                ui.label(self.t("仍有操作未完成或等待确认。退出会放弃待确认操作；已提交操作可能继续执行，结果需重新打开后核对。", "An operation is unfinished or awaiting confirmation. Exiting discards pending confirmation; submitted work may continue. Reopen the GUI to inspect its result."));
            } else {
                let label = self.t("不再询问", "Don't ask again");
                ui.checkbox(&mut self.dont_ask_again, label);
            }
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                if ui.button(self.t("返回", "Return")).clicked() { choice = Some(None); }
                if ui.add_enabled(self.tray.is_some(), egui::Button::new(self.t("最小化到托盘", "Minimize to tray"))).clicked() { choice = Some(Some(true)); }
                if ui.button(self.t("退出图形界面", "Exit GUI")).clicked() { choice = Some(Some(false)); }
            });
        });
        if let Some(Some(minimize)) = choice {
            self.show_close_confirmation = false;
            if !busy && self.dont_ask_again {
                self.settings.minimize_on_close = minimize;
                self.settings.ask_on_close = false;
                save_settings(&self.settings);
            }
            if minimize {
                context.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                exit_gui();
            }
        } else if choice.is_some() || response.should_close() {
            self.show_close_confirmation = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_policy_preserves_access_and_warns_before_abandoning_work() {
        assert_eq!(
            close_action(false, true, false, false, false),
            CloseAction::Ask
        );
        assert_eq!(
            close_action(false, true, false, true, true),
            CloseAction::Hide
        );
        assert_eq!(
            close_action(true, true, false, true, true),
            CloseAction::Ask
        );
        assert_eq!(
            close_action(false, false, false, true, true),
            CloseAction::Ask
        );
        assert_eq!(
            close_action(true, true, true, true, false),
            CloseAction::Exit
        );
        assert_eq!(
            close_action(false, false, true, true, false),
            CloseAction::Ask
        );
    }
    #[test]
    fn confirmation_blocks_refresh_and_replacement_until_released() {
        let mut app = App::default();
        app.confirm_action(confirmation::PendingAction::StopAgent);
        app.start_job(|_| panic!("confirmation must block worker"));
        app.confirm_action(confirmation::PendingAction::StopAdapter);
        assert!(app.job.is_none());
        assert_eq!(
            app.pending_action,
            Some(confirmation::PendingAction::StopAgent)
        );
        app.pending_action = None;
        app.show_close_confirmation = true;
        app.start_job(|_| panic!("close modal must block worker"));
        assert!(app.job.is_none());
        app.show_close_confirmation = false;
        app.start_job(|worker| worker.message = "released".into());
        assert!(app
            .job
            .take()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .is_ok());
    }
}
