use super::*;
use egui::{Color32, CornerRadius, Margin, Stroke};

pub(super) fn preferences_window<'a>(
    context: &egui::Context,
    title: &'a str,
    open: &'a mut bool,
) -> egui::Window<'a> {
    let frame = egui::Frame::window(&context.style());
    let title_height = context.style().spacing.interact_size.y.max(22.0);
    // Window max_height limits the body, excluding the title and both sets
    // of frame margins. Reserve them explicitly before adding scrolling.
    let chrome = title_height + frame.total_margin().sum().y * 2.0 + 20.0;
    egui::Window::new(title)
        .id(egui::Id::new("preferences"))
        .open(open)
        .frame(frame)
        .collapsible(false)
        .resizable(false)
        .vscroll(true)
        .min_width(0.0)
        .max_width((context.screen_rect().width() - 56.0).max(80.0))
        .max_height((context.screen_rect().height() - chrome).max(32.0))
}

pub(super) fn input(text: &mut dyn egui::TextBuffer) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text)
        .margin(Margin::symmetric(8, 7))
        .min_size(egui::vec2(0.0, 32.0))
        .desired_width(f32::INFINITY)
}

pub(super) fn document_view(ui: &mut egui::Ui, id: impl std::hash::Hash, text: &mut String) {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(240.0)
        .min_scrolled_height(120.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .desired_width(f32::INFINITY)
                    .desired_rows(4)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
        });
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn theme_colors_roundtrip_and_keep_selection_text_readable() {
        fn luminance(color: Color32) -> f32 {
            let linear = |value: u8| {
                let v = value as f32 / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
        }
        let legacy: Settings =
            serde_json::from_str(r#"{"language":"English","zoom":1.25}"#).unwrap();
        assert_eq!(legacy.accent, Accent::Teal);
        assert_eq!(legacy.zoom, 1.25);
        for accent in Accent::ALL {
            let settings = Settings {
                accent,
                ..Settings::default()
            };
            let decoded: Settings =
                serde_json::from_str(&serde_json::to_string(&settings).unwrap()).unwrap();
            assert_eq!(decoded.accent, accent);
            let context = egui::Context::default();
            apply_theme(&context, &settings);
            for theme in [egui::Theme::Light, egui::Theme::Dark] {
                let style = context.style_of(theme);
                let fg = luminance(style.visuals.selection.stroke.color);
                let bg = luminance(style.visuals.selection.bg_fill);
                let ratio = (fg.max(bg) + 0.05) / (fg.min(bg) + 0.05);
                assert!(
                    ratio >= 4.5,
                    "{accent:?}/{theme:?}: selection contrast {ratio}"
                );
            }
        }
    }

    #[test]
    fn preferences_with_long_content_stays_inside_short_viewport() {
        for size in [egui::vec2(535.0, 355.0), egui::vec2(507.0, 347.0)] {
            let context = egui::Context::default();
            apply_theme(&context, &Settings::default());
            for _ in 0..3 {
                let _ = context.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ctx| {
                        let mut open = true;
                        let response = preferences_window(ctx, "Settings", &mut open)
                            .show(ctx, |ui| {
                                for _ in 0..30 {
                                    ui.checkbox(&mut false, "A preference with a persistent label");
                                }
                            })
                            .unwrap();
                        assert!(
                            response.response.rect.height() <= size.y - 8.0,
                            "Preferences must leave room below the last option: {:?}",
                            response.response.rect
                        );
                    },
                );
            }
        }
    }

    #[test]
    fn document_below_viewport_keeps_a_readable_height() {
        let context = egui::Context::default();
        let mut document = "status line\n".repeat(100);
        let _ = context.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(500.0, 400.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.add_space(600.0);
                        let start = ui.cursor().top();
                        document_view(ui, "document-below-viewport", &mut document);
                        assert!(
                            ui.cursor().top() - start >= 120.0,
                            "An initially offscreen JSON viewer must remain readable"
                        );
                    });
                });
            },
        );
    }

    #[test]
    fn long_document_keeps_export_action_near_the_viewer() {
        let context = egui::Context::default();
        let mut document = "a long status line\n".repeat(1000);
        let _ = context.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(500.0, 400.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let start = ui.cursor().top();
                    document_view(ui, "document-under-test", &mut document);
                    let export = ui.button("Export").rect;
                    assert!(
                        export.bottom() - start < 300.0,
                        "Export must stay reachable after long JSON: {export:?}"
                    );
                });
            },
        );
    }
}

pub(super) fn card<R>(
    ui: &mut egui::Ui,
    content: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    egui::Frame::new()
        .fill(ui.visuals().window_fill)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(10)
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.style_mut()
                .text_styles
                .insert(egui::TextStyle::Heading, egui::FontId::proportional(17.0));
            content(ui)
        })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Accent {
    #[default]
    Teal,
    Lake,
    Iris,
    Rose,
    Amber,
}

impl Accent {
    pub(super) const ALL: [Self; 5] = [Self::Teal, Self::Lake, Self::Iris, Self::Rose, Self::Amber];

    pub(super) fn color(self, dark: bool) -> Color32 {
        let (light, night) = match self {
            Self::Teal => ([36, 73, 68], [110, 211, 185]),
            Self::Lake => ([25, 91, 152], [120, 187, 250]),
            Self::Iris => ([98, 71, 171], [183, 160, 249]),
            Self::Rose => ([158, 58, 91], [245, 153, 184]),
            Self::Amber => ([142, 88, 21], [237, 192, 112]),
        };
        let rgb = if dark { night } else { light };
        Color32::from_rgb(rgb[0], rgb[1], rgb[2])
    }

    fn label(self, language: Language) -> &'static str {
        let (zh, en) = match self {
            Self::Teal => ("松石绿", "Teal"),
            Self::Lake => ("湖蓝", "Lake"),
            Self::Iris => ("靛紫", "Iris"),
            Self::Rose => ("玫瑰", "Rose"),
            Self::Amber => ("琥珀", "Amber"),
        };
        if language == Language::Chinese {
            zh
        } else {
            en
        }
    }
}

fn tint(base: Color32, color: Color32, amount: f32) -> Color32 {
    let blend = |a: u8, b: u8| (a as f32 * (1.0 - amount) + b as f32 * amount).round() as u8;
    Color32::from_rgb(
        blend(base.r(), color.r()),
        blend(base.g(), color.g()),
        blend(base.b(), color.b()),
    )
}

pub(super) fn apply_theme(context: &egui::Context, settings: &Settings) {
    install_ui_fonts(context);
    context.set_theme(match settings.theme {
        Theme::System => egui::ThemePreference::System,
        Theme::Light => egui::ThemePreference::Light,
        Theme::Dark => egui::ThemePreference::Dark,
    });
    // Customize both styles so a system-theme change updates the whole application.
    context.all_styles_mut(|style| {
        let dark = style.visuals.dark_mode;
        let accent = settings.accent.color(dark);
        let border = if dark {
            Color32::from_rgb(51, 61, 70)
        } else {
            Color32::from_rgb(218, 226, 229)
        };
        style.visuals.panel_fill = if dark {
            Color32::from_rgb(20, 26, 32)
        } else {
            Color32::from_rgb(245, 248, 249)
        };
        style.visuals.window_fill = if dark {
            Color32::from_rgb(27, 34, 41)
        } else {
            Color32::WHITE
        };
        style.visuals.extreme_bg_color = if dark {
            Color32::from_rgb(16, 22, 28)
        } else {
            Color32::from_rgb(249, 251, 252)
        };
        style.visuals.faint_bg_color = if dark {
            Color32::from_rgb(30, 38, 45)
        } else {
            Color32::from_rgb(236, 242, 244)
        };
        style.visuals.panel_fill = tint(style.visuals.panel_fill, accent, 0.035);
        style.visuals.window_fill = tint(style.visuals.window_fill, accent, 0.02);
        style.visuals.extreme_bg_color = tint(style.visuals.extreme_bg_color, accent, 0.025);
        style.visuals.faint_bg_color = tint(style.visuals.faint_bg_color, accent, 0.07);
        style.visuals.override_text_color = None;
        style.visuals.widgets.noninteractive.fg_stroke.color = if dark {
            Color32::from_rgb(224, 233, 238)
        } else {
            Color32::from_rgb(31, 48, 57)
        };
        style.visuals.widgets.inactive.fg_stroke.color =
            style.visuals.widgets.noninteractive.fg_stroke.color;
        style.visuals.selection.bg_fill = tint(
            style.visuals.window_fill,
            accent,
            if dark { 0.15 } else { 0.10 },
        );
        style.visuals.selection.stroke = Stroke::new(1.0_f32, accent);
        style.visuals.hyperlink_color = accent;
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, border);
        style.visuals.widgets.noninteractive.corner_radius = CornerRadius::same(10);
        style.visuals.widgets.inactive.weak_bg_fill = style.visuals.window_fill;
        style.visuals.widgets.inactive.bg_fill = style.visuals.extreme_bg_color;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, border);
        style.visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
        style.visuals.widgets.hovered.bg_fill = style.visuals.selection.bg_fill;
        style.visuals.widgets.hovered.weak_bg_fill = style.visuals.selection.bg_fill;
        style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, accent);
        style.visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
        style.visuals.widgets.active = style.visuals.widgets.hovered;
        style.visuals.window_corner_radius = CornerRadius::same(12);
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 32.0;
        style.spacing.text_edit_width = 240.0;
        style.spacing.window_margin = Margin::same(18);
        style.animation_time = if settings.reduced_motion { 0.0 } else { 0.15 };
        for (kind, size) in [
            (egui::TextStyle::Heading, 22.0),
            (egui::TextStyle::Body, 14.0),
            (egui::TextStyle::Button, 14.0),
            (egui::TextStyle::Small, 12.0),
        ] {
            style
                .text_styles
                .insert(kind, egui::FontId::proportional(size));
        }
        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(22.0, egui::FontFamily::Name("MiSans Medium".into())),
        );
    });
    context.set_zoom_factor(settings.zoom.clamp(0.8, 1.5));
}

impl Page {
    fn description(self, language: Language) -> &'static str {
        let pair = match self {
            Self::Overview => (
                "设备状态、虚拟网络与连接会话，一目了然。",
                "Your device, virtual networks and connection sessions at a glance.",
            ),
            Self::Connectivity => (
                "管理虚拟网卡、连接发现与中继。",
                "Manage the virtual adapter, discovery and relay connections.",
            ),
            Self::Join => (
                "使用邀请连接网络，或手动配置入网信息。",
                "Connect with an invitation or configure enrollment manually.",
            ),
            Self::Controller => (
                "管理网络、成员授权和路由策略。",
                "Manage networks, member authorization and routing policy.",
            ),
            Self::Gateway => (
                "配置流量出口、双栈网关与故障关闭。",
                "Configure traffic exits, dual-stack gateways and the kill switch.",
            ),
            Self::Maintenance => (
                "诊断连接、保护状态并管理本机服务。",
                "Diagnose connections, protect state and manage local services.",
            ),
        };
        if language == Language::Chinese {
            pair.0
        } else {
            pair.1
        }
    }
}

impl App {
    pub(super) fn render_shell(&mut self, context: &egui::Context) -> egui::Rect {
        let compact = context.screen_rect().width() < 720.0;
        egui::TopBottomPanel::bottom("footer")
            .frame(
                egui::Frame::new()
                    .fill(context.style().visuals.window_fill)
                    .inner_margin(Margin::symmetric(18, 8)),
            )
            .show(context, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.small(format!("MeshLake {}", env!("CARGO_PKG_VERSION")));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.small(self.t("后台独立运行", "Agent runs independently"));
                    });
                });
            });
        if compact {
            egui::TopBottomPanel::top("compact-navigation")
                .frame(
                    egui::Frame::new()
                        .fill(context.style().visuals.window_fill)
                        .inner_margin(Margin::same(12)),
                )
                .show(context, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong("MeshLake");
                        if ui.button(self.t("偏好设置", "Preferences")).clicked() {
                            self.show_settings = true;
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        for page in Page::ALL {
                            ui.selectable_value(
                                &mut self.page,
                                page,
                                page.title(self.settings.language),
                            );
                        }
                    });
                });
        } else {
            egui::SidePanel::left("navigation")
                .resizable(false)
                .exact_width(202.0)
                .frame(
                    egui::Frame::new()
                        .fill(context.style().visuals.window_fill)
                        .inner_margin(Margin::same(16)),
                )
                .show(context, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("navigation-scroll")
                        .show(ui, |ui| {
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(28.0, 28.0),
                                    egui::Sense::hover(),
                                );
                                icons::brand(ui.painter(), rect, self.settings.accent.color(false));
                                ui.label(egui::RichText::new("MeshLake").size(23.0).strong());
                            });
                            ui.add_space(2.0);
                            ui.small(self.t("你的设备，同一个网络", "Your devices. One network."));
                            ui.add_space(24.0);
                            ui.weak(self.t("工作区", "WORKSPACE"));
                            ui.add_space(4.0);
                            for page in Page::ALL {
                                let selected = self.page == page;
                                let (rect, response) = ui.allocate_exact_size(
                                    egui::vec2(ui.available_width(), 42.0),
                                    egui::Sense::click(),
                                );
                                let color = if selected {
                                    ui.visuals().hyperlink_color
                                } else {
                                    ui.visuals().text_color()
                                };
                                if selected || response.hovered() || response.has_focus() {
                                    ui.painter().rect_filled(
                                        rect,
                                        7.0,
                                        if selected {
                                            ui.visuals().selection.bg_fill
                                        } else {
                                            ui.visuals().faint_bg_color
                                        },
                                    );
                                }
                                icons::navigation(
                                    ui.painter(),
                                    egui::Rect::from_center_size(
                                        egui::pos2(rect.left() + 20.0, rect.center().y),
                                        egui::vec2(20.0, 20.0),
                                    ),
                                    page,
                                    color,
                                );
                                ui.painter().text(
                                    egui::pos2(rect.left() + 40.0, rect.center().y),
                                    egui::Align2::LEFT_CENTER,
                                    page.title(self.settings.language),
                                    egui::FontId::proportional(14.0),
                                    color,
                                );
                                response.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::WidgetType::SelectableLabel,
                                        true,
                                        selected,
                                        page.title(self.settings.language),
                                    )
                                });
                                if response.clicked() {
                                    self.page = page;
                                }
                            }
                            ui.add_space(20.0);
                            ui.separator();
                            ui.add_space(6.0);
                            if ui
                                .add_sized(
                                    [ui.available_width(), 36.0],
                                    egui::Button::new(self.t("偏好设置", "Preferences")),
                                )
                                .clicked()
                            {
                                self.show_settings = true;
                            }
                            ui.add_space(16.0);
                            ui.small(self.t("本机后台", "LOCAL AGENT"));
                            let connected = self.status.is_some();
                            ui.colored_label(
                                if connected {
                                    ui.visuals().hyperlink_color
                                } else {
                                    ui.visuals().weak_text_color()
                                },
                                if connected {
                                    self.t("● 已连接", "● Connected")
                                } else {
                                    self.t("○ 未连接", "○ Disconnected")
                                },
                            );
                        });
                });
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(context.style().visuals.panel_fill)
                    .inner_margin(Margin::same(if compact { 12 } else { 24 })),
            )
            .show(context, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(format!("page-{:?}", self.page))
                    .auto_shrink([false, false])
                    .min_scrolled_height(0.0)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                egui::RichText::new(self.page.title(self.settings.language))
                                    .size(28.0)
                                    .strong(),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add_enabled(
                                            self.can_start_action(),
                                            egui::Button::new(self.t("刷新状态", "Refresh")),
                                        )
                                        .clicked()
                                    {
                                        self.refresh();
                                    }
                                },
                            );
                        });
                        ui.weak(self.page.description(self.settings.language));
                        ui.add_space(12.0);
                        if !self.message.is_empty() || self.job.is_some() {
                            egui::Frame::new()
                                .fill(ui.visuals().faint_bg_color)
                                .corner_radius(8)
                                .inner_margin(Margin::same(12))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal_wrapped(|ui| {
                                        if self.job.is_some() {
                                            if !self.settings.reduced_motion {
                                                ui.spinner();
                                            }
                                            ui.strong(self.t("处理中", "Working"));
                                        }
                                        ui.label(&self.message);
                                        if let Some(cancel) = &self.process_cancel {
                                            if self.job.is_some()
                                                && ui
                                                    .button(self.t("取消操作", "Cancel operation"))
                                                    .clicked()
                                            {
                                                cancel.store(
                                                    true,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                            }
                                        }
                                    });
                                });
                            ui.add_space(14.0);
                        }
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().text_edit_width =
                            (ui.available_width() - 160.0).clamp(120.0, 520.0);
                        ui.add_enabled_ui(self.can_start_action(), |ui| {
                            self.render_page(context, ui)
                        });
                    });
            })
            .response
            .rect
    }

    pub(super) fn appearance_settings_ui(&mut self, ui: &mut egui::Ui) {
        ui.strong(self.t("外观", "Appearance"));
        ui.horizontal(|ui| {
            for (value, zh, en) in [
                (Theme::System, "跟随系统", "System"),
                (Theme::Light, "浅色", "Light"),
                (Theme::Dark, "深色", "Dark"),
            ] {
                let label = self.t(zh, en);
                ui.selectable_value(&mut self.settings.theme, value, label);
            }
        });
        ui.label(self.t("主题色", "Theme color"));
        ui.horizontal_wrapped(|ui| {
            for accent in Accent::ALL {
                let label = egui::RichText::new(accent.label(self.settings.language))
                    .color(accent.color(ui.visuals().dark_mode));
                ui.selectable_value(&mut self.settings.accent, accent, label);
            }
        });
        let label = self.t("减少动画", "Reduce motion");
        ui.checkbox(&mut self.settings.reduced_motion, label);
        ui.horizontal_wrapped(|ui| {
            ui.label(self.t("界面缩放", "Interface scale"));
            egui::ComboBox::from_id_salt("interface_scale")
                .width(108.0)
                .selected_text(format!("{:.0}%", self.settings.zoom * 100.0))
                .show_ui(ui, |ui| {
                    for percent in [80, 90, 100, 110, 125, 150] {
                        ui.selectable_value(
                            &mut self.settings.zoom,
                            percent as f32 / 100.0,
                            format!("{percent}%"),
                        );
                    }
                });
        });
    }
}
