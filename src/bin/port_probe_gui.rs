use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use gpui::prelude::*;
use gpui::{
    div, px, App, Application, Context, Entity, IntoElement, Render, SharedString, Window,
    WindowOptions,
};
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::input::{Input, InputState};
use gpui_component::scroll::ScrollableElement;
use gpui_component::{Disableable, Root, Sizable, StyledExt};

use port_8116_test::{probe_port, probe_sip_register, ProbeParams, ProbeResult, Protocol};

pub struct PortProbeGui {
    target_input: Entity<InputState>,
    start_port_input: Entity<InputState>,
    end_port_input: Entity<InputState>,
    protocol_input: Entity<InputState>,
    timeout_input: Entity<InputState>,
    status: SharedString,
    results: Vec<ProbeResult>,
    running: bool,
    gb_target_input: Entity<InputState>,
    gb_port_input: Entity<InputState>,
    gb_timeout_input: Entity<InputState>,
    gb_status: SharedString,
    gb_result: Option<ProbeResult>,
    gb_running: bool,
}

impl PortProbeGui {
    fn new(window: &mut Window, cx: &mut App) -> Self {
        Self {
            target_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("10.7.2.140")
            }),
            start_port_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("8116")
            }),
            end_port_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("8116")
            }),
            protocol_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("tcp")
            }),
            timeout_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("3000")
            }),
            status: "就绪".into(),
            results: Vec::new(),
            running: false,
            gb_target_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("10.7.2.19")
            }),
            gb_port_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("5060")
            }),
            gb_timeout_input: cx.new(|cx| {
                InputState::new(window, cx).default_value("3000")
            }),
            gb_status: "就绪".into(),
            gb_result: None,
            gb_running: false,
        }
    }

    fn read_field(entity: &Entity<InputState>, cx: &mut Context<Self>) -> String {
        entity.read(cx).value().to_string()
    }

    fn start_probe(&mut self, cx: &mut Context<Self>) {
        let target: IpAddr = match Self::read_field(&self.target_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.status = "目标地址格式错误".into();
                cx.notify();
                return;
            }
        };

        let start_port: u16 = match Self::read_field(&self.start_port_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.status = "起始端口格式错误".into();
                cx.notify();
                return;
            }
        };

        let end_port: u16 = match Self::read_field(&self.end_port_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.status = "结束端口格式错误".into();
                cx.notify();
                return;
            }
        };

        let protocol = match Protocol::from_str(Self::read_field(&self.protocol_input, cx).trim()) {
            Ok(v) => v,
            Err(_) => {
                self.status = "协议必须是 tcp 或 udp".into();
                cx.notify();
                return;
            }
        };

        let timeout_ms: u64 = match Self::read_field(&self.timeout_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.status = "超时格式错误".into();
                cx.notify();
                return;
            }
        };

        if start_port > end_port {
            self.status = "起始端口不能大于结束端口".into();
            cx.notify();
            return;
        }

        self.results.clear();
        self.running = true;
        self.status = format!("正在探测 {} 的 {} - {} ...", target, start_port, end_port).into();
        cx.notify();

        let timeout = Duration::from_millis(timeout_ms);

        cx.spawn(move |this: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            let mut cx = cx.clone();
            async move {
                for port in start_port..=end_port {
                    let params = ProbeParams {
                        target,
                        port,
                        protocol,
                        timeout,
                    };
                    let result = cx
                        .background_executor()
                        .spawn(async move { probe_port(&params) })
                        .await;

                    this.update(&mut cx, |this, cx| {
                        this.results.push(result);
                        cx.notify();
                    })
                    .ok();
                }

                this.update(&mut cx, |this, cx| {
                    this.running = false;
                    this.status = format!(
                        "探测完成：{} 个可达，{} 个不可达/无响应",
                        this.results.iter().filter(|r| r.success).count(),
                        this.results.iter().filter(|r| !r.success).count()
                    )
                    .into();
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();
    }

    fn start_gb_probe(&mut self, cx: &mut Context<Self>) {
        let target: IpAddr = match Self::read_field(&self.gb_target_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.gb_status = "国标目标地址格式错误".into();
                cx.notify();
                return;
            }
        };

        let port: u16 = match Self::read_field(&self.gb_port_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.gb_status = "国标端口格式错误".into();
                cx.notify();
                return;
            }
        };

        let timeout_ms: u64 = match Self::read_field(&self.gb_timeout_input, cx).trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.gb_status = "国标超时格式错误".into();
                cx.notify();
                return;
            }
        };

        self.gb_running = true;
        self.gb_result = None;
        self.gb_status = format!("正在测试国标端口 {}:{} ...", target, port).into();
        cx.notify();

        let timeout = Duration::from_millis(timeout_ms);

        cx.spawn(move |this: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
            let mut cx = cx.clone();
            async move {
                let result = cx
                    .background_executor()
                    .spawn(async move { probe_sip_register(target, port, timeout) })
                    .await;

                this.update(&mut cx, |this, cx| {
                    this.gb_running = false;
                    this.gb_result = Some(result.clone());
                    this.gb_status = if result.success {
                        format!("国标端口可达：{}", result.summary)
                    } else {
                        format!("国标端口不可达/无响应：{}", result.summary)
                    }
                    .into();
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();
    }
}

impl Render for PortProbeGui {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let form_row = |label: &str, input: Entity<InputState>| {
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(div().w(px(80.)).child(label.to_string()))
                .child(div().flex_1().child(Input::new(&input)))
        };

        let status_color = if self.running {
            gpui::blue()
        } else {
            gpui::black()
        };

        let gb_status_color = if self.gb_running {
            gpui::blue()
        } else {
            gpui::black()
        };

        div()
            .v_flex()
            .gap_3()
            .p_4()
            .size_full()
            .overflow_y_scrollbar()
            .child(
                div()
                    .text_xl()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("端口探测工具"),
            )
            .child(form_row("目标地址", self.target_input.clone()))
            .child(form_row("起始端口", self.start_port_input.clone()))
            .child(form_row("结束端口", self.end_port_input.clone()))
            .child(form_row("协议", self.protocol_input.clone()))
            .child(form_row("超时(ms)", self.timeout_input.clone()))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .child(
                        Button::new("start")
                            .label("开始探测")
                            .primary()
                            .small()
                            .when(self.running, |this| this.disabled(true))
                            .on_click(cx.listener(|this, _, _window, cx| this.start_probe(cx))),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(status_color)
                    .child(self.status.to_string()),
            )
            .child(
                div()
                    .v_flex()
                    .gap_3()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("国标 SIP 端口测试"),
                    )
                    .child(form_row("目标地址", self.gb_target_input.clone()))
                    .child(form_row("端口", self.gb_port_input.clone()))
                    .child(form_row("超时(ms)", self.gb_timeout_input.clone()))
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap_2()
                            .child(
                                Button::new("gb_start")
                                    .label("测试国标端口")
                                    .primary()
                                    .small()
                                    .when(self.gb_running, |this| this.disabled(true))
                                    .on_click(cx.listener(|this, _, _window, cx| this.start_gb_probe(cx))),
                            ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(gb_status_color)
                            .child(self.gb_status.to_string()),
                    )
                    .children(self.gb_result.iter().map(|r| {
                        let color = if r.success { gpui::green() } else { gpui::red() };
                        div()
                            .flex()
                            .flex_row()
                            .gap_2()
                            .text_sm()
                            .child(div().w(px(60.)).child(r.protocol.to_string()))
                            .child(div().w(px(120.)).child(format!("{}:{}", r.target, r.port)))
                            .child(div().w(px(80.)).text_color(color).child(r.summary.clone()))
                            .child(div().flex_1().child(format!("{:?} | {}", r.duration, r.detail)))
                    })),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .h(px(320.))
                    .overflow_y_scrollbar()
                    .children(self.results.iter().map(|r| {
                        let color = if r.success { gpui::green() } else { gpui::red() };
                        div()
                            .flex()
                            .flex_row()
                            .gap_2()
                            .text_sm()
                            .child(
                                div()
                                    .w(px(60.))
                                    .child(r.protocol.to_string()),
                            )
                            .child(
                                div()
                                    .w(px(120.))
                                    .child(format!("{}:{}", r.target, r.port)),
                            )
                            .child(
                                div()
                                    .w(px(80.))
                                    .text_color(color)
                                    .child(r.summary.clone()),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(format!("{:?} | {}", r.duration, r.detail)),
                            )
                    })),
            )
    }
}

fn main() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);

        cx.open_window(
            WindowOptions {
                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds::centered(
                    None,
                    gpui::size(px(700.0), px(600.0)),
                    cx,
                ))),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| PortProbeGui::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .unwrap();
    });
}
