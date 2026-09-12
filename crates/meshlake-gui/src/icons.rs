//! Original MeshLake symbols: a shared 24-unit vector grid, rounded 1.65-unit strokes.
use super::{egui, Page};
use egui::{pos2, vec2, Color32, Painter, Rect, Stroke};

fn path(painter: &Painter, rect: Rect, points: &[[f32; 2]], color: Color32) {
    let scale = rect.width().min(rect.height()) / 24.0;
    let origin = rect.center() - vec2(12.0, 12.0) * scale;
    let stroke = Stroke::new(1.65 * scale, color);
    let points: Vec<_> = points
        .iter()
        .map(|p| origin + vec2(p[0], p[1]) * scale)
        .collect();
    for segment in points.windows(2) {
        painter.line_segment([segment[0], segment[1]], stroke);
    }
    for point in points {
        painter.circle_filled(point, stroke.width / 2.0, color);
    }
}

fn outline(painter: &Painter, rect: Rect, bounds: [f32; 4], radius: f32, color: Color32) {
    let scale = rect.width().min(rect.height()) / 24.0;
    let origin = rect.center() - vec2(12.0, 12.0) * scale;
    painter.rect_stroke(
        Rect::from_min_max(
            origin + vec2(bounds[0], bounds[1]) * scale,
            origin + vec2(bounds[2], bounds[3]) * scale,
        ),
        radius * scale,
        Stroke::new(1.65 * scale, color),
        egui::StrokeKind::Middle,
    );
}

pub(super) fn navigation(painter: &Painter, rect: Rect, page: Page, color: Color32) {
    let line = |points: &[[f32; 2]]| path(painter, rect, points, color);
    let box_at = |bounds, radius| outline(painter, rect, bounds, radius, color);
    match page {
        Page::Overview => {
            box_at([3.0, 3.0, 10.0, 14.0], 1.8);
            box_at([14.0, 3.0, 21.0, 9.0], 1.8);
            box_at([3.0, 18.0, 10.0, 21.0], 1.4);
            box_at([14.0, 13.0, 21.0, 21.0], 1.8);
        }
        Page::Connectivity => {
            line(&[[12.0, 9.0], [12.0, 13.0]]);
            line(&[[6.0, 16.0], [6.0, 13.0], [18.0, 13.0], [18.0, 16.0]]);
            box_at([8.5, 3.0, 15.5, 9.0], 1.8);
            box_at([3.0, 16.0, 9.0, 21.0], 1.5);
            box_at([15.0, 16.0, 21.0, 21.0], 1.5);
        }
        Page::Join => {
            line(&[[13.0, 3.0], [19.0, 3.0], [19.0, 21.0], [13.0, 21.0]]);
            line(&[[3.0, 12.0], [14.0, 12.0]]);
            line(&[[10.0, 8.0], [14.0, 12.0], [10.0, 16.0]]);
        }
        Page::Controller => {
            box_at([3.0, 3.5, 21.0, 10.0], 2.0);
            box_at([3.0, 14.0, 21.0, 20.5], 2.0);
            line(&[[7.0, 6.75], [7.2, 6.75]]);
            line(&[[7.0, 17.25], [7.2, 17.25]]);
            line(&[[13.0, 6.75], [17.0, 6.75]]);
            line(&[[13.0, 17.25], [17.0, 17.25]]);
        }
        Page::Gateway => {
            line(&[[3.0, 7.0], [21.0, 7.0], [17.0, 3.0]]);
            line(&[[21.0, 7.0], [17.0, 11.0]]);
            line(&[[21.0, 17.0], [3.0, 17.0], [7.0, 13.0]]);
            line(&[[3.0, 17.0], [7.0, 21.0]]);
        }
        Page::Maintenance => {
            for (y, x) in [(5.0, 8.0), (12.0, 16.0), (19.0, 10.0)] {
                line(&[[3.0, y], [x - 2.0, y]]);
                line(&[[x + 2.0, y], [21.0, y]]);
                box_at([x - 2.0, y - 2.0, x + 2.0, y + 2.0], 1.2);
            }
        }
    }
}

// Selected concept A, "Shores": the original 64-unit cubic paths flattened
// once for both GPU vector strokes and the operating system's pixel icons.
fn shores() -> &'static [Vec<[f32; 2]>; 2] {
    static PATHS: std::sync::OnceLock<[Vec<[f32; 2]>; 2]> = std::sync::OnceLock::new();
    PATHS.get_or_init(|| {
        fn curve(points: &mut Vec<[f32; 2]>, a: [f32; 2], b: [f32; 2], c: [f32; 2]) {
            let start = *points.last().unwrap();
            for i in 1..=24 {
                let t = i as f32 / 24.0;
                let u = 1.0 - t;
                points.push([0, 1].map(|k| {
                    u * u * u * start[k]
                        + 3.0 * u * u * t * a[k]
                        + 3.0 * u * t * t * b[k]
                        + t * t * t * c[k]
                }));
            }
        }
        let mut upper = vec![[34.0, 14.0], [25.0, 14.0]];
        curve(&mut upper, [17.0, 14.0], [12.0, 20.0], [12.0, 27.0]);
        curve(&mut upper, [12.0, 34.0], [17.0, 40.0], [25.0, 40.0]);
        upper.push([30.0, 40.0]);
        let mut lower = vec![[30.0, 50.0], [39.0, 50.0]];
        curve(&mut lower, [47.0, 50.0], [52.0, 44.0], [52.0, 37.0]);
        curve(&mut lower, [52.0, 30.0], [47.0, 24.0], [39.0, 24.0]);
        lower.push([34.0, 24.0]);
        [upper, lower].map(|points| {
            points
                .into_iter()
                .map(|p| [p[0] * 0.375, p[1] * 0.375])
                .collect()
        })
    })
}

pub(super) fn brand(painter: &Painter, rect: Rect, color: Color32) {
    painter.rect_filled(rect, rect.width() * 0.265625, color);
    let scale = rect.width().min(rect.height()) / 24.0;
    let origin = rect.center() - vec2(12.0, 12.0) * scale;
    let stroke = Stroke::new(1.875 * scale, Color32::WHITE);
    for line in shores() {
        let points: Vec<_> = line
            .iter()
            .map(|p| origin + vec2(p[0], p[1]) * scale)
            .collect();
        painter.add(egui::Shape::line(points.clone(), stroke));
        for p in [points[0], *points.last().unwrap()] {
            painter.circle_filled(p, stroke.width / 2.0, Color32::WHITE);
        }
    }
}
/// OS icons require pixels. Sample the same vector geometry with 4x antialiasing.
pub(super) fn application_icon(size: u32, background: Color32) -> egui::IconData {
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut channels = [0u32; 4];
            for sy in 0..4 {
                for sx in 0..4 {
                    let p = pos2(
                        (x as f32 + (sx as f32 + 0.5) / 4.0) * 24.0 / size as f32,
                        (y as f32 + (sy as f32 + 0.5) / 4.0) * 24.0 / size as f32,
                    );
                    let q = vec2((p.x - 12.0).abs() - 5.625, (p.y - 12.0).abs() - 5.625);
                    if vec2(q.x.max(0.0), q.y.max(0.0)).length() + q.x.max(q.y).min(0.0) > 6.375 {
                        continue;
                    }
                    let ink = shores().iter().any(|line| {
                        line.windows(2).any(|s| {
                            let a = pos2(s[0][0], s[0][1]);
                            let b = pos2(s[1][0], s[1][1]);
                            let t = ((p - a).dot(b - a) / (b - a).length_sq()).clamp(0.0, 1.0);
                            p.distance(a + (b - a) * t) <= 0.9375
                        })
                    });
                    let color = if ink {
                        [255, 255, 255]
                    } else {
                        [
                            background.r() as u32,
                            background.g() as u32,
                            background.b() as u32,
                        ]
                    };
                    for c in 0..3 {
                        channels[c] += color[c];
                    }
                    channels[3] += 255;
                }
            }
            let alpha = channels[3];
            for channel in channels.iter().take(3) {
                rgba.push(if alpha == 0 {
                    0
                } else {
                    (channel * 255 / alpha) as u8
                });
            }
            rgba.push((alpha / 16) as u8);
        }
    }
    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}
